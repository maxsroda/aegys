"""Shell words: splitting a command into pipeline stages, unwrapping wrapper commands
(env, xargs, timeout and the like), and the program sets the command checks use:
READERS, SEARCHERS, WRITERS and PRINTERS.

``aegys/command_checks.py`` and ``aegys/guard.py`` use these to see which program
a command runs and which words it names.
"""
from __future__ import annotations

import os
import re
import shlex
from pathlib import Path


# Shell operators shlex splits off as their own tokens.
PUNCTUATION = "();<>|&`\n"
SEPARATOR_CHARS = set(";|&()`\n")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Environment assignments that point git at another repository or configuration,
# or make node run code.
DANGEROUS_ASSIGNMENT = re.compile(
    r"^(?:GIT_(?:DIR|WORK_TREE|COMMON_DIR|INDEX_FILE|OBJECT_DIRECTORY|CONFIG\w*|SSH\w*)"
    r"|NODE_OPTIONS)=")

# Commands that run the rest of their words as a command, and their options that
# take a separate value.
WRAPPERS = {
    "env": {"-u", "-C", "-S", "-P"}, "command": set(), "exec": {"-a"}, "nohup": set(),
    "time": set(), "nice": {"-n"}, "builtin": set(), "xargs": {"-I", "-n", "-P", "-L",
    "-s", "-d", "-E", "-a", "-J", "-R"}, "timeout": {"-s", "-k"}, "stdbuf": {"-i", "-o", "-e"},
    "caffeinate": {"-t", "-w"},
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
ENV_DUMP_WHY = "printing the environment exposes API keys; not needed here"
# Compound-command keywords: `{ git push; }` and `do git push` run the words after them;
# closing keywords (`done`, `fi`, `esac`, `}`) end a compound block.
KEYWORDS = {"{", "}", "!", "if", "then", "else", "elif", "fi", "while", "until", "do", "done", "esac", "coproc"}

# Programs whose words are search patterns and read-only operands: a `..` or `.git`
# in them is a regex or an exclusion, not a path to leave the worktree by.
SEARCHERS = {"rg", "grep", "egrep", "fgrep", "ag", "ack", "fd", "fdfind"}
# Read-only programs that may name the worktree's `.git` (ls .git, du -sh .git).
READERS = SEARCHERS | {"ls", "du", "tree", "stat", "file", "cat", "head", "tail", "wc",
                       "realpath", "readlink", "diff", "cmp", "less", "more"}
# find options that write, delete or run a command; without them find only reads.
FIND_WRITE_FLAGS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0",
                    "-fprintf", "-fls"}
# Commands whose operands are written (created, moved, removed or changed).
WRITERS = {"rm", "rmdir", "unlink", "mv", "cp", "ln", "mkdir", "touch", "chmod", "tee",
           "truncate", "install", "patch", "dd", "tar", "zip", "unzip", "gzip", "gunzip",
           "bzip2", "xz", "split", "ditto"}
# Programs whose words are printed, not opened: only a redirect target is a path.
PRINTERS = {"echo", "printf"}


GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                  "--config-env", "--super-prefix", "--list-cmds"}


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


# --- bash ----------------------------------------------------------------------

def split_stages(command: str, comments: bool = True) -> list[list[str]]:
    """The command's pipeline stages, each a list of words with quotes removed.
    Raises ValueError when the command does not parse (an unbalanced quote).
    comments=False keeps `#` as an ordinary character, for a caller that has
    cut comments itself."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=PUNCTUATION)
    if not comments:
        lexer.commenters = ""
    lexer.whitespace = " \t\r"      # a newline separates commands, like `;`
    lexer.whitespace_split = True
    stages, stage = [], []
    for token in lexer:
        if token and (set(token) <= SEPARATOR_CHARS or re.fullmatch(r"[<>]+\(+", token)):   # also <( and >(
            stages.append(stage)
            stage = []
        else:
            stage.append(token)
    stages.append(stage)
    return [s for s in stages if s]


def unwrap(words: list[str]) -> tuple[list[str], str | None]:
    """Strip leading assignments and wrapper commands (env, xargs, timeout, ...);
    returns the words of the command that actually runs, or a denial."""
    words = list(words)
    while words:
        if words[0] == "function" and len(words) > 1:        # function NAME { body; }
            del words[:2]
            continue
        if words[0] == "coproc" and len(words) > 2 and words[2] == "{":   # coproc NAME { body; }
            del words[:2]
            continue
        if words[0] in ("for", "select"):                    # for NAME [in WORDS...]; select NAME [in WORDS...]
            if len(words) >= 3 and words[2] == "in":
                return [words[0], *words[3:]], None
            if len(words) >= 3 and words[2] == "do":         # for NAME do CMD; done
                del words[:3]
                continue
            return [], None
        if words[0] == "case":                               # case WORD in ...
            return (["case", words[1]] if len(words) >= 2 else []), None
        if words[0] in KEYWORDS:
            words.pop(0)
            continue
        if ASSIGNMENT.match(words[0]):
            if DANGEROUS_ASSIGNMENT.match(words[0]):
                return [], f"{words[0].split('=')[0]} redirects git or node; not needed here"
            words.pop(0)
            continue
        name = os.path.basename(words[0])
        if name not in WRAPPERS:
            break
        value_opts = WRAPPERS[name]
        words.pop(0)
        split_string = False
        while words and (words[0].startswith("-") or (name == "env" and ASSIGNMENT.match(words[0]))):
            split_string = split_string or words[0].startswith("-S")
            if DANGEROUS_ASSIGNMENT.match(words[0]):
                return [], f"{words[0].split('=')[0]} redirects git or node; not needed here"
            option = words.pop(0)
            if option in value_opts and words:
                words.pop(0)
        if name == "timeout" and words and re.match(r"^\d", words[0]):
            words.pop(0)
        if name == "env" and not words and not split_string:
            return [], ENV_DUMP_WHY      # `env`, `env -i`, `env FOO=1` print the environment
    return words, None


def git_config_writes(options: list[str], positional: list[str]) -> bool:
    """True when `git config` with these options and positional words writes
    settings rather than reading them."""

    def long_flag(*names: str) -> bool:
        return any(o.split("=")[0] in names for o in options)

    first = positional[0] if positional else None
    if long_flag("--unset", "--unset-all", "--add", "--replace-all", "--rename-section",
                 "--remove-section", "--edit") or "-e" in options \
            or first in ("set", "unset", "rename-section", "remove-section", "edit"):
        return True
    reads = first in ("get", "list") or long_flag(
        "--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "--get-color",
        "--get-colorbool") or "-l" in options
    return not reads and len(positional) >= 2


def brace_expansions(word: str, limit: int = 64) -> list[str]:
    """The words the shell makes of `{a,b}` in `word` (at most `limit`)."""
    match = re.search(r"\{([^{}]*,[^{}]*)\}", word)
    if not match:
        return [word]
    out: list[str] = []
    for alternative in match.group(1).split(","):
        out += brace_expansions(word[:match.start()] + alternative + word[match.end():], limit)
        if len(out) >= limit:
            return out[:limit]
    return out


def git_subcommand_index(args: list[str]) -> int | None:
    """Index of the subcommand among git's arguments, past its own options."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in GIT_VALUE_OPTS else 1
    return i if i < len(args) else None


