#!/usr/bin/env python3
"""Mistral Vibe pre_tool hook: hold an unattended worker to its worktree, best effort.

Active only when ``VIBE_WORKTREE_GUARD`` names a directory (a runner that drives
Vibe headless sets it to the worker's worktree); otherwise it passes every
call through, so interactive sessions are unaffected.

What it denies, while active:

1. File tools (``write_file``, ``edit``, ``search_replace`` and any other tool
   with a ``file_path``/``path`` argument) aimed outside the worktree, or at its
   ``.git`` pointer file.
2. Bash commands that change shared git state or leave the machine:
   ``git config`` writes, ``init``, ``push``, ``fetch``/``pull``/``clone``,
   ``remote`` changes, ``reset --hard``, ``clean -f``, ``worktree``,
   ``update-ref``, ``symbolic-ref`` writes, ``gc``, ``reflog expire``, ``notes``
   writes, ``branch``/``tag`` deletes, renames and forced moves,
   ``checkout -B``/``switch -C``, ``stash drop/clear``, ``git -c``, and ``-C``/
   ``--git-dir`` pointing elsewhere; ``curl``, ``wget``, ``ssh``, ``scp``,
   ``rsync``, ``sudo``, ``brew``, global npm and pip installs, ``osascript``,
   ``launchctl``, ``defaults write``, ``security``.
3. Inline code: ``node``/``tsx`` ``-e``/``-p``/``-pe``, ``--import``/``--require``/
   ``--loader``/``--test-reporter`` of a ``data:`` or ``http(s):`` URL, the same through ``npx`` or
   ``npm exec``, ``python3 -c``, ``perl -e``, ``npx -c``.
4. Bash naming an absolute path outside the worktree, the system temporary
   directories and the standard tool locations (after resolving ``..`` and
   symlinks), including the program itself (``../x``, ``~/x.sh``); a relative
   word that climbs out with ``..``, in any command except the search programs
   (``rg '../lib'`` is a pattern); the operands of ``rm``/``cp``/``mv``/``touch``/
   ``mkdir``/``ln``/``dd``/``tar``/``zip``/``gzip`` and friends, redirect targets
   (``>``, ``>>``, ``>|``), and the option values of git and ``sort`` that leave
   the worktree, are the whole worktree, or are a glob or brace expression that
   can expand to ``..`` or ``.git`` (``.?``, ``.gi?``, ``{.,.}.``); any command
   naming the worktree's ``.git`` in any letter case, except read-only ones
   (``ls``, ``du``, ``find`` without ``-delete``/``-exec``/``-fprint``, ``cat``,
   the search programs); ``sed -i``. ``echo`` and ``printf`` print their words and
   are checked only for redirects.

Each command is split into its pipeline stages with ``shlex``, so a word inside a
quoted argument (a commit message, a regex) is never mistaken for a command.
Wrappers (``env``, ``command``, ``xargs``, ``timeout``, ``find -exec``,
``sh -c``, ``eval``, command and process substitution, and the keywords of
brace groups, ``if``, loops, ``function`` and ``coproc``) are unwrapped and checked
too. An
absolute path whose top-level directory does not exist (``/api/users``) is a
regex or a route, not a path. A command that does not parse is denied.

Contract (Vibe hooks, v2.25+): JSON on stdin with ``tool_name``, ``tool_input``
and ``cwd``; print ``{"decision": "deny", "reason": ...}`` to deny, nothing to
pass. Declared with ``strict = true``, so a crash denies (fails closed).

A pattern check, not a sandbox: code a permitted command runs (a test suite, a
build script) is not inspected. Vibe's own bash allowlist, which the runner keeps
narrow through the environment, is the first line; this hook is the second, and it
runs before Vibe's smart-approve classifier, so the classifier cannot override it.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

GUARD_ENV = "VIBE_WORKTREE_GUARD"
# Optional: further directories (os.pathsep-separated) that count as inside,
# e.g. the runner's exchange directory holding the brief and the report.
EXTRA_ENV = "VIBE_WORKTREE_GUARD_EXTRA"
# Optional: append every payload and decision to this file (runner diagnostics).
LOG_ENV = "VIBE_WORKTREE_GUARD_LOG"

# Absolute paths a command may name besides the worktree.
ALLOWED_PREFIXES = (
    "/tmp", "/private/tmp", "/var/folders", "/private/var/folders", "/dev/null", "/dev/zero",
    "/dev/urandom", "/dev/random",
    "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd", "/usr/bin", "/bin",
    "/usr/local/bin", "/opt/homebrew/bin", "/usr/sbin", "/sbin", "/usr/share", "/usr/lib",
    "/usr/include", "/opt/homebrew/lib", "/opt/homebrew/share", "/opt/homebrew/opt",
)

FILE_TOOL_KEYS = ("file_path", "path", "target_file")

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
# Programs that print the environment, which holds the API keys exported from the
# user's shell. `env CMD` runs CMD and is unwrapped; `env` alone dumps.
ENV_DUMPERS = {"printenv"}
ENV_DUMP_WHY = "printing the environment exposes API keys; not needed here"
# Compound-command keywords: `{ git push; }` and `do git push` run the words after them.
KEYWORDS = {"{", "!", "if", "then", "else", "elif", "while", "until", "do", "coproc"}

NETWORK = {"curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet",
           "ftp", "socat", "http", "https", "aria2c"}
SYSTEM = {"sudo", "su", "doas", "brew", "launchctl", "osascript", "security", "killall",
          "pkill", "crontab", "shutdown", "reboot", "diskutil", "mount", "umount"}
# Programs whose words are search patterns and read-only operands: a `..` or `.git`
# in them is a regex or an exclusion, not a path to leave the worktree by.
SEARCHERS = {"rg", "grep", "egrep", "fgrep", "ag", "ack", "fd", "fdfind"}
# Read-only programs that may name the worktree's `.git` (ls .git, du -sh .git).
READERS = SEARCHERS | {"ls", "du", "tree", "stat", "file", "cat", "head", "tail", "wc",
                       "realpath", "readlink", "diff", "cmp", "less", "more"}
# find options that write, delete or run a command; without them find only reads.
FIND_WRITE_FLAGS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0",
                    "-fprintf", "-fls"}
# Options whose value is a pattern, not a path (`zip -x` is added for zip).
PATTERN_OPTS = {"--grep", "-S", "-G", "--author", "--committer", "-e", "--exclude"}
# Search options that make the first plain word a file, not the pattern.
PATTERN_FROM_ELSEWHERE = {"-f", "--file", "--files"}
# Commands whose operands are written (created, moved, removed or changed).
WRITERS = {"rm", "rmdir", "unlink", "mv", "cp", "ln", "mkdir", "touch", "chmod", "tee",
           "truncate", "install", "patch", "dd", "tar", "zip", "unzip", "gzip", "gunzip",
           "bzip2", "xz", "split", "ditto"}
# Programs whose words are printed, not opened: only a redirect target is a path.
PRINTERS = {"echo", "printf"}
# Options whose separate value (`--output X`) is checked as a path, besides every
# option of git; other programs' options are checked only in the attached form.
OUTPUT_OPTIONS = {"sort": {"-o", "--output"}}

NODE_LIKE = {"node", "tsx", "ts-node", "bun", "deno"}
NODE_EVAL = {"-e", "--eval", "-p", "--print"}
NODE_EVAL_CLUSTER = re.compile(r"^-[A-Za-z]*[ep][A-Za-z]*$")     # -pe, -ep
# Options that load a module; a data: or http(s): URL there is inline code.
NODE_MODULE_OPTS = {"--import", "--require", "-r", "--loader", "--experimental-loader",
                    "--test-reporter"}
NPX_VALUE_OPTS = {"-p", "--package", "--cache", "--userconfig"}

GIT_VALUE_OPTS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                  "--config-env", "--super-prefix", "--list-cmds"}
GIT_DENIED = {
    "init": "git init creates a repository; use mktemp -d under tmp/ for scratch repos only if the brief asks",
    "push": "pushing is the coordinator's step",
    "fetch": "no network: the repository is provisioned before you start",
    "pull": "no network: the repository is provisioned before you start",
    "clone": "no network: the repository is provisioned before you start",
    "ls-remote": "no network: the repository is provisioned before you start",
    "send-email": "no network",
    "worktree": "worktrees and refs are the coordinator's",
    "update-ref": "worktrees and refs are the coordinator's",
    "filter-branch": "history rewrites change refs shared with every worktree",
    "filter-repo": "history rewrites change refs shared with every worktree",
    "replace": "replacement refs are shared with every worktree",
    "gc": "gc and prune can drop objects other worktrees still need",
    "prune": "gc and prune can drop objects other worktrees still need",
    "fast-import": "worktrees and refs are the coordinator's",
}
REFS_REASON = "branches, tags and refs are shared with every worktree; create your own, never move or delete one"


def bare_tool_name(name: str) -> str:
    """The unified harness names built-in tools `file_system.bash`, the legacy one
    `bash`: compare on the last dotted component."""
    return name.rsplit(".", 1)[-1]


def inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def resolve(candidate: str, cwd: Path) -> Path:
    return (cwd / Path(candidate).expanduser()).resolve()


def inside_any(path: Path, roots: list[Path]) -> bool:
    return any(inside(path, r) for r in roots)


def in_git_pointer(path: Path, root: Path) -> bool:
    """Whether path is the worktree's `.git` or inside it, in any letter case: the
    default macOS file system treats `.GIT` as `.git`."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    return bool(parts) and parts[0].casefold() == ".git"


def allowed_location(path: Path) -> bool:
    for prefix in ALLOWED_PREFIXES:
        for base in {Path(prefix), Path(prefix).resolve()}:
            if inside(path, base):
                return True
    return False


def file_denial(tool_input: dict[str, Any], cwd: Path, roots: list[Path]) -> str | None:
    for key in FILE_TOOL_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            try:
                target = resolve(value, cwd)
            except (OSError, RuntimeError, ValueError):
                return f"{value} cannot be resolved as a path; use a plain path inside your worktree"
            if not inside_any(target, roots):
                return f"{value} is outside your worktree {roots[0]}; work only inside it"
            if in_git_pointer(target, roots[0]):
                return f"{value} is the worktree's git metadata; leave it to git"
    return None


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


def git_denial(args: list[str], cwd: Path, roots: list[Path]) -> str | None:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        name, eq, value = args[i].partition("=")
        if name in GIT_VALUE_OPTS and not eq:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 1
        if name in ("-c", "--config-env"):
            return "git -c sets configuration for the command (hooks, fsmonitor); not needed here"
        if name in ("-C", "--git-dir", "--work-tree") and value \
                and not inside_any(resolve(value, cwd), roots):
            return f"git {name} {value} points git at another repository; work in your worktree"
        i += 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1:]
    options = [a for a in rest if a.startswith("-")]
    positional = [a for a in rest if not a.startswith("-")]
    first = positional[0] if positional else None

    def short_flags(letters: str) -> bool:
        return any(re.match(r"^-[A-Za-z]+$", o) and set(o[1:]) & set(letters) for o in options)

    def long_flag(*names: str) -> bool:
        return any(o.split("=")[0] in names for o in options)

    if sub in GIT_DENIED:
        return GIT_DENIED[sub]
    if sub == "config":
        if git_config_writes(options, positional):
            return "git config writes repository or user settings shared with other worktrees"
    elif sub == "remote" and first in ("add", "set-url", "remove", "rm", "rename", "set-head",
                                       "set-branches", "prune", "update"):
        return "remotes are shared repository state"
    elif sub == "reset" and "--hard" in options:
        return "git reset --hard discards work; commit or ask instead"
    elif sub == "clean" and (short_flags("f") or long_flag("--force")):
        return "git clean -f deletes untracked files"
    elif sub == "stash" and first in ("drop", "clear"):
        return "the stash is shared with every worktree"
    elif sub == "branch" and (short_flags("dDmMcCfu") or long_flag(
            "--delete", "--move", "--copy", "--force", "--set-upstream-to", "--unset-upstream",
            "--edit-description")):
        return REFS_REASON
    elif sub == "tag" and (short_flags("df") or long_flag("--delete", "--force")):
        return REFS_REASON
    elif sub == "symbolic-ref" and (len(positional) > 1 or long_flag("--delete") or "-d" in options):
        return REFS_REASON
    elif sub == "reflog" and first in ("expire", "delete"):
        return REFS_REASON
    elif sub == "notes" and first not in (None, "show", "list"):
        return REFS_REASON
    elif sub == "checkout" and "-B" in options:
        return REFS_REASON
    elif sub == "switch" and ("-C" in options or long_flag("--force-create")):
        return REFS_REASON
    return None


def inline_code_denial(program: str, args: list[str]) -> str | None:
    why = f"{program} with inline code is not allowed; write the code to a file under tmp/ and run that"
    if program in NODE_LIKE:
        for i, a in enumerate(args):
            if a == "--":
                break
            name, eq, value = a.partition("=")
            if a in NODE_EVAL or name in ("--eval", "--print") or NODE_EVAL_CLUSTER.match(a):
                return why
            if name in NODE_MODULE_OPTS:
                value = value if eq else (args[i + 1] if i + 1 < len(args) else "")
                if re.match(r"^(?:data|https?):", value, re.IGNORECASE):
                    return f"{program} {name} {value.split(',')[0]}... runs code from a URL; use a file under tmp/"
    elif re.match(r"^python[0-9.]*$", program):
        for a in args:
            if a == "-m" or not a.startswith("-"):
                break
            if re.match(r"^-[A-Za-z]*c$", a):
                return why
    elif program in ("perl", "ruby") and any(a in ("-e", "-E") for a in args):
        return why
    elif program == "php" and "-r" in args:
        return why
    return None


def package_runner_denial(args: list[str]) -> str | None:
    """`npx ARGS` or `npm exec ARGS`: the package it runs, with that package's arguments."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        name = args[i].split("=")[0]
        if args[i] == "--":
            i += 1
            break
        if name in ("-c", "--call"):
            return "npx -c runs a shell string; run the command itself"
        if name == "--node-options":
            return "--node-options can run inline code; not needed here"
        if name in NPX_VALUE_OPTS and "=" not in args[i]:
            i += 1
        i += 1
    if i >= len(args):
        return None
    package = args[i]
    name = package if not package.startswith("@") else package[1:]
    name = os.path.basename(name.split("@")[0])
    return inline_code_denial(name, args[i + 1:])


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


def glob_matches(component: str, name: str) -> bool:
    """Whether the shell's glob `component` can expand to the directory entry `name`:
    a leading dot must be matched by a literal dot, and case is ignored (APFS)."""
    return fnmatch.fnmatchcase(name, component.casefold()) and (
        not name.startswith(".") or component.startswith("."))


def glob_denial(value: str, cwd: Path, root: Path) -> str | None:
    """A glob such as `.?`, `.*` or `.gi?` expands to `..` or `.git` in the shell,
    after the guard has looked at the unexpanded word."""
    parts = Path(value).parts
    for i, part in enumerate(parts):
        if not set(part) & set("*?["):
            continue
        if glob_matches(part, ".."):
            return f"{value} is a glob that can expand to ..; name the path"
        if glob_matches(part, ".git"):
            try:
                prefix = resolve(str(Path(*parts[:i])) if i else ".", cwd)
            except (OSError, RuntimeError, ValueError):
                continue
            if prefix == root:
                return f"{value} is a glob that can expand to the worktree's .git; name the path"
    return None


def git_subcommand_index(args: list[str]) -> int | None:
    """Index of the subcommand among git's arguments, past its own options."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in GIT_VALUE_OPTS else 1
    return i if i < len(args) else None


def path_denial(program: str, words: list[str], cwd: Path, roots: list[Path],
                environ: dict[str, str]) -> str | None:
    """Deny a word that is a path leaving the worktree, or naming its `.git`.

    An option value counts, attached (`--output=../x`) or, for git, separate. A
    relative word is checked when the program writes its operands, when it follows a
    redirect, when it is an option value, or when it climbs with `..`; an absolute
    word (`/`, `~`, `$HOME`) always. Search programs and search-pattern options are
    exempt from the `..` rule: `rg -F '../lib'` is a pattern."""
    root = roots[0]
    writes = program in WRITERS
    home = environ.get("HOME") or str(Path.home())
    sub_index = git_subcommand_index(words) if program == "git" else None
    git_grep = sub_index is not None and words[sub_index] == "grep"
    searcher = program in SEARCHERS or git_grep
    reads_git = program in READERS or (program == "git" and "check-ignore" in words) \
        or (program == "find" and not FIND_WRITE_FLAGS & set(words))
    pattern_options = PATTERN_OPTS | ({"-x"} if program == "zip" else set()) \
        | ({"-m", "--message"} if program == "git" else set())
    pattern_first = not PATTERN_FROM_ELSEWHERE & set(words)
    first_plain_is_pattern = program in SEARCHERS and pattern_first   # rg PATTERN PATH...
    after_redirect = False
    previous_option = ""
    for index, word in enumerate(words):
        if word and set(word) <= set("<>&|0123456789") and ">" in word:
            after_redirect = True
            continue
        redirected, after_redirect = after_redirect, False
        option, previous_option = previous_option, word if word.startswith("-") else ""
        value = word
        if program == "dd" and re.match(r"^[a-z]+=", word):
            value = word.split("=", 1)[1]                 # of=PATH, if=PATH
        elif word.startswith("-"):
            name, eq, value = word.partition("=")
            option = name if eq else ""
        pattern_value = option in pattern_options
        if not word.startswith("-"):
            if first_plain_is_pattern:
                pattern_value, first_plain_is_pattern = True, False
            if git_grep and index == sub_index:
                first_plain_is_pattern = pattern_first
            if option and not (program == "git" or option in OUTPUT_OPTIONS.get(program, ())):
                if word == "/" and program == "sort" and option == "-t":
                    continue                               # sort -t /, a delimiter
                option = ""
        if not value or (program in PRINTERS and not redirected):
            continue
        home_var = next((v for v in ("${HOME}", "$HOME") if value.startswith(v)), None)
        if home_var:
            value, absolute = home + value[len(home_var):], True
        else:
            absolute = value.startswith(("/", "~"))
        if pattern_value or (searcher and not absolute):
            continue
        # Unexpanded shell syntax is resolved only where a write could follow.
        spelled = brace_expansions(value) if (writes or redirected or option) else [value]
        for value in spelled:
            checked = absolute or writes or redirected or bool(option) \
                or ".." in Path(value).parts
            if checked and not absolute and (writes or redirected or option):
                why = glob_denial(value, cwd, root)
                if why:
                    return why
            try:
                target = resolve(value, cwd)
            except (OSError, RuntimeError, ValueError):
                if checked:
                    return f"{word} cannot be resolved as a path; use a plain path inside your worktree"
                continue
            if inside_any(target, roots):
                if in_git_pointer(target, root) and not reads_git:
                    return (f"{word} is the worktree's git metadata; leave it to git "
                            "(to skip it in a search, use rg --glob '!.git')")
                if program == "rm" and (target == root or (target.parent == root and target.name in ("*", ".*"))):
                    return "rm of the whole worktree is not allowed; name the paths to remove"
                continue
            if not checked:
                continue
            # The allowed prefixes are for absolute scratch paths; a relative operand
            # that climbs out of the worktree is denied wherever it lands.
            if absolute and allowed_location(target):
                continue
            parts = Path(os.path.expanduser(value)).parts
            if absolute and len(parts) > 1 and not Path("/", parts[1]).exists():
                continue   # /api/users, /app/: a route, regex or alias, not a path on this machine
            return f"{word} is outside your worktree {root}; use paths inside it or under tmp/"
    return None


def stage_denial(words: list[str], cwd: Path, roots: list[Path], environ: dict[str, str],
                 depth: int = 0) -> str | None:
    if depth > 5:
        return "command nesting too deep to check"
    for word in words:
        if "$(" in word or "`" in word:
            inner = word.replace("$(", ";").replace("`", ";").replace(")", ";")
            why = bash_denial(inner, cwd, roots, environ, depth + 1)
            if why:
                return why
    words, why = unwrap(words)
    if why or not words:
        return why
    program, args = os.path.basename(words[0]), words[1:]
    if "/" in words[0]:
        why = path_denial("run", [words[0]], cwd, roots, environ)    # the program is a path too
        if why:
            return why
    if program == "sed" and any(re.match(r"^-[A-Za-z]*i", a) or a.startswith("--in-place")
                                for a in args):
        return "sed -i edits files in place; use the edit tool"
    if program in SHELLS:
        for i, a in enumerate(args):
            if re.match(r"^-[A-Za-z]*c[A-Za-z]*$", a) and i + 1 < len(args):
                return bash_denial(args[i + 1], cwd, roots, environ, depth + 1)
    if program == "eval":
        return bash_denial(" ".join(args), cwd, roots, environ, depth + 1)
    if program == "find":
        for i, a in enumerate(args):
            if a in ("-exec", "-execdir", "-ok", "-okdir"):
                why = stage_denial([w for w in args[i + 1:] if w not in (";", "{}", "+")],
                                   cwd, roots, environ, depth + 1)
                if why:
                    return why
    if program == "git":
        why = git_denial(args, cwd, roots)
    elif program in NETWORK:
        why = "no network tools: dependencies are provisioned before you start"
    elif program in ENV_DUMPERS:
        why = ENV_DUMP_WHY
    elif program in SYSTEM or (program == "defaults" and args[:1] == ["write"]):
        why = "system-level command"
    elif program in ("npm", "pnpm", "yarn", "bun") and args[:1] in (["exec"], ["dlx"], ["x"]):
        why = package_runner_denial(args[1:])
    elif program in ("npx", "bunx", "pnpx"):
        why = package_runner_denial(args)
    elif program in ("npm", "pnpm", "yarn", "bun") and args[:1] in (["publish"],):
        why = "publishing is the maintainer's step"
    elif program in ("npm", "pnpm", "yarn", "bun") and args[:1] in (["i"], ["install"], ["add"]) \
            and ("-g" in args or "--global" in args):
        why = "global installs change the machine"
    elif re.match(r"^pip[0-9.]*$", program) and "install" in args:
        why = "pip installs change an environment outside the worktree"
    elif re.match(r"^python[0-9.]*$", program) and args[:2] == ["-m", "pip"] and "install" in args:
        why = "pip installs change an environment outside the worktree"
    else:
        why = inline_code_denial(program, args)
    return why or path_denial(program, args, cwd, roots, environ)


def bash_denial(command: str, cwd: Path, roots: list[Path], environ: dict[str, str],
                depth: int = 0) -> str | None:
    try:
        stages = split_stages(command)
    except ValueError as err:
        return f"the command does not parse ({err}); run it plainly"
    for stage in stages:
        why = stage_denial(stage, cwd, roots, environ, depth)
        if why:
            return why
    return None


def decide(payload: dict[str, Any], environ: dict[str, str]) -> tuple[str, str | None]:
    guard = environ.get(GUARD_ENV)
    if not guard:
        return "pass", None
    root = Path(guard).expanduser().resolve()
    extra = [Path(p).expanduser().resolve()
             for p in environ.get(EXTRA_ENV, "").split(os.pathsep) if p.strip()]
    roots = [root, *extra]
    cwd = Path(payload.get("cwd") or root).expanduser()
    tool = bare_tool_name(str(payload.get("tool_name", "")))
    tool_input = payload.get("tool_input") or {}
    if tool == "bash":
        why = bash_denial(str(tool_input.get("command", "")), cwd, roots, environ)
    else:
        why = file_denial(tool_input, cwd, roots)
    return ("deny", why) if why else ("pass", None)


def main() -> int:
    payload = json.load(sys.stdin)
    decision, reason = decide(payload, dict(os.environ))
    log = os.environ.get(LOG_ENV)
    if log:
        with open(log, "a") as handle:
            handle.write(json.dumps({"tool_name": payload.get("tool_name"),
                                     "tool_input": payload.get("tool_input"),
                                     "decision": decision, "reason": reason}) + "\n")
    if decision == "deny":
        print(json.dumps({"decision": "deny", "reason": reason}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
