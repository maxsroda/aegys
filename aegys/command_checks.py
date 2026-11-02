"""Deterministic checks on shell commands, file paths and URLs, for the aegys guard.

guard.py runs these checks before it decides a command. Checks 1 and 3, and the
address test of check 4, are fixed in code. Check 2 and the host names of check 4
come from the policy lists (see ``aegys/config.py``):

1. ``rg --pre CMD`` and ``fd -x CMD``: flags that run a command on every file.
   The check sees the flag anywhere in its stage of the command.
2. Secret paths (the policy's ``secretPaths``): no command may read or write them,
   and a recursive search that starts above one is denied.
3. Control files: a write, redirect or inline code that names one changes what
   the harnesses, git or this guard run or allow, so it is denied. So are a
   recursive delete of a critical path and git settings that can run a program.
4. URLs: each URL in a command is checked against the policy's ``deniedHosts``
   and against private, loopback, link-local and metadata addresses (SSRF).

Commands are split into stages by ``aegys/shell_words.py``. Directory changes
inside the command are followed.

This is a pattern check, not a shell parser or a threat feed. It cannot know a
host is malicious, only that it is on the list; it will not see a URL built
from a variable at run time. Over-blocking is cheap (the model gets an error
and rephrases), so patterns lean towards catching more.
"""
from __future__ import annotations

import fnmatch
import glob
import ipaddress
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Policy, harness_config_repository
from .shell_words import (
    FIND_WRITE_FLAGS, PRINTERS, READERS, SEARCHERS, SHELLS, WRITERS, brace_expansions,
    git_config_writes, git_subcommand_index, inside, split_stages, unwrap,
)


def canonicalize_case(value: str) -> str:
    out = []
    for ch in value:
        up = ch.upper()
        if len(up) != 1 or (ord(ch) >= 128 and ord(up) < 128):
            out.append(ch)
        else:
            out.append(up)
    return "".join(out)


def matches_wildcard_pattern(
    pattern: str, value: str, overflow_match: bool = True
) -> bool:
    if len(pattern) > 4096 or len(value) > 1024 * 1024:
        return overflow_match
    norm_pat = canonicalize_case(pattern)
    norm_val = canonicalize_case(value)
    if "*" not in norm_pat:
        return norm_pat == norm_val
    starts_wild = norm_pat.startswith("*")
    ends_wild = norm_pat.endswith("*")
    literals = [lit for lit in norm_pat.split("*") if lit]
    if not literals:
        return True
    lit_idx = 0
    val_idx = 0
    last_lit_idx = len(literals)
    if not starts_wild:
        prefix = literals[0]
        if not norm_val.startswith(prefix):
            return False
        val_idx = len(prefix)
        lit_idx = 1
    search_end = len(norm_val)
    if not ends_wild:
        suffix = literals[-1]
        search_end -= len(suffix)
        if search_end < val_idx or not norm_val.endswith(suffix):
            return False
        last_lit_idx -= 1
    while lit_idx < last_lit_idx:
        literal = literals[lit_idx]
        found = norm_val.find(literal, val_idx, search_end)
        if found < 0:
            return False
        val_idx = found + len(literal)
        lit_idx += 1
    return True


def matches_bash_deny_pattern(arg_pattern: str, candidate: str) -> bool:
    if matches_wildcard_pattern(arg_pattern, candidate, overflow_match=True):
        return True
    if arg_pattern.endswith(" *"):
        return matches_wildcard_pattern(
            arg_pattern[:-2], candidate, overflow_match=True
        )
    return False


# --- bash: allow-listed commands with an exec flag ----------------------------

# The command must be the first word of a pipeline stage: at the start, or right
# after ; | & ( or a backtick. Anchoring on plain whitespace would also match
# the word as an argument, as in `echo fd -x`.
CMD_START = r"(?:^|[;|&(`])\s*"
STAGE = r"[^|;&]*"  # rest of the same pipeline stage

BASH_RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "rg --pre",
        re.compile(rf"{CMD_START}rg\b{STAGE}\s--pre(?:=|\s|$)"),
        "rg --pre runs an arbitrary command on every file; use rg without --pre.",
    ),
    (
        "fd --exec",
        re.compile(
            rf"{CMD_START}(?:fd|fdfind)\b{STAGE}\s"
            r"(?:-[A-Za-z]*[xX][A-Za-z]*|--exec(?:-batch)?)(?:=|\s|$)"
        ),
        "fd -x/-X/--exec runs an arbitrary command on every match; use fd alone "
        "and act on the output separately.",
    ),
]

# --- bash: one pass over the command, stage by stage -----------------------------

SHELL_STRING_FLAG = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")  # -c, -lc, -ec
CWD_CHANGERS = {"cd", "pushd"}
ASSIGNMENT_WORD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
PRIVILEGE_WRAPPERS = {"sudo", "doas"}
PRIVILEGE_VALUE_OPTIONS = {"-u", "-g", "-C", "-D", "-h", "-p", "-U", "-r", "-t", "-T"}


def strip_privilege(words: list[str]) -> list[str]:
    """`sudo`/`doas` and their options removed: the command they run is what counts."""
    words = list(words)
    while words and os.path.basename(words[0]) in PRIVILEGE_WRAPPERS:
        words.pop(0)
        while words and words[0].startswith("-"):
            option = words.pop(0)
            if option in PRIVILEGE_VALUE_OPTIONS and words:
                words.pop(0)
    return words


def run_words(raw: list[str]) -> tuple[list[str], bool]:
    """The words of the command a stage runs, with wrappers, `sudo`/`doas` and
    leading assignments removed, and whether a wrapper was refused. A refused
    stage (GIT_DIR=..., NODE_OPTIONS=...) keeps its words, minus assignments, so
    the path checks still see what it names."""
    words = strip_privilege(raw)
    unwrapped, refusal = unwrap(words)
    if refusal is None:
        return strip_privilege(unwrapped), False
    return [w for w in words if not ASSIGNMENT_WORD.match(w)], True


def expand_home(word: str, home: Path) -> str:
    """`~`, `$HOME` and `${HOME}` at the start of a word, spelled out."""
    for prefix in ("~", "$HOME", "${HOME}"):
        if word == prefix or word.startswith(prefix + "/"):
            return str(home) + word[len(prefix):]
    return word


def resolve_word(word: str, cwd: Path, home: Path) -> Path:
    """The file a shell word or tool argument names, symlinks followed."""
    return (cwd / expand_home(word, home)).resolve()


GLOB_CHARS = frozenset("*?[")


def expand_word(word: str, cwd: Path, home: Path) -> list[Path]:
    """The paths a shell word may name from `cwd`, as the shell would expand it:
    each brace alternative, its literal path, and every existing glob match."""
    paths = []
    for variant in brace_expansions(word):
        spelled = expand_home(variant, home)
        paths.append((cwd / spelled).resolve())
        if GLOB_CHARS & set(spelled):
            paths += [Path(match).resolve() for match in glob.glob(str(cwd / spelled))]
    return paths


# Output and input redirect operators, as split_stages splits them off.
ANY_REDIRECT = re.compile(r"^(?:&?>>?|>\||>&|<>|<|<&|<<<)$")
# What heredoc_bodies leaves in place of each heredoc operator it cut a body for:
# one word the splitter keeps whole, which a stage counts and its words drop.
HEREDOC_MARKER = "__heredoc_body__"


def without_redirects(words: list[str]) -> list[str]:
    """A stage's words without its redirects: each operator, its target, and the
    descriptor number before it (`2>&1` arrives as 2, >&, 1). What a program
    reads and writes is judged from these words; redirect targets separately."""
    kept, skip = [], False
    for word in words:
        if skip:
            skip = False
        elif word == HEREDOC_MARKER:
            continue
        elif ANY_REDIRECT.match(word):
            if kept and kept[-1].isdigit():
                kept.pop()
            skip = True
        else:
            kept.append(word)
    return kept


INTERPRETER = re.compile(r"^(?:sh|bash|zsh|dash|ksh|python[0-9.]*|node|perl|ruby)$")
INLINE_OR_MODULE = {"-c", "-e", "-m", "-p", "--eval", "--print", "-"}


def shell_reads_stdin(words: list[str]) -> bool:
    """Whether a shell takes its commands from standard input: `-s`, or no script
    operand (`-o`, `-O`, `--rcfile` and `--init-file` take a value; `--` ends the
    options)."""
    args, i = words[1:], 0
    while i < len(args):
        arg = args[i]
        if arg in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
        elif arg == "--":
            return i + 1 == len(args)
        elif arg.startswith("-") and not arg.startswith("--") and "s" in arg[1:]:
            return True
        elif arg.startswith(("-", "+")) and arg != "--":
            i += 1
        else:
            return False
    return True


def reads_program_from_stdin(words: list[str]) -> bool:
    """Whether an interpreter (python, node, perl, ruby) takes its program from
    standard input: an explicit `-`, or no script, module or inline-code operand."""
    args = words[1:]
    return "-" in args or not any(a in INLINE_OR_MODULE or not a.startswith("-") for a in args)


# A heredoc operator and its delimiter (`<<EOF`, `<<-'EOF'`, `<< "EOF"`, `<<\EOF`).
HEREDOC_OPERATOR = re.compile(r"<<(-?)[ \t]*\\?(['\"]?)([^\s'\"<>|;&()\\]+)\2")


def heredoc_bodies(command: str) -> tuple[str, list[str]]:
    """The command without its heredoc bodies, and the bodies in order of their
    `<<` operators; the splitter would read each body line as a command of its own.
    Operators are found outside quotes, comments and `((...))`, across lines, so a
    quoted `<<`, one in a comment or one inside a multi-line string is text; each
    one found is replaced by HEREDOC_MARKER, and comments are cut, so the caller
    splits with comments off and a mid-word `#` (`a#b`) stays in its word."""
    out, bodies, pending, quote, arithmetic, i, n = [], [], [], "", 0, 0, len(command)
    while i < n:
        c = command[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(command[i:i + 2])
                i += 2
                continue
            quote = "" if c == quote else quote
        elif c == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        elif c in "'\"":
            quote = c
        elif command.startswith(("$((", "(("), i):
            width = 3 if c == "$" else 2
            arithmetic += 1
            out.append(command[i:i + width])
            i += width
            continue
        elif arithmetic and command.startswith("))", i):
            arithmetic -= 1
            out.append("))")
            i += 2
            continue
        elif not arithmetic and command.startswith("<<", i) and not command.startswith("<<<", i):
            match = HEREDOC_OPERATOR.match(command, i)
            if match:
                pending.append((match.group(3), match.group(1) == "-"))
                out.append(f" {HEREDOC_MARKER} ")
                i = match.end()
                continue
        elif c == "#" and (i == 0 or command[i - 1] in " \t\n;|&()"):
            end = command.find("\n", i)  # a comment runs to the end of its line, and goes
            i = n if end < 0 else end
            continue
        elif c == "\n" and pending:
            out.append(c)
            i += 1
            for delimiter, strip_tabs in pending:  # each body runs to its delimiter line
                body = []
                while i < n:
                    end = command.find("\n", i)
                    end = n if end < 0 else end
                    line, i = command[i:end], end + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
                    body.append(line)
                bodies.append("\n".join(body))
            pending = []
            continue
        out.append(c)
        i += 1
    return "".join(out), bodies


def command_substitutions(text: str) -> list[str]:
    """Every `$(...)` and `` `...` `` command substitution in `text` (outside
    single quotes and `$((...))` arithmetic), in order."""
    subs: list[str] = []
    quote = ""
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if quote == "'":
            if c == "'":
                quote = ""
            i += 1
            continue
        if quote == "$'":
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == "'":
                quote = ""
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if not quote and c == "$" and i + 1 < n and text[i + 1] == "'":
            quote = "$'"
            i += 2
            continue
        if c == '"' and quote in ("", '"'):
            quote = "" if quote == '"' else '"'
            i += 1
            continue
        if not quote and c == "'":
            quote = "'"
            i += 1
            continue
        if text.startswith("$((", i):
            depth_arith = 1
            j = i + 3
            while j < n and depth_arith > 0:
                if text.startswith("((", j):
                    depth_arith += 1
                    j += 2
                elif text.startswith("))", j):
                    depth_arith -= 1
                    j += 2
                else:
                    j += 1
            i = j
            continue
        if text.startswith("$(", i):
            depth_parens = 1
            sub_quote = ""
            j = i + 2
            while j < n and depth_parens > 0:
                ch = text[j]
                if sub_quote == "'":
                    if ch == "'":
                        sub_quote = ""
                elif ch == "\\" and j + 1 < n:
                    j += 2
                    continue
                elif sub_quote == '"':
                    if ch == '"':
                        sub_quote = ""
                else:
                    if ch in ("'", '"'):
                        sub_quote = ch
                    elif ch == "(":
                        depth_parens += 1
                    elif ch == ")":
                        depth_parens -= 1
                        if depth_parens == 0:
                            break
                j += 1
            if depth_parens == 0:
                subs.append(text[i + 2 : j])
                i = j + 1
                continue
        if c == "`":
            j = i + 1
            buf: list[str] = []
            while j < n and text[j] != "`":
                if text[j] == "\\" and j + 1 < n and text[j + 1] in ("$", "`", "\\", '"'):
                    buf.append(text[j + 1])
                    j += 2
                else:
                    buf.append(text[j])
                    j += 1
            if j < n and text[j] == "`":
                subs.append("".join(buf))
                i = j + 1
                continue
        i += 1
    return subs


@dataclass
class Stage:
    """One command of a pipeline or list, as it will run."""

    words: list[str]          # wrappers (env, xargs, sudo, ...) and assignments removed
    cwds: tuple[Path, ...]    # every directory its relative paths may be relative to
    cwd_known: bool           # False after a cd the hook cannot follow
    refused: bool             # a wrapper the hook will not see through (GIT_DIR=..., ...)
    text: str                 # the stage as written, for spelled-path checks
    raw: list[str]            # the stage's words as split, redirects and wrappers included


def command_stages(command: str, cwd: Path, home: Path, depth: int = 0) -> list[Stage] | None:
    """The command's stages in order. Relative paths are checked against the
    session's directory and, after a `cd`/`pushd` or `-C DIR`, that directory
    too: subshells are not tracked, so both stay candidates. `sh -c` strings,
    `eval` and a heredoc a shell runs are expanded; a heredoc another interpreter
    runs joins its words as code; any other heredoc is data. None when the command
    does not parse."""
    command, bodies = heredoc_bodies(command)
    try:
        raw_stages = split_stages(command, comments=False)
    except ValueError:
        return None
    stages: list[Stage] = []
    current, known = cwd, True
    for raw in raw_stages:
        words, refused = run_words(raw)
        words = without_redirects(words)
        program = os.path.basename(words[0]) if words else ""
        stage_bodies = [bodies.pop(0) for word in raw if word == HEREDOC_MARKER and bodies]
        stage_bodies += [raw[k + 1] for k, word in enumerate(raw[:-1]) if word == "<<<"]  # here-strings
        # A stage expanded into its inner commands still has redirects of its own.
        redirects_only = Stage([], tuple(dict.fromkeys([cwd, current])), known, refused, " ".join(raw), raw)
        if stage_bodies and program in SHELLS:
            if shell_reads_stdin(words) and depth < 3:
                stages.append(redirects_only)
                for body in stage_bodies:  # the shell runs the body
                    inner = command_stages(body, current, home, depth + 1)
                    if inner is None:
                        return None
                    stages.extend(inner)
                continue
        elif stage_bodies and INTERPRETER.match(program) and reads_program_from_stdin(words):
            words = [*words, "-", *stage_bodies]  # the program, read like a -c string
        if depth < 3 and program in SHELLS:
            flag = next((i for i, a in enumerate(words[1:-1], 1) if SHELL_STRING_FLAG.match(a)), None)
            if flag is not None:
                inner = command_stages(words[flag + 1], current, home, depth + 1)
                if inner is None:
                    return None
                stages.extend([redirects_only, *inner])
                continue
        if depth < 3 and program == "eval":
            inner = command_stages(" ".join(words[1:]), current, home, depth + 1)
            if inner is None:
                return None
            stages.extend([redirects_only, *inner])
            continue
        cwds = [cwd, current]
        for i, word in enumerate(words[:-1]):
            if word == "-C":
                try:
                    cwds.append(resolve_word(words[i + 1], current, home))
                except (ValueError, OSError, RuntimeError):
                    known = False
        stages.append(Stage(words, tuple(dict.fromkeys(cwds)), known, refused, " ".join(raw), raw))
        if program in CWD_CHANGERS:
            target = words[1] if len(words) > 1 else "~"
            if target == "-" or "$" in target or "`" in target:
                known = False
            else:
                try:
                    current = resolve_word(target, current, home)
                except (ValueError, OSError, RuntimeError):
                    known = False
    if depth < 3:
        for sub in command_substitutions(command):
            inner = command_stages(sub, current, home, depth + 1)
            if inner is None:
                return None
            stages.extend(inner)
    return stages


# --- bash: deletes that never run unattended -------------------------------------

GIVE_IT_BACK = "Do not run it in another form; give the user the exact command to run themselves"


def recursive_rm_operands(args: list[str]) -> tuple[bool, list[str]]:
    """Whether rm's arguments ask for a recursive removal, and its operands."""
    recursive, operands, options_ended = False, [], False
    for arg in args:
        if options_ended or arg == "-" or not arg.startswith("-"):
            operands.append(arg)
        elif arg == "--":
            options_ended = True
        elif arg.startswith("--"):
            recursive = recursive or arg == "--recursive"
        else:
            recursive = recursive or "r" in arg.lower()
    return recursive, operands


# find's global options, with how many arguments each takes. GNU find accepts
# them before the start points too: `find -maxdepth 1 x` searches x.
FIND_GLOBAL_OPTIONS = {
    "-maxdepth": 1, "-mindepth": 1, "-regextype": 1,
    "-depth": 0, "-d": 0, "-xdev": 0, "-mount": 0, "-noleaf": 0, "-follow": 0,
    "-daystart": 0, "-ignore_readdir_race": 0, "-noignore_readdir_race": 0,
    "-warn": 0, "-nowarn": 0,
}


def find_start_points(args: list[str]) -> list[str]:
    """find's starting directories: past its leading options (-H, -L, -P, -D x,
    -O3) and any global options (-maxdepth 2, -xdev), the arguments before the
    first expression."""
    i = 0
    while i < len(args) and (args[i] in ("-H", "-L", "-P", "-D") or args[i].startswith("-O")):
        i += 2 if args[i] == "-D" else 1
    starts = []
    while i < len(args):
        arg = args[i]
        if arg in FIND_GLOBAL_OPTIONS:
            i += 1 + FIND_GLOBAL_OPTIONS[arg]
            continue
        if arg.startswith(("-", "(", "!", ")")):
            break
        starts.append(arg)
        i += 1
    return starts or ["."]


# Tests that make a find select files rather than take everything below its start.
FIND_FILTERS = {
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex",
    "-type", "-newer", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-size",
    "-empty", "-user", "-group", "-perm", "-links", "-inum", "-samefile",
}


FIND_EXEC_FLAGS = {"-exec", "-execdir", "-ok", "-okdir"}
# Programs a find -exec may run that read or change files but delete none.
FIND_EXEC_KEEPS = READERS | SEARCHERS | PRINTERS | {
    "chmod", "chown", "chgrp", "touch", "dos2unix", "unix2dos", "sed", "tee", "cp", "ln",
    "install", "md5sum", "sha1sum", "sha256sum", "shasum", "setfacl", "xattr",
}


def find_deletes(args: list[str]) -> bool:
    """Whether a find deletes: -delete, or an -exec/-ok whose program is not known
    to keep files (rm, mv, a shell, sudo, a script)."""
    if "-delete" in args:
        return True
    return any(a in FIND_EXEC_FLAGS and os.path.basename(args[i + 1]) not in FIND_EXEC_KEEPS
               for i, a in enumerate(args[:-1]))


def find_writes(args: list[str]) -> bool:
    """Whether a find's arguments delete or write: -delete, -fprint..., or an
    -exec/-ok whose command is not a reader (`-exec grep …` only reads)."""
    if any(a in FIND_WRITE_FLAGS - FIND_EXEC_FLAGS for a in args):
        return True
    return any(a in FIND_EXEC_FLAGS and os.path.basename(args[i + 1])
               not in READERS | SEARCHERS | PRINTERS
               for i, a in enumerate(args[:-1]))


# Inside `find -exec sh -c STRING _ {} +`, the positional parameters are find's
# matches, which the find itself is judged for.
FIND_MATCH_PARAMETER = re.compile(r'"?\$\{?[0-9@*]\}?"?')


def find_exec_shell_strings(words: list[str]) -> list[str]:
    """The command strings a find runs through `-exec [env ...] SHELL -c STRING`,
    with its positional parameters replaced by a relative placeholder."""
    strings = []
    for i, word in enumerate(words):
        if word not in FIND_EXEC_FLAGS:
            continue
        inner, refusal = unwrap(strip_privilege(words[i + 1:]))
        inner = strip_privilege(inner)
        if (refusal is None and len(inner) >= 3 and os.path.basename(inner[0]) in SHELLS
                and SHELL_STRING_FLAG.match(inner[1])):
            strings.append(FIND_MATCH_PARAMETER.sub("./find-match", inner[2]))
    return strings


def deletes_in(words: list[str]) -> list[tuple[str, list[str], bool]]:
    """Every recursive `rm` and deleting `find` among a stage's words, wherever it
    sits (after an unknown wrapper such as ionice or ssh, inside `find -exec`):
    (program, operands, whether a find is filtered). An `rm` run by `find -exec`
    gets `{}`/`+` from the find, which is judged itself, so those are dropped.
    `git rm` is git's own subcommand and is judged by git's rules."""
    if words and os.path.basename(words[0]) == "git":
        return []
    found, in_find_exec = [], False
    for i, word in enumerate(words):
        name, rest = os.path.basename(word), words[i + 1:]
        if word in FIND_EXEC_FLAGS:
            in_find_exec = True
        if name == "rm":
            recursive, operands = recursive_rm_operands(rest)
            if in_find_exec:
                operands = [o for o in operands if o not in ("{}", "+")]
                if not operands:
                    continue
            if recursive:
                found.append(("rm", operands, False))
        elif name == "find" and find_deletes(rest):
            found.append(("find", find_start_points(rest), any(a in FIND_FILTERS for a in rest)))
    return found


def critical_removal(command: str, cwd: Path, home: Path,
                     also_critical: frozenset[Path] = frozenset()) -> str | None:
    """What a recursive delete in this command would wipe that no unattended call
    may: /, a directory directly under /, $HOME or a directory above it, the
    session's working directory or a directory above it (also as `dir/*`, through
    a symlink when the operand ends in / or a glob, and through a glob such as
    `~/pro*`), or a target the hook cannot see. Covers `rm -r`, a deleting `find`
    (-delete, or -exec of a program not known to keep files) and the command
    strings a find runs through a shell; a filtered find (`-name`, `-type`, ...)
    may start in the working directory itself unless that is $HOME or above.
    also_critical carries the session's critical paths into a find's shell string,
    which runs in the directory a `cd` reached."""
    stages = command_stages(command, cwd, home)
    if stages is None:
        return None
    critical = {home, *home.parents, cwd, *cwd.parents, *also_critical}
    project_cwd = cwd != home and cwd not in home.parents
    for stage in stages:
        program = os.path.basename(stage.words[0]) if stage.words else ""
        if program in PRINTERS or program in SEARCHERS:
            continue
        if stage.refused and {"rm", "find"} & {os.path.basename(w) for w in stage.words}:
            return f"a delete behind a wrapper the hook cannot see through. {GIVE_IT_BACK}"
        for program, operands, filtered in deletes_in(stage.words):
            why = critical_operand(program, operands, filtered, stage, critical, cwd, home, project_cwd)
            if why:
                return why
        for string in find_exec_shell_strings(stage.words):
            why = critical_removal(string, stage.cwds[-1], home, frozenset(critical))
            if why:
                return why
    return None


def critical_operand(program: str, operands: list[str], filtered: bool, stage: Stage,
                     critical: set[Path], cwd: Path, home: Path, project_cwd: bool) -> str | None:
    """Why one delete's operands reach a critical path, or None."""
    if not operands:
        return f"{program} -r whose operands come from input the hook cannot see. {GIVE_IT_BACK}"
    for operand in (variant for word in operands for variant in brace_expansions(word)):
        spelled = expand_home(operand, home)
        if "$" in spelled or "`" in spelled or spelled.startswith("~") or "{}" in spelled:
            return f"{program} of {operand!r}, whose value the hook cannot see. {GIVE_IT_BACK}"
        if not spelled.startswith("/") and not stage.cwd_known:
            return f"{program} of {operand!r} after a cd the hook cannot see. {GIVE_IT_BACK}"
        stripped = re.sub(r"(?:/\.?\*|/)+$", "", spelled)
        base = "/" if spelled.startswith("/") and not stripped else (stripped or ".")
        if base in ("*", ".*"):
            base = "."
        traverses = spelled != stripped or base == "."  # dir/, dir/*: the target's contents
        for directory in stage.cwds:
            targets = {Path(os.path.normpath(directory / base))}
            try:
                if traverses:
                    targets.add((directory / base).resolve())
                if GLOB_CHARS & set(base):
                    pattern = os.path.normpath(directory / base)
                    targets |= {Path(m).resolve() for m in glob.glob(pattern)}
                    targets |= {c for c in critical if fnmatch.fnmatch(str(c), pattern)}
            except (ValueError, OSError, RuntimeError):
                return f"{program} of {operand!r}, whose target the hook cannot resolve. {GIVE_IT_BACK}"
            for target in targets:
                if filtered and target == cwd and project_cwd:
                    continue
                if not (target in critical or target.parent == Path("/")):
                    continue
                advice = (
                    "If you meant a directory below the working directory, name it in "
                    "the command itself instead of cd-ing into it"
                    if len(stage.cwds) > 1 and not spelled.startswith("/") else GIVE_IT_BACK
                )
                return f"{program} of {operand!r} could remove {target}. {advice}"
    return None


# --- paths that decide what the harnesses or git run or allow, and secrets --------------

# The code that runs as the guard: this package. Editing it edits the guard.
PACKAGE_DIR = Path(__file__).resolve().parent
# Under $HOME: the directories whose binaries choose the guard's own python and
# tools (the aegys launcher lives in ~/.local/bin), and git's user settings (hooks
# path, pager, aliases).
HOME_CONTROL = (".local/bin", ".cargo/bin", "usr/bin", ".gitconfig", ".config/git")
# PATH directories outside $HOME, user-writable on Homebrew Macs.
ABSOLUTE_CONTROL = (Path("/opt/homebrew/bin"), Path("/usr/local/bin"))
# Spellings of those files in free text (inline code, quoted strings). The harness
# config repository adds its own (see control_spellings).
CONTROL_SPELLINGS = (
    "aegys/", ".gitconfig",
    ".local/bin/", ".cargo/bin/", ".config/git/", "/opt/homebrew/bin/", "/usr/local/bin/",
)


def control_dirs(home: Path) -> tuple[Path, ...]:
    """The guard's own package, and the control directories of the harness config
    repository (see aegys.config): what installs and runs the harnesses."""
    repository = harness_config_repository(home)
    return (PACKAGE_DIR, *(repository.control_dirs if repository else ()))


def control_spellings(home: Path) -> tuple[str, ...]:
    """CONTROL_SPELLINGS, and those of the harness config repository."""
    repository = harness_config_repository(home)
    return (*CONTROL_SPELLINGS, *(repository.harness_control_spellings if repository else ()))


def control_areas(home: Path) -> tuple[Path, ...]:
    """The fixed control directories and files, for the ancestor rule."""
    return (*control_dirs(home), *(home / name for name in HOME_CONTROL), *ABSOLUTE_CONTROL)


def harness_control(path: Path, home: Path) -> bool:
    """True when writing path (resolved) changes what the harnesses, git or this
    guard runs or allows."""
    if ".git" in path.parts:
        return True
    if any(inside(path, d) for d in control_dirs(home)) or any(inside(path, d) for d in ABSOLUTE_CONTROL):
        return True
    return any(inside(path, home / name) for name in HOME_CONTROL)


def holds_control(path: Path, home: Path) -> bool:
    """True when path is a directory above a fixed control area: a write into it
    (`cp -r x/. ~/repo/`, `tar -C ~`, `mv ~/repo …`) can replace control
    files without naming them."""
    return any(inside(area, path) for area in control_areas(home))


def secret(path: Path, secret_paths: tuple[str, ...]) -> bool:
    """True when path, or a directory it lies in, matches one of the secret path globs
    (fnmatch syntax, in any letter case). A secret directory covers what is below it."""
    names = [str(p).lower() for p in (path, *path.parents)]
    return any(fnmatch.fnmatchcase(name, pattern.lower())
               for pattern in secret_paths for name in names)


def secret_areas(secret_paths: tuple[str, ...]) -> tuple[str, ...]:
    """The directories and files of the secret paths, as `.ssh` for `*/.ssh/*`,
    read relative to $HOME, or `/home/u/.key` for `/home/u/.key/*` (an entry
    written with `~/` is already absolute), read as itself. A pattern with a
    wildcard left over is no area: it names no fixed place. No recursive search
    may start above an area."""
    areas = (pattern.removeprefix("*/").removesuffix("/*") for pattern in secret_paths)
    return tuple(dict.fromkeys(area for area in areas if not set(area) & set("*?[")))


RECURSIVE_SEARCHERS = {"rg", "grep", "egrep", "fgrep"}
# Options that take a separate value, which is then neither the pattern nor a
# start directory.
RG_VALUE_OPTIONS = {
    "-e", "--regexp", "-f", "--file", "-g", "--glob", "--iglob", "-t", "--type", "-T",
    "--type-not", "--type-add", "--type-clear", "-m", "--max-count", "-A", "--after-context",
    "-B", "--before-context", "-C", "--context", "-M", "--max-columns", "-j", "--threads",
    "-E", "--encoding", "-d", "--max-depth", "-r", "--replace", "--max-filesize",
    "--path-separator", "--pre", "--pre-glob", "--sort", "--sortr", "--color", "--colors",
    "--context-separator", "--field-match-separator", "--field-context-separator",
    "--ignore-file", "--engine", "--dfa-size-limit", "--regex-size-limit",
}
GREP_VALUE_OPTIONS = {
    "-e", "--regexp", "-f", "--file", "-m", "--max-count", "-A", "--after-context", "-B",
    "--before-context", "-C", "--context", "-d", "--directories", "-D", "--devices",
    "--include", "--exclude", "--exclude-dir", "--exclude-from", "--label", "--binary-files",
    "--color", "--colour", "--group-separator",
}


def search_starts(words: list[str]) -> tuple[list[str], bool] | None:
    """Where a recursive search starts (rg, or grep with -r, -R, --recursive or
    -d recurse; default `.`), and whether it skips hidden files and directories,
    as rg does without --hidden or -uu. None for any other stage."""
    if not words or os.path.basename(words[0]) not in RECURSIVE_SEARCHERS:
        return None
    rg = os.path.basename(words[0]) == "rg"
    if rg and "--files" in words:
        return None  # lists file names, reads no contents
    values = RG_VALUE_OPTIONS if rg else GREP_VALUE_OPTIONS
    recursive, hidden, unrestricted, pattern_given = rg, False, 0, False
    operands, args, i = [], words[1:], 0
    while i < len(args):
        arg, i = args[i], i + 1
        if arg == "--":
            operands += args[i:]
            break
        if arg.startswith("--"):
            name, separator, value = arg.partition("=")
            if name in values and not separator:
                value, i = (args[i] if i < len(args) else ""), i + 1
            pattern_given |= name in ("--regexp", "--file")
            hidden |= name == "--hidden"
            unrestricted += name == "--unrestricted"
            recursive |= name in ("--recursive", "--dereference-recursive") or (
                name == "--directories" and value == "recurse")
            continue
        if arg.startswith("-") and len(arg) > 1:
            for j, letter in enumerate(arg[1:]):
                if rg:
                    hidden |= letter == "."
                    unrestricted += letter == "u"
                else:
                    recursive |= letter in "rR"
                if f"-{letter}" in values:
                    value = arg[j + 2:]
                    if not value:
                        value, i = (args[i] if i < len(args) else ""), i + 1
                    pattern_given |= letter in "ef"
                    recursive |= not rg and letter == "d" and value == "recurse"
                    break
            continue
        operands.append(arg)
    if not recursive:
        return None
    if not pattern_given:
        operands = operands[1:]
    # A ripgrep config file can turn --hidden on for every search.
    configured = bool(os.environ.get("RIPGREP_CONFIG_PATH")) and "--no-config" not in args
    return operands or ["."], rg and not hidden and unrestricted < 2 and not configured


def secret_below(start: Path, home: Path, skips_hidden: bool,
                 secret_paths: tuple[str, ...]) -> Path | None:
    """The first secret area a recursive search from start reads: one start is
    inside, or one below start, reached unless the search skips hidden entries
    and the way down passes one."""
    for name in secret_areas(secret_paths):
        area = Path(os.path.realpath(home / name))
        if inside(start, area):
            return area
        if inside(area, start):
            below = area.relative_to(start).parts
            if not (skips_hidden and any(part.startswith(".") for part in below)):
                return area
    return None


# Programs that only read the files they name. A stage whose program is not here
# counts as a write; over-blocking costs the model one rephrase.
READ_ONLY_PROGRAMS = READERS | {
    "jq", "sha1sum", "sha256sum", "shasum", "md5sum", "nl", "uniq", "cut", "tr",
    "column", "basename", "dirname", "pwd", "test", "[", "echo", "printf", "cd",
    "pushd", "sed", "sort", "find", "tree", "git", "export", "declare", "typeset", "unset",
    "set", "alias", "local", "readonly", "for", "select", "case",
}
# git subcommands that leave the working tree's files as they are.
GIT_FILE_KEEPING = {"diff", "log", "show", "status", "blame", "ls-files", "ls-tree",
                    "cat-file", "rev-parse", "grep", "shortlog", "describe", "add", "commit",
                    "config"}
REDIRECT = re.compile(r"^(?:&?>>?|>\||>&|<>)$")
HARMLESS_REDIRECT_TARGET = re.compile(r"^(?:\d+|-|/dev/null|/dev/stdout|/dev/stderr)$")


def redirect_targets(words: list[str]) -> list[str]:
    return [following for word, following in zip(words, [*words[1:], ""])
            if REDIRECT.match(word) and not HARMLESS_REDIRECT_TARGET.match(following)]


# Input redirect operators (a here-string's word is text, not a file).
INPUT_REDIRECT = re.compile(r"^(?:<|<&)$")


def input_targets(words: list[str]) -> list[str]:
    return [following for word, following in zip(words, [*words[1:], ""])
            if INPUT_REDIRECT.match(word) and not HARMLESS_REDIRECT_TARGET.match(following)]


# git settings sections none of whose keys make git run a program, and harmless
# keys of sections that also hold program settings (core.pager, init.templateDir,
# pull.twohead, which names a merge program).
SAFE_GIT_CONFIG_SECTIONS = {
    "user", "color", "advice", "column", "log", "i18n", "status", "commit", "push",
    "fetch", "rebase", "branch", "tag", "apply", "am",
}
SAFE_GIT_CONFIG_KEYS = {
    "init.defaultbranch", "core.autocrlf", "core.quotepath", "core.filemode", "core.safecrlf",
    "core.ignorecase", "merge.conflictstyle", "merge.ff", "pull.rebase", "pull.ff",
}


def git_config_injection(words: list[str]) -> str | None:
    """The first key a `git -c KEY=VALUE` or `--config-env=KEY=VAR` sets that is
    neither in SAFE_GIT_CONFIG_SECTIONS nor in SAFE_GIT_CONFIG_KEYS (core.pager,
    core.hooksPath, alias.*, safe.directory, ...), or None."""
    if not words or os.path.basename(words[0]) != "git":
        return None
    args = words[1:]
    i = git_subcommand_index(args)
    head = args[:i] if i is not None else args
    for j, arg in enumerate(head):
        if arg in ("-c", "--config-env") and j + 1 < len(head):
            setting = head[j + 1]
        elif arg.startswith("--config-env="):
            setting = arg.split("=", 1)[1]
        else:
            continue
        key = setting.split("=", 1)[0]
        if key.split(".", 1)[0].lower() not in SAFE_GIT_CONFIG_SECTIONS \
                and key.lower() not in SAFE_GIT_CONFIG_KEYS:
            return key
    return None


def git_config_target(words: list[str], cwd: Path, home: Path) -> Path | None:
    """The git settings file `git config` with a value writes (--global:
    ~/.gitconfig). None otherwise."""
    if not words or os.path.basename(words[0]) != "git":
        return None
    args = words[1:]
    i = git_subcommand_index(args)
    if i is None or args[i] != "config":
        return None
    rest = args[i + 1:]
    if not git_config_writes([a for a in rest if a.startswith("-")],
                             [a for a in rest if not a.startswith("-")]):
        return None
    if "--global" in rest:
        return home / ".gitconfig"
    if "--system" in rest:
        return Path("/etc/gitconfig")
    return cwd / ".git" / "config"


def git_repository_created(words: list[str], cwd: Path, home: Path) -> Path | None:
    """Where `git init [dir]` or `git clone URL DIR` creates a repository, or None."""
    if not words or os.path.basename(words[0]) != "git":
        return None
    args = words[1:]
    i = git_subcommand_index(args)
    if i is None or args[i] not in ("init", "clone"):
        return None
    positional = [a for a in args[i + 1:] if not a.startswith("-")]
    wanted = 0 if args[i] == "init" else 1
    if len(positional) > wanted:
        target = positional[wanted]
    elif args[i] == "init":
        target = "."
    else:  # clone without DIR: the URL's last component, below cwd
        name = positional[0].rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1] if positional else ""
        target = name[:-4] if name.endswith(".git") else name
        if not target:
            return None
    try:
        return resolve_word(target, cwd, home)
    except (ValueError, OSError, RuntimeError):
        return None


# git subcommands that rewrite the working tree without naming the files they touch.
def git_rewrites_tree(words: list[str]) -> bool:
    if not words or os.path.basename(words[0]) != "git":
        return False
    args = words[1:]
    i = git_subcommand_index(args)
    if i is None:
        return False
    sub, rest = args[i], args[i + 1:]
    if sub in ("am", "merge", "rebase", "pull", "cherry-pick", "revert", "read-tree"):
        return True
    if sub == "apply":
        return not any(a in ("--check", "--stat", "--numstat", "--summary") for a in rest)
    paths = git_checkout_paths(words)
    if paths is not None:  # named files are judged as paths; `:/`, `*.py` or a file list name none
        return (any(path.startswith(":") or GLOB_CHARS & set(path) for path in paths)
                or any(a.startswith("--pathspec-from-file") for a in rest))
    positional = [a for a in rest if not a.startswith("-")]
    if sub == "checkout":  # `-b NEW` keeps the files; `-b NEW START` checks START out
        return not any(a in ("-b", "-B") for a in rest) or len(positional) >= 2
    if sub == "switch":
        creates = any(a in ("-c", "-C", "--create", "--force-create") for a in rest)
        return not creates or len(positional) >= 2
    if sub == "restore":
        return False  # --staged alone writes only the index
    if sub == "reset":
        return any(a in ("--hard", "--merge", "--keep") for a in rest)
    if sub == "stash":
        return not (rest and rest[0] in ("list", "show"))
    return False


def git_checkout_paths(words: list[str]) -> list[str] | None:
    """The paths `git checkout [REF] -- PATHS` or `git restore PATHS` rewrites in
    the working tree; None for any other git command and for `restore --staged`,
    which writes only the index."""
    if not words or os.path.basename(words[0]) != "git":
        return None
    args = words[1:]
    i = git_subcommand_index(args)
    if i is None:
        return None
    sub, rest = args[i], args[i + 1:]
    if sub == "checkout" and "--" in rest:
        return rest[rest.index("--") + 1:]
    if sub == "restore" and not ({"--staged", "-S"} & set(rest) and not {"--worktree", "-W"} & set(rest)):
        paths, skip = [], False
        for arg in rest:
            if skip:
                skip = False
            elif arg in ("-s", "--source"):
                skip = True
            elif not arg.startswith("-"):
                paths.append(arg)
        return paths
    return None


def script_index(words: list[str]) -> int | None:
    """Index of the file an interpreter stage runs, or None (inline code, a module,
    standard input, or not an interpreter)."""
    if not words or not INTERPRETER.match(os.path.basename(words[0])):
        return None
    for i, arg in enumerate(words[1:], 1):
        if arg in INLINE_OR_MODULE or SHELL_STRING_FLAG.match(arg):
            return None
        if not arg.startswith("-"):
            return i
    return None


def executed_file(stage: Stage, home: Path) -> Path | None:
    """The file a stage runs: its program when given as a path, or an interpreter's
    script operand. None for a bare command name or inline code."""
    words = stage.words
    if not words:
        return None
    index = 0 if "/" in words[0] else script_index(words)
    if index is None:
        return None
    try:
        return resolve_word(words[index], stage.cwds[-1], home)
    except (ValueError, OSError, RuntimeError):
        return None


def operand_words(words: list[str]) -> list[str]:
    """A stage's words without the program and an interpreter's script operand:
    running a file does not write it."""
    index = script_index(words)
    rest = words[1:]
    return rest if index is None else rest[:index - 1] + rest[index:]


# A sed command's optional address range and `!`, its `s/re/text/` body, and the
# characters that end a command.
SED_ADDRESS = r"(?:\d+(?:~\d+)?|\$|/(?:\\.|[^/\\])*/[IM]*)"
SED_COMMAND_START = re.compile(
    rf"[\s;]*(?:{SED_ADDRESS}(?:\s*,\s*(?:[+~]?\d+|{SED_ADDRESS}))?)?\s*!*\s*")
SED_SUBSTITUTE = re.compile(r"s(.)((?:\\.|(?!\1).)*)\1((?:\\.|(?!\1).)*)\1")
SED_SEPARATOR = re.compile(r"[;\n{}]")


def sed_script_targets(script: str) -> list[str]:
    """The files a sed script writes: the rest of the line after a `w`/`W` command
    or an `s///` command's `w` flag. Commands are read left to right, so a `w` in
    a regex, a replacement or a file name is not taken for one."""
    targets, i = [], 0
    while i < len(script):
        i = SED_COMMAND_START.match(script, i).end()
        if i >= len(script):
            break
        command = script[i]
        if command in "{}":
            i += 1
            continue
        if command == "s":
            match = SED_SUBSTITUTE.match(script, i)
            if match:
                i = match.end() + len(re.match(r"[0-9gpiImMe]*", script[match.end():]).group(0))
                if i >= len(script) or script[i] not in "wW":
                    continue
                command = script[i]
        if command in "wW":
            end = script.find("\n", i)
            end = len(script) if end < 0 else end
            if script[i + 1:end].strip():
                targets.append(script[i + 1:end].strip())
            i = end
            continue
        separator = SED_SEPARATOR.search(script, i + 1)
        i = separator.start() if separator else len(script)
    return targets


def sed_targets(args: list[str]) -> list[str] | None:
    """The files sed writes besides standard output: the `w` targets of its
    expressions (-e X, -eX, --expression=X, or the first operand when no -e is
    given). None when it rewrites its input files (-i) or runs a script file the
    hook cannot see (-f), so that every operand may be written. Short options are
    read letter by letter: -ni and -nf count."""
    expressions, operands, take_next = [], [], False
    for arg in args:
        if take_next:
            expressions.append(arg)
            take_next = False
        elif arg.startswith(("--in-place", "--file")):
            return None
        elif arg.startswith("--expression"):
            if "=" in arg:
                expressions.append(arg.split("=", 1)[1])
            else:
                take_next = True
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            for j, letter in enumerate(arg[1:]):
                if letter in "if":
                    return None  # -i, -ni, -i.bak, -f, -nf
                if letter == "e":
                    attached = arg[j + 2:]
                    if attached:
                        expressions.append(attached)
                    else:
                        take_next = True
                    break
        elif not arg.startswith("-"):
            operands.append(arg)
    return [target for script in (expressions or operands[:1])
            for target in sed_script_targets(script)]


def sed_files(args: list[str]) -> list[str]:
    """sed's input files: its operands after the script, which is the first
    operand unless -e, --expression, -f or --file gives it."""
    positional, script_given, take_next = [], False, False
    for arg in args:
        if take_next:
            take_next = False
        elif arg.startswith(("--expression", "--file")):
            script_given, take_next = True, "=" not in arg
        elif arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            for j, letter in enumerate(arg[1:]):
                if letter == "i":
                    break  # the rest is a backup suffix
                if letter in "ef":
                    script_given, take_next = True, not arg[j + 2:]
                    break
        elif not arg.startswith("-"):
            positional.append(arg)
    return positional if script_given else positional[1:]


def sed_writes(args: list[str]) -> bool:
    return sed_targets(args) != []


def program_writes(words: list[str]) -> bool:
    """True unless the stage's program only reads the files it names; redirects
    are judged separately, by their targets."""
    if not words:
        return False
    program, args = os.path.basename(words[0]), words[1:]
    if program not in READ_ONLY_PROGRAMS:
        return True
    if program == "sed":
        return sed_writes(args)
    if program == "sort":
        return any(a == "--output" or a.startswith(("-o", "--output=")) for a in args)
    if program == "find":
        return find_writes(args)
    if program == "tree":
        return any(a.startswith("-o") for a in args)
    if program == "git":
        i = git_subcommand_index(args)
        subcommand = args[i] if i is not None else ""
        return subcommand not in GIT_FILE_KEEPING or any(a.startswith("--output") for a in args)
    return False


def stage_paths(stage: Stage, home: Path, words: list[str] | None = None) -> list[Path]:
    """Every path the given words (default: the whole stage) may name: plain words,
    `--opt=value` values and attached short-option values (`-o/path`), against
    each candidate directory, with globs expanded as the shell would."""
    paths = []
    for word in stage.words if words is None else words:
        if URL_WORD.match(word) and "/.." not in word:
            continue  # a URL, not a path
        if word.startswith("--"):
            values = [word.split("=", 1)[1]] if "=" in word else []
        elif word.startswith("-") and len(word) > 2:
            values = [word[2:]]
        elif word.startswith("-"):
            values = []  # -i, -n, -: an option or standard input
        elif KEY_VALUE_WORD.match(word):
            values = [word.split("=", 1)[1]]  # dd of=PATH, make VAR=PATH
        else:
            values = [word]
        for value in values:
            for directory in stage.cwds:
                try:
                    paths.extend(expand_word(value, directory, home))
                except (ValueError, OSError, RuntimeError):
                    continue
    return paths


URL_WORD = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
URL_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"]*")
KEY_VALUE_WORD = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


def repository_code_spelling(names: tuple[str, ...]) -> re.Pattern[str] | None:
    """Inside the harness config repository, its launcher and script directories by
    relative name at the start of a word (so skills/x/scripts/y.py is not one)."""
    if not names:
        return None
    alternatives = "|".join(re.escape(name) for name in names)
    return re.compile(r"(?:^|[\s'\"(=,])((?:\./)?(?:" + alternatives + r")/[^\s'\"),]*)")


COPIERS = {"cp", "ln", "install", "rsync", "ditto"}


def copy_destination(program: str, args: list[str]) -> list[str]:
    """What cp, ln, install, rsync or ditto writes: the -t directory, every operand
    of `install -d`, or the last operand."""
    operands = [a for a in args if not a.startswith("-")]
    if program == "install" and ("-d" in args or "--directory" in args):
        return operands
    for i, arg in enumerate(args):
        if arg in ("-t", "--target-directory") and i + 1 < len(args):
            return [args[i + 1]]
        if arg.startswith("--target-directory="):
            return [arg.split("=", 1)[1]]
    return operands[-1:]


def option_values(args: list[str], short: str, long: str) -> list[str]:
    """The values of an option given as `-o X`, `-oX`, `--output X` or `--output=X`."""
    values = []
    for i, arg in enumerate(args):
        if arg in (short, long) and i + 1 < len(args):
            values.append(args[i + 1])
        elif arg.startswith(long + "="):
            values.append(arg.split("=", 1)[1])
        elif arg.startswith(short) and not arg.startswith("--") and len(arg) > len(short):
            values.append(arg[len(short):])
    return values


TAR_MODES = set("cxtrudA")


def tar_cluster(args: list[str]) -> tuple[int, str]:
    """Where tar's mode letters are and what they are: the first word when it has
    no dash (old style, `tar czf ARCHIVE`), else the first single-dash word holding
    a mode letter, wherever options such as `-C DIR` or `--exclude=X` put it.
    (-1, "") when there is none."""
    if args and not args[0].startswith("-"):
        return 0, args[0]
    for i, arg in enumerate(args):
        if arg.startswith("-") and not arg.startswith("--") and TAR_MODES & set(arg[1:]):
            return i, arg[1:]
    return -1, ""


def tar_directory(args: list[str]) -> list[str]:
    """Where tar extracts: -C DIR, -CDIR, --directory[=]DIR, --one-top-level=DIR,
    or a C in the mode cluster (`-xzC DIR`, `-xCDIR`); [] for the working
    directory."""
    at, cluster = tar_cluster(args)
    for i, arg in enumerate(args):
        if arg in ("-C", "--directory") and i + 1 < len(args):
            return [args[i + 1]]
        if arg.startswith(("--directory=", "--one-top-level=")):
            return [arg.split("=", 1)[1]]
        if arg.startswith("-C") and len(arg) > 2:
            return [arg[2:]]
    if "C" in cluster:
        attached = cluster[cluster.index("C") + 1:]
        after = at + 1 + cluster[:cluster.index("C")].count("f")  # f takes its word first
        return [attached] if attached else args[after:after + 1]
    return []


def tar_created_archive(args: list[str]) -> list[str] | None:
    """The archive a creating tar writes (-f FILE, --file=FILE, or the word after
    a cluster such as czf); None when tar does not create."""
    at, cluster = tar_cluster(args)
    if "--create" not in args and "c" not in cluster:
        return None
    archives = [a.split("=", 1)[1] for a in args if a.startswith("--file=")]
    archives += [args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-f", "--file")]
    if "f" in cluster:
        old_style = at == 0 and not args[0].startswith("-")
        attached = "" if old_style else cluster[cluster.index("f") + 1:]
        archives.append(attached or (args[at + 1] if at + 1 < len(args) else ""))
    return archives


def written_operands(words: list[str]) -> list[str]:
    """The operands a writing stage writes, where the hook can tell them from what
    it reads: a copy's destination, the -o file of sort and tree, sed's `w` files
    (or its input files with -i or -f),
    a creating archiver's archive. Every operand otherwise; redirects never."""
    program, args = os.path.basename(words[0]), words[1:]
    if program in COPIERS:
        return copy_destination(program, args)
    if program in ("sort", "tree"):
        return option_values(args, "-o", "--output")
    if program == "sed":
        targets = sed_targets(args)
        return sed_files(args) if targets is None else targets
    if program in ("tar", "bsdtar"):
        archives = tar_created_archive(args)
        if archives is not None:
            return archives
    if program == "zip":
        return [a for a in args if not a.startswith("-")][:1]
    if program in ("7z", "7za", "7zz"):
        operands = [a for a in args if not a.startswith("-")]
        if operands[:1] in (["a"], ["u"], ["d"]):
            return operands[1:2]
    return operand_words(words)


def ancestor_operands(words: list[str]) -> list[str]:
    """The operands a stage writes into as directories, for the ancestor rule: the
    destination of a copy, every operand of mv, -C or the working directory of an
    extracting tar, unzip's -d, 7z's -o, the start points of a writing find, the
    paths of `git checkout -- PATHS` and `git restore`, dd's of=, and every operand
    of the other writers (rm, chmod, ...). Empty for programs that do not write
    into directories they name, so `cmake ..`, `pytest .` and
    `./configure --prefix=~/.local` are not caught."""
    if not words:
        return []
    program, args = os.path.basename(words[0]), words[1:]
    operands = [a for a in args if not a.startswith("-")]
    if program == "mv":
        return operands  # the sources disappear, the destination is written
    if program in COPIERS:
        return copy_destination(program, args)
    if program == "unzip":
        if any(a in ("-l", "-t", "-v", "-Z", "-p", "-c") for a in args):
            return []  # lists, tests or prints
        return option_values(args, "-d", "--exdir") or ["."]
    if program in ("7z", "7za", "7zz"):
        if not operands or operands[0] not in ("x", "e"):
            return []
        return [a[2:] for a in args if a.startswith("-o")] or ["."]
    if program == "find":
        return find_start_points(args) if find_writes(args) else []
    if program == "git":
        return git_checkout_paths(words) or []
    if program == "zip":
        return []  # writes only its archive
    if program in ("tar", "bsdtar"):
        extracting = "--extract" in args or "--get" in args or "x" in tar_cluster(args)[1]
        return (tar_directory(args) or ["."]) if extracting else []
    if program == "dd":
        return [a.split("=", 1)[1] for a in args if a.startswith("of=")]
    return operands if program in WRITERS else []


def spelled_control(text: str, home: Path, in_config_repository: bool = False) -> str | None:
    """A control-file spelling in free text, where no path can be resolved, as
    the whole word that holds it. URLs are not paths and are skipped, unless they
    climb with `/..`."""
    text = URL_TEXT.sub(lambda m: m.group(0) if "/.." in m.group(0) else " ", text)
    for spelling in control_spellings(home):
        if spelling in text:
            return re.search(r"[^\s'\"(=,]*" + re.escape(spelling) + r"[^\s'\"),]*", text).group(0)
    repository = harness_config_repository(home)
    code_spelling = repository_code_spelling(repository.code_dir_names) if repository else None
    if in_config_repository and code_spelling is not None:
        match = code_spelling.search(text)
        if match:
            return match.group(1)
    return None


CONTROL_WRITE = (
    "this command can write {control}, which decides what the harnesses, git or the guard "
    "run or allow. Change it with the edit tool, where the change is checked, or "
    "leave it to the user"
)

# A program the hook does not know to be read-only, naming a control file: the
# hook cannot tell whether it writes it.
UNKNOWN_PROGRAM_ON_CONTROL = (
    "{program} is not known to only read files, and it names {control}, which decides "
    "what the harnesses, git or the guard run or allow. If it only reads, ask the user to "
    "run it, or run it on a copy in a worktree"
)


def inline_code(words: list[str]) -> list[str]:
    """The program text a python, node, perl or ruby stage runs from its own words:
    the word after -c, -e, -p, --eval or --print (or a cluster such as -pe), and
    everything after a lone `-` (a program on standard input, a heredoc's body).
    Shells are not here: their -c strings are walked as commands."""
    program = os.path.basename(words[0]) if words else ""
    if not INTERPRETER.match(program) or program in SHELLS:
        return []
    code = []
    for i, arg in enumerate(words[1:], 1):
        if arg == "-":
            return [*code, *words[i + 1:]]
        if arg.startswith(("--eval=", "--print=")):
            code.append(arg.split("=", 1)[1])
        elif (arg in ("--eval", "--print") or re.fullmatch(r"-[A-Za-z]*[cep]", arg)) and i + 1 < len(words):
            code.append(words[i + 1])
    return code


CONTROL_ANCESTOR_WRITE = (
    "this command writes into {directory}, which holds files that decide what the harnesses, "
    "git or the guard run or allow. Write into a directory below it, or leave it to "
    "the user"
)
# Added when a relative target after a `cd` is what reached that directory.
AFTER_CD = (
    ". After a cd, the hook checks a relative target from every directory the command "
    "may be in, because it cannot track subshells; name the target directory instead"
)

# An assignment that points git at another repository or working tree, and one
# that hands git settings through the environment (GIT_CONFIG_PARAMETERS,
# GIT_CONFIG_KEY_0, GIT_CONFIG_GLOBAL, ...).
GIT_LOCATION_WORD = re.compile(r"(?:^|\s)GIT_(?:DIR|WORK_TREE|COMMON_DIR)=")
GIT_CONFIG_WORD = re.compile(r"(?:^|\s)GIT_CONFIG\w*=")


def git_environment(earlier: list[Stage], stage: Stage) -> str:
    """The assignments that reach a git stage, as text: its own leading ones and
    those of earlier `export`/`declare`/`typeset` stages. A commit message is not
    among them."""
    exported = [w for s in earlier
                if (os.path.basename(s.words[0]) in ("export", "declare", "typeset") if s.words
                    else all(ASSIGNMENT_WORD.match(w) for w in s.raw))  # `X=1;`, not `X=1 bash -c …`
                for w in s.raw if ASSIGNMENT_WORD.match(w)]
    own = []
    for word in stage.raw:
        if os.path.basename(word) == "git":
            break
        if ASSIGNMENT_WORD.match(word):
            own.append(word)
    return " ".join([*exported, *own])


def git_c_directories(stage: Stage, home: Path) -> list[Path]:
    """Where a git stage given `-C DIR` runs, from each directory it may start in;
    each -C applies to the one before. Empty without -C."""
    if not stage.words or os.path.basename(stage.words[0]) != "git":
        return []
    args = stage.words[1:]
    i = git_subcommand_index(args)
    head = args[:i] if i is not None else args
    values = [head[j + 1] for j, arg in enumerate(head[:-1]) if arg == "-C"]
    if not values:
        return []
    directories = []
    for base in stage.cwds:
        try:
            for value in values:
                base = resolve_word(value, base, home)
        except (ValueError, OSError, RuntimeError):
            continue
        directories.append(base)
    return directories


def git_top(path: Path) -> Path | None:
    """The working tree path lies in: the nearest directory at or above it with a
    `.git` entry (a directory in a main clone, a file in a linked worktree)."""
    return next((d for d in (path, *path.parents) if (d / ".git").exists()), None)


def bash_path_denial(command: str, cwd: Path, home: Path,
                     temp_roots: tuple[Path, ...] = (),
                     policy: Policy | None = None) -> str | None:
    """Why a bash command must not run: a stage names a secret, or searches
    recursively from above one (the secret checks need a policy); a stage's
    redirect targets a control file; git settings are written, or injected with a
    key that can run a program; git
    creates a repository outside the working directory and the temporary
    directories; a stage whose program writes writes a control file or into a
    directory above one; git settings come from the environment; git or patch
    rewrites files of the harness config repository without naming them. A stage
    that runs a file in the repository's control directories runs the user's own
    guarded code, so its operands are not held against it."""
    stages = command_stages(command, cwd, home)
    if stages is None:
        return None
    # Without a policy the secret checks have no paths to check; the guard then asks
    # before the command, so nothing here is allowed on that account.
    secret_paths = policy.secret_paths if policy is not None else None
    for index, stage in enumerate(stages):
        for path in stage_paths(stage, home):
            if secret_paths is not None and secret(path, secret_paths):
                return f"{path} holds keys or credentials, which no tool may read or write"
        searched = search_starts(stage.words)
        if searched is not None and secret_paths is not None:
            starts, skips_hidden = searched
            for start in stage_paths(stage, home, starts):
                reached = secret_below(start, home, skips_hidden, secret_paths)
                if reached is not None:
                    return (f"a recursive search from {start} would read {reached}, which holds "
                            "keys, credentials or session transcripts. Search a directory that "
                            "does not contain it")
        outputs = redirect_targets(stage.raw)
        for target in [*outputs, *input_targets(stage.raw)]:
            for directory in stage.cwds:
                try:
                    resolved = expand_word(target, directory, home)
                except (ValueError, OSError, RuntimeError):
                    continue
                for path in resolved:
                    if secret_paths is not None and secret(path, secret_paths):
                        return f"{path} holds keys or credentials, which no tool may read or write"
                    if target in outputs and harness_control(path, home):
                        return CONTROL_WRITE.format(control=path)
        injected = git_config_injection(stage.words)
        if injected is not None:
            return (f"`git -c {injected}=…` sets a git setting the hook does not know to be "
                    "harmless; settings such as core.pager, core.hooksPath and alias.* run "
                    "programs. Leave it out (for paging, use `git --no-pager`) or ask the user")
        git_settings = git_config_target(stage.words, stage.cwds[-1], home)
        if git_settings is not None:
            return CONTROL_WRITE.format(control=git_settings)
        created = git_repository_created(stage.words, stage.cwds[-1], home)
        in_project = inside(created, cwd) and cwd != home and cwd not in home.parents \
            if created is not None else False
        if created is not None and not (in_project
                                        or any(inside(created, r) for r in temp_roots)):
            return (
                f"git would create a repository at {created}, outside the working directory, "
                "and writes there would then pass as undoable. Ask the user to create it"
            )
        executed = executed_file(stage, home)
        if executed is not None and any(inside(executed, d) for d in control_dirs(home)):
            continue  # the user's own guarded code, run as installed
        # The main clone only: a worktree elsewhere or inside it is ordinary work.
        # `git -C DIR` runs in DIR alone; no subshell can leave it elsewhere.
        repo_dirs = git_c_directories(stage, home) or list(stage.cwds)
        repository = harness_config_repository(home)
        in_config_repository = repository is not None and any(
            git_top(directory) == repository.path for directory in repo_dirs)
        program = os.path.basename(stage.words[0]) if stage.words else ""
        writes = stage.refused or program_writes(stage.words)
        operands = stage.words if stage.refused else written_operands(stage.words) if writes else []
        if writes:
            known_writer = stage.refused or program in WRITERS or program in READ_ONLY_PROGRAMS
            for path in stage_paths(stage, home, operands):
                if harness_control(path, home):
                    if known_writer:
                        return CONTROL_WRITE.format(control=path)
                    return UNKNOWN_PROGRAM_ON_CONTROL.format(program=program, control=path)
            for word in ancestor_operands(stage.words):
                for path in stage_paths(stage, home, [word]):
                    if holds_control(path, home):
                        after_cd = len(stage.cwds) > 1 and not expand_home(word, home).startswith("/")
                        return CONTROL_ANCESTOR_WRITE.format(directory=path) + (AFTER_CD if after_cd else "")
            # Words are judged by where they resolve; only text no path can be read
            # from (inline code, a refused wrapper) is searched for spellings.
            spelled = spelled_control(stage.text if stage.refused else " ".join(inline_code(stage.words)),
                                      home, in_config_repository)
            if spelled is not None:
                return CONTROL_WRITE.format(control=spelled)
        git_at = next((i for i, w in enumerate(stage.words) if os.path.basename(w) == "git"), None)
        environment = git_environment(stages[:index], stage) if git_at is not None else ""
        relocated = git_at is not None and (GIT_LOCATION_WORD.search(environment) or any(
            w.startswith(("--git-dir", "--work-tree")) for w in stage.words[git_at + 1:]))
        if git_at is not None and GIT_CONFIG_WORD.search(environment):
            return ("git settings given through GIT_CONFIG_* variables, which the hook does not "
                    "read, can make git run a program. Leave them out or ask the user")
        if relocated and (git_rewrites_tree(stage.words[git_at:])
                          or git_checkout_paths(stage.words[git_at:]) is not None):
            return (
                "git pointed at another repository or working tree (GIT_DIR, GIT_WORK_TREE, "
                "--git-dir, --work-tree) would rewrite a tree the hook cannot locate. Leave it "
                "to the user"
            )
        if in_config_repository and (git_rewrites_tree(stage.words) or program == "patch"):
            return (
                f"this command may rewrite files of the harness config repository ({repository.path}) "
                "without naming them, which could change what the harnesses run. To restore named "
                "files, use `git restore FILE` or `git checkout -- FILE`, which are judged by "
                "their paths; for a worktree, name it with `git -C WORKTREE`; otherwise leave "
                "it to the user"
            )
    return None


# --- URLs: hosts no tool may contact --------------------------------------------
# A host matches if it equals an entry or ends with "." + entry. The listed hosts
# are the policy's deniedHosts (see aegys/config.py).

# Names that resolve inside this machine's own network or to cloud metadata.
# web_fetch runs locally, so a URL here reaches services the model should not.
INTERNAL_HOST_SUFFIXES = [
    "localhost", "local", "internal", "lan", "home.arpa", "metadata.google.internal",
]
INTERNAL_REASON = "internal / private network name"

# "]" stays inside a URL so bracketed IPv6 hosts like http://[::1]/ survive.
URL_PATTERN = re.compile(r"https?://[^\s'\"<>`)}]+", re.IGNORECASE)


def host_denial_reason(host: str, denied_hosts: dict[str, str] | None) -> str | None:
    """Why a host must not be contacted, or None. Private, loopback, link-local and
    reserved addresses are always denied. Then the names: those of denied_hosts (host
    to reason, from the policy) and the internal suffixes. Without a policy,
    denied_hosts is None and only the address check and the internal suffixes apply."""
    host = host.lower().rstrip(".")
    if not host:
        return None
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return "private, loopback, link-local or metadata address"
        return None
    names = (*(denied_hosts or {}).items(),
             *((name, INTERNAL_REASON) for name in INTERNAL_HOST_SUFFIXES))
    for denied, why in names:
        if host == denied or host.endswith("." + denied):
            return why
    return None


def iter_strings(value: Any):
    """Every string inside a nested tool input, in order."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from iter_strings(v)


def urls_in(tool_input: dict[str, Any]):
    """Every full http(s) URL in the strings of a tool input."""
    for text in iter_strings(tool_input):
        yield from URL_PATTERN.findall(text)


SYSTEM_TEMP_ROOTS = tuple({Path(p).resolve() for p in ("/tmp", "/var/tmp", tempfile.gettempdir())})


