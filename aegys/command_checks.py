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
import itertools
import os
import re
import shlex
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Policy, harness_config_repository
from .shell_words import (
    FIND_WRITE_FLAGS, PRINTERS, PUNCTUATION, READERS, SEARCHERS, SEPARATOR_CHARS,
    SHELLS, WRITERS, brace_expansions, git_config_writes, git_subcommand_index,
    inside, path_exists, path_is_dir, path_is_file, unwrap,
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
    """Whether a deny or ask pattern matches a command. A ` * ` between two words
    matches any arguments between them, including none: `find * -fprint*` matches
    `find -fprint out` as well as `find . -fprint out`. A trailing ` *` likewise
    matches no arguments. A pattern with more than five ` * ` matches them only as
    written, one or more arguments each."""
    parts = arg_pattern.split(" * ")
    joints_choices = (
        itertools.product((" * ", " "), repeat=len(parts) - 1) if len(parts) <= 6
        else [(" * ",) * (len(parts) - 1)]
    )
    for joints in joints_choices:
        pattern = parts[0] + "".join(joint + part for joint, part in zip(joints, parts[1:]))
        if matches_wildcard_pattern(pattern, candidate, overflow_match=True):
            return True
        if pattern.endswith(" *") and matches_wildcard_pattern(
            pattern[:-2], candidate, overflow_match=True
        ):
            return True
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
# What _heredoc_bodies_with_quoting leaves in place of each heredoc operator it cut a body for:
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
    standard input: an explicit `-` before any script, module or inline-code
    operand, or no script, module or inline-code operand."""
    args = words[1:]
    first = next(
        (
            a
            for a in args
            if a in INLINE_OR_MODULE
            or a.startswith(("--eval=", "--print="))
            or re.fullmatch(r"-[A-Za-z]*[cep]", a)
            or not a.startswith("-")
        ),
        None,
    )
    return first is None or first == "-"


# A heredoc operator and its delimiter (`<<EOF`, `<<-'EOF'`, `<< "EOF"`, `<<\EOF`).
HEREDOC_OPERATOR = re.compile(r"<<(-?)[ \t]*(\\?)(['\"]?)([^\s'\"<>|;&()\\]+)\3")


def _heredoc_bodies_with_quoting(command: str) -> tuple[str, list[tuple[str, bool]]]:
    """Return `(stripped_command, [(body, is_unquoted), ...])` in order of `<<`.
    The stripped command has its comments cut, its heredoc bodies taken out, and each
    backslash-newline outside single quotes removed, as the shell joins the lines."""
    out, bodies, pending, quote, arithmetic, i, n = [], [], [], "", 0, 0, len(command)
    while i < n:
        c = command[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < n:
                if command[i + 1] != "\n":  # inside double quotes a backslash-newline joins lines
                    out.append(command[i:i + 2])
                i += 2
                continue
            quote = "" if c == quote else quote
        elif c == "\\" and i + 1 < n:
            if command[i + 1] != "\n":  # a backslash-newline joins the lines, before any `#` is read
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
                unquoted = not (match.group(2) or match.group(3))
                pending.append((match.group(4), match.group(1) == "-", unquoted))
                out.append(f" {HEREDOC_MARKER} ")
                i = match.end()
                continue
        elif c == "#" and (not out or out[-1][-1] in " \t\n;|&()"):
            end = command.find("\n", i)  # a comment runs to the end of its line, and goes
            i = n if end < 0 else end
            continue
        elif c == "\n" and pending:
            out.append(c)
            i += 1
            for delimiter, strip_tabs, unquoted in pending:  # each body runs to its delimiter line
                body = []
                while i < n:
                    end = command.find("\n", i)
                    end = n if end < 0 else end
                    line, i = command[i:end], end + 1
                    if (line.lstrip("\t") if strip_tabs else line) == delimiter:
                        break
                    body.append(line)
                bodies.append(("\n".join(body), unquoted))
            pending = []
            continue
        out.append(c)
        i += 1
    return "".join(out), bodies


def _scan_substitutions(text: str) -> tuple[list[tuple[int, str]], str]:
    """Return `([(offset, sub), ...], masked_text)` where unquoted backtick spans
    are replaced with underscores of equal length so `shlex` keeps surrounding words
    in the same stage while the backtick body is walked separately."""
    subs: list[tuple[int, str]] = []
    masked = list(text)
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
            if depth_arith == 0:
                inner_subs, _ = _scan_substitutions(text[i + 3 : j - 2])
                for sub_off, sub in inner_subs:
                    subs.append((i + 3 + sub_off, sub))
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
                elif sub_quote in ('"', "`"):
                    if ch == sub_quote:
                        sub_quote = ""
                else:
                    if ch in ("'", '"', "`"):
                        sub_quote = ch
                    elif ch == "(":
                        depth_parens += 1
                    elif ch == ")":
                        depth_parens -= 1
                        if depth_parens == 0:
                            break
                j += 1
            if depth_parens == 0:
                subs.append((i, text[i + 2 : j]))
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
                subs.append((i, "".join(buf)))
                if not quote:
                    for k in range(i, j + 1):
                        masked[k] = "_"
                i = j + 1
                continue
        i += 1
    return subs, "".join(masked)


def command_substitutions(text: str) -> list[str]:
    """Every `$(...)` and `` `...` `` command substitution in `text` (outside
    single quotes, including inside `$((...))` arithmetic), in order."""
    subs, _ = _scan_substitutions(text)
    return [sub for _off, sub in subs]


def _split_stages_with_ends(command: str) -> list[tuple[list[str], int, bool]]:
    """Split `command` (comments already cut) into `(raw_stage, end_offset, piped)`
    triples; `piped` is whether a pipe (`|`, `|&`) leads into the stage."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=PUNCTUATION)
    lexer.commenters = ""
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    stages: list[tuple[list[str], int, bool]] = []
    stage: list[str] = []
    piped_in = piped_next = False
    for token in lexer:
        if token and (set(token) <= SEPARATOR_CHARS or re.fullmatch(r"[<>]+\(+", token)):
            if stage:
                pos = (
                    lexer.instream.tell()
                    - len(getattr(lexer, "_pushback_chars", ()))
                    - len(lexer.pushback)
                )
                stages.append((stage, pos, piped_in))
                stage = []
                piped_in = False
            # a newline after a pipe continues the pipeline
            piped_next = token.rstrip("\n") in ("|", "|&") or (piped_next and token == "\n")
            piped_in = piped_next
        else:
            stage.append(token)
    if stage:
        stages.append((stage, len(command), piped_in))
    return stages


@dataclass
class Stage:
    """One command of a pipeline or list, as it will run."""

    words: list[str]          # wrappers (env, xargs, sudo, ...) and assignments removed
    cwds: tuple[Path, ...]    # every directory its relative paths may be relative to
    cwd_known: bool           # False after a cd the hook cannot follow
    refused: bool             # a wrapper the hook will not see through (GIT_DIR=..., ...)
    text: str                 # the stage as written, for spelled-path checks
    raw: list[str]            # the stage's words as split, redirects and wrappers included
    piped: bool = False       # its standard input is the previous stage's output (`|`, `|&`)


def command_stages(
    command: str,
    cwd: Path,
    home: Path,
    depth: int = 0,
    initial_cwds: tuple[Path, ...] | None = None,
    initial_known: bool = True,
) -> list[Stage] | None:
    """The command's stages in order. Relative paths are checked against the
    session's directory and, after a `cd`/`pushd` or `-C DIR`, that directory
    too: subshells are not tracked, so both stay candidates. `sh -c` strings,
    `eval`, `$(...)` and backtick command substitutions, and a heredoc a shell
    runs are expanded; a heredoc another interpreter runs joins its words as code;
    any other heredoc is data (with command substitutions in unquoted heredocs
    still walked). None when the command does not parse."""
    command, bodies = _heredoc_bodies_with_quoting(command)
    subs_with_offsets, masked_command = _scan_substitutions(command)
    try:
        raw_stages_with_ends = _split_stages_with_ends(masked_command)
    except ValueError:
        return None
    subs_by_stage: dict[int, list[str]] = {}
    if raw_stages_with_ends:
        for sub_off, sub in subs_with_offsets:
            idx = next(
                (i for i, (_r, end_off, _p) in enumerate(raw_stages_with_ends) if end_off > sub_off),
                len(raw_stages_with_ends) - 1,
            )
            subs_by_stage.setdefault(idx, []).append(sub)
    stages: list[Stage] = []
    base_cwds = initial_cwds if initial_cwds is not None else (cwd,)
    current, known = cwd, initial_known
    for stage_idx, (raw, _end_off, stage_piped) in enumerate(raw_stages_with_ends):
        words, refused = run_words(raw)
        words = without_redirects(words)
        program = os.path.basename(words[0]) if words else ""
        stage_heredocs = [bodies.pop(0) for word in raw if word == HEREDOC_MARKER and bodies]
        stage_bodies = [body for body, _unquoted in stage_heredocs]
        unquoted_bodies = [body for body, unquoted in stage_heredocs if unquoted]
        cwds = [*base_cwds, current]
        for i, word in enumerate(words[:-1]):
            if word == "-C":
                try:
                    cwds.append(resolve_word(words[i + 1], current, home))
                except (ValueError, OSError, RuntimeError):
                    known = False
        stage_cwds = tuple(dict.fromkeys(cwds))
        if depth < 3:
            stage_subs = list(subs_by_stage.get(stage_idx, ()))
            if not (stage_bodies and program in SHELLS and shell_reads_stdin(words)):
                for body in unquoted_bodies:
                    stage_subs.extend(command_substitutions(body))
            for sub in stage_subs:
                inner = command_stages(
                    sub, current, home, depth + 1, initial_cwds=stage_cwds, initial_known=known
                )
                if inner is None:
                    return None
                stages.extend(inner)
        # A stage expanded into its inner commands still has redirects of its own.
        redirects_only = Stage([], stage_cwds, known, refused, " ".join(raw), raw)
        if stage_bodies and program in SHELLS:
            if shell_reads_stdin(words) and depth < 3:
                stages.append(redirects_only)
                for body in stage_bodies:  # the shell runs the body
                    inner = command_stages(
                        body, current, home, depth + 1, initial_cwds=stage_cwds, initial_known=known
                    )
                    if inner is None:
                        return None
                    stages.extend(inner)
                continue
        elif stage_bodies and INTERPRETER.match(program) and reads_program_from_stdin(words):
            words = [*words, "-", *stage_bodies]  # the program, read like a -c string
        if depth < 3 and program in SHELLS:
            flag = next((i for i, a in enumerate(words[1:-1], 1) if SHELL_STRING_FLAG.match(a)), None)
            if flag is not None:
                inner = command_stages(
                    words[flag + 1], current, home, depth + 1, initial_cwds=stage_cwds, initial_known=known
                )
                if inner is None:
                    return None
                stages.extend([redirects_only, *inner])
                continue
        if depth < 3 and program == "eval":
            inner = command_stages(
                " ".join(words[1:]), current, home, depth + 1, initial_cwds=stage_cwds, initial_known=known
            )
            if inner is None:
                return None
            stages.extend([redirects_only, *inner])
            continue
        stages.append(Stage(words, stage_cwds, known, refused, " ".join(raw), raw, stage_piped))
        if program in CWD_CHANGERS:
            target = words[1] if len(words) > 1 else "~"
            if target == "-" or "$" in target or "`" in target:
                known = False
            else:
                try:
                    current = resolve_word(target, current, home)
                except (ValueError, OSError, RuntimeError):
                    known = False
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
    if any(p.lower() == ".git" for p in path.parts):
        return True
    if git_settings_match(path, home) is not None:
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


CHECKSUM_PROGRAMS = {"md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum",
                     "sha512sum", "shasum", "b2sum", "cksum"}


def reads_a_file_list(words: list[str]) -> bool:
    """True for sort, wc and du with `--files0-from` (or a prefix of it), and for a
    checksum program with -c or --check, which read every file a list names."""
    if not words:
        return False
    program, args = os.path.basename(words[0]), words[1:]
    if program in ("sort", "wc", "du"):
        return any(word.startswith("--fi") and "--files0-from".startswith(word.partition("=")[0])
                   for word in args)
    if program in CHECKSUM_PROGRAMS:
        return any(word.startswith("--c") and "--check".startswith(word)
                   or word.startswith("-") and not word.startswith("--") and "c" in word
                   for word in args)
    return False


ENV_PATHSPEC = re.compile(r"^:(?:[!^]|\((?P<magic>[^)]*)\))\*\.env\*$")


def excludes_env_pathspec(word: str) -> bool:
    """Whether a pathspec excludes `*.env*` from the root down: `:!`, `:^` or `:(exclude)`,
    with at most `icase` and `top` beside it. `literal` reads the `*` literally and `glob`
    stops it at a `/`, so neither excludes a nested or any `.env.*` file."""
    match = ENV_PATHSPEC.match(word)
    if match is None:
        return False
    if match.group("magic") is None:
        return True
    magic = match.group("magic").split(",")
    return "exclude" in magic and set(magic) <= {"exclude", "icase", "top"}


# The long options of git add (the hidden --unified and --inter-hunk-context included, which
# make --u and --inter ambiguous), and those that stage a whole tree or a list.
GIT_ADD_LONG_OPTIONS = (
    "--all", "--chmod", "--dry-run", "--edit", "--force", "--ignore-errors", "--ignore-missing",
    "--ignore-removal", "--intent-to-add", "--inter-hunk-context", "--interactive", "--no-all",
    "--no-ignore-removal", "--patch", "--pathspec-file-nul", "--pathspec-from-file", "--refresh",
    "--renormalize", "--sparse", "--unified", "--update", "--verbose",
)
GIT_ADD_BROAD_OPTIONS = {"--all", "--update", "--interactive", "--pathspec-from-file"}


def git_add_stages_broadly(words: list[str], cwds: tuple[Path, ...], home: Path) -> bool:
    """True for `git add` of `.`, a directory, a glob, `-A`/`--all`, `-u`/`--update`,
    `-i`/`--interactive` or a pathspec file, which stages every un-ignored `.env.*` the
    work tree holds (and `git diff --cached`, `git status -v` and others then print it),
    unless the command carries an excluding pathspec such as `':!*.env*'`. Guarding the
    staging step covers the readers that print whole trees, and only for `.env.*`: a
    reader that names an index entry (`git show :.npmrc`) is guarded by
    `git_object_reads_secret`, and a bare reader of history (`git log -p`) is not guarded."""
    if not words or os.path.basename(words[0]) != "git" or "add" not in words[1:]:
        return False
    rest = words[words.index("add") + 1:]
    operands = rest[rest.index("--") + 1:] if "--" in rest else []
    options = rest[:rest.index("--")] if "--" in rest else rest
    operands += [word for word in options if not word.startswith("-")]
    options = [word for word in options if word.startswith("-")]
    if any(excludes_env_pathspec(word) for word in operands):
        return False
    # -i stages untracked files from its piped answers; -p and -e touch tracked files only.
    # git reads an unambiguous prefix of a long option as the full name (`--al` is `--all`).
    if any(resolve_long_option(word.partition("=")[0], GIT_ADD_LONG_OPTIONS) in GIT_ADD_BROAD_OPTIONS
           or re.fullmatch(r"-[A-Za-z]*[Aui][A-Za-z]*", word) for word in options):
        return True
    for operand in operands:
        if operand.endswith("/") or set(operand) & set("*?[") or operand.startswith(":"):
            return True
        for cwd in cwds:
            try:
                if any(path_is_dir(path) for path in expand_word(operand, cwd, home)):
                    return True
            except (ValueError, OSError, RuntimeError):
                return True
    return False


GIT_OBJECT_READERS = {"show", "cat-file", "diff", "log"}


def git_object_reads_secret(words: list[str], secret_paths: tuple[str, ...]) -> bool:
    """True for a git reader (`show`, `cat-file`, `diff`, `log`) with an operand that
    names a secret path inside an object: `REV:path`, `:path` (the index) or `:N:path`.
    `expand_word` reads `HEAD:.env` as a file named `HEAD:.env`, so the path checks never
    see it. The path is read from the repository root, written with a leading `/` for
    the secret globs."""
    if not words or os.path.basename(words[0]) != "git":
        return False
    rest = words[1:]
    if not GIT_OBJECT_READERS & set(rest):
        return False
    for word in rest:
        if word.startswith("-") or ":" not in word:
            continue
        revision, _, path = word.partition(":")
        if re.fullmatch(r"[0-3]", path.partition(":")[0]) and revision == "":
            path = path.partition(":")[2]  # `:N:path`, an index entry at stage N
        path = os.path.normpath("/" + path)
        if secret(Path(path), secret_paths):
            return True
    return False


def rg_runs_a_program(words: list[str]) -> bool:
    """True for rg with `--hostname-bin`, which runs a program to learn the host name."""
    return (bool(words) and os.path.basename(words[0]) == "rg"
            and any(word == "--hostname-bin" or word.startswith("--hostname-bin=")
                    for word in words[1:]))


def git_add_forces(words: list[str]) -> bool:
    """True for `git add` with -f or --force (also among combined short flags)."""
    if not words or os.path.basename(words[0]) != "git" or "add" not in words[1:]:
        return False
    return any(word == "--force" or re.fullmatch(r"-[A-Za-z]*f[A-Za-z]*", word)
               for word in words[words.index("add") + 1:])


GH_TOKEN_FLAG = re.compile(r"^(?:--show-token(?:=.*)?|-[A-Za-z]*t[A-Za-z]*(?:=.*)?)$")


def gh_shows_token(words: list[str]) -> bool:
    """True for `gh auth status` with `-t` or `--show-token`, which prints the GitHub
    token: `-t` alone, among combined short flags (`-at`), or with a value (`-t=true`).
    Read from the stage's words, so quoting and escaping do not hide the flag. The
    match is case-sensitive, as gh's flags are."""
    return (len(words) >= 3 and os.path.basename(words[0]) == "gh" and words[1:3] == ["auth", "status"]
            and any(GH_TOKEN_FLAG.match(word) for word in words[3:]))


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


# The names a recursive search must not read: .env files and a repository's .git
# directory, which holds .git/config and its remote URLs.
SEARCH_SECRET_FILE = ".env"
SEARCH_SECRET_DIRECTORY = ".git"
# `.env.staging` and kin have no fixed set of names, so an exclusion of them is
# accepted only in these spellings, each of which covers all of them.
ENV_FAMILY_EXCLUSIONS = {".env*", ".env.*", ".*", "*"}
ENV_FAMILY_PREFIX = ".env."


@dataclass(frozen=True)
class NameFilter:
    """One option of a search that includes or excludes names, in command-line order."""

    exclude: bool
    pattern: str
    applies_to: str = "both"        # "file", "directory" or "both"
    ignore_case: bool = False


@dataclass(frozen=True)
class Search:
    """A stage that reads every file below the paths it names."""

    starts: list[str]           # the paths it starts from (default `.`)
    skips_hidden: bool          # skips hidden files and directories, as rg does without --hidden
    filters: tuple[NameFilter, ...] = ()   # its --include, --exclude, -g and -x options, in order
    exclusion_words: frozenset[int] = frozenset()  # indexes in the stage's words of the filters
    program: str = "grep"       # "grep", "rg", "diff" or "git"
    explicit_starts: bool = True    # the command names its start paths (else it reads `.` or stdin)


def name_filtered_out(name: str, is_directory: bool, filters: tuple[NameFilter, ...]) -> bool | None:
    """Whether the filters exclude `name` (True), include it (False), or say nothing
    (None): the last filter that matches decides, as in rg and, by its manual, GNU grep."""
    decision = None
    for entry in filters:
        if entry.applies_to != "both" and (entry.applies_to == "directory") != is_directory:
            continue
        pattern, candidate = entry.pattern, name
        if entry.ignore_case:
            pattern, candidate = pattern.lower(), name.lower()
        # fnmatch reads no escapes and no braces, which grep and rg do: an include with
        # either may name any name, so it counts as including this one.
        if fnmatch.fnmatchcase(candidate, pattern) or (
                not entry.exclude and set(pattern) & set("\\{")):
            decision = entry.exclude
    return decision


def could_match_env_family(pattern: str, ignore_case: bool) -> bool:
    """Whether a glob may match a name that starts with `.env.`: its literal start
    agrees with `.env.` as far as it goes, and it has a wildcard or goes past it."""
    pattern = pattern.lower() if ignore_case else pattern
    if set(pattern) & set("\\{"):
        return True  # an escape or a brace may spell any name
    literal = re.split(r"[*?\[]", pattern, maxsplit=1)[0]
    if literal.startswith(ENV_FAMILY_PREFIX):
        return True
    return ENV_FAMILY_PREFIX.startswith(literal) and len(literal) < len(pattern)


def env_family_covered(filters: tuple[NameFilter, ...]) -> bool:
    """Whether the filters exclude `.env.*`: one of them excludes it in a known spelling
    and no later filter may include a `.env.*` name again."""
    last = None
    for index, entry in enumerate(filters):
        pattern = entry.pattern.lower() if entry.ignore_case else entry.pattern
        if entry.exclude and entry.applies_to != "directory" and pattern in ENV_FAMILY_EXCLUSIONS:
            last = index
    return last is not None and not any(
        not entry.exclude and entry.applies_to != "directory"
        and could_match_env_family(entry.pattern, entry.ignore_case)
        for entry in filters[last + 1:])


def uncovered_secrets(search: Search) -> list[str]:
    """The secret names the search does not clearly exclude: `.env`, `.env.*` and `.git`.
    A name is covered by an excluding option that no later including option undoes."""
    uncovered = []
    if not name_filtered_out(SEARCH_SECRET_FILE, False, search.filters):
        uncovered.append(SEARCH_SECRET_FILE)
    if not env_family_covered(search.filters):
        uncovered.append(ENV_FAMILY_PREFIX + "*")
    if not name_filtered_out(SEARCH_SECRET_DIRECTORY, True, search.filters):
        uncovered.append(SEARCH_SECRET_DIRECTORY)
    return uncovered


# The long options of GNU grep and diff, which read an unambiguous prefix as the full name.
GREP_LONG_OPTIONS = (
    "--after-context", "--basic-regexp", "--before-context", "--binary", "--binary-files",
    "--byte-offset", "--color", "--colour", "--context", "--count", "--dereference-recursive",
    "--devices", "--directories", "--exclude", "--exclude-dir", "--exclude-from",
    "--extended-regexp", "--file", "--files-with-matches", "--files-without-match",
    "--fixed-strings", "--group-separator", "--help", "--ignore-case", "--include",
    "--initial-tab", "--invert-match", "--label", "--line-buffered", "--line-number",
    "--line-regexp", "--max-count", "--no-filename", "--no-group-separator",
    "--no-ignore-case", "--no-messages", "--null", "--null-data", "--only-matching",
    "--perl-regexp", "--quiet", "--recursive", "--regexp", "--silent", "--text", "--version",
    "--with-filename", "--word-regexp",
)
DIFF_LONG_OPTIONS = (
    "--brief", "--color", "--context", "--ed", "--exclude", "--exclude-from", "--expand-tabs",
    "--from-file", "--help", "--horizon-lines", "--ifdef", "--ignore-all-space",
    "--ignore-blank-lines", "--ignore-case", "--ignore-file-name-case",
    "--ignore-matching-lines", "--ignore-space-change", "--ignore-tab-expansion",
    "--ignore-trailing-space", "--initial-tab", "--label", "--left-column", "--line-format",
    "--minimal", "--new-file", "--no-dereference", "--no-ignore-file-name-case", "--normal",
    "--paginate", "--palette", "--rcs", "--recursive", "--report-identical-files",
    "--show-c-function", "--show-function-line", "--side-by-side", "--speed-large-files",
    "--starting-file", "--strip-trailing-cr", "--suppress-blank-empty",
    "--suppress-common-lines", "--tabsize", "--text", "--to-file", "--unidirectional-new-file",
    "--unified", "--version", "--width",
)


def resolve_long_option(name: str, options: tuple[str, ...]) -> str | None:
    """The long option `name` stands for: itself, or the one option it is a prefix of.
    None when it is ambiguous (the program refuses the command) or unknown."""
    if name in options:
        return name
    candidates = [option for option in options if option.startswith(name)]
    return candidates[0] if len(candidates) == 1 else None


# Options of diff that take a separate value, then neither an operand nor a path.
DIFF_VALUE_LETTERS = "xXIFLUCSWD"
DIFF_VALUE_LONG_OPTIONS = {"--exclude", "--exclude-from", "--ignore-matching-lines", "--label",
                           "--starting-file", "--width", "--ifdef", "--show-function-line"}


def inside_a_git_directory(path: Path) -> bool:
    return SEARCH_SECRET_DIRECTORY in path.parts


def repository_root(cwd: Path) -> Path | None:
    """The nearest directory at or above cwd that holds a `.git`, or None."""
    return next((d for d in (cwd, *cwd.parents) if path_exists(d / ".git")), None)


def git_diff_reads_outside_the_work_tree(operands: list[str], cwd: Path, home: Path) -> bool:
    """Whether `git diff A B` runs as `--no-index` without the flag: two operands, one of
    which names an existing path outside the repository's work tree, or no repository."""
    if len(operands) < 2:
        return False
    root = repository_root(cwd)
    for operand in operands:
        try:
            paths = expand_word(operand, cwd, home)
        except (ValueError, OSError, RuntimeError):
            continue
        if any(path_exists(path) and (root is None or not inside(path, root)) for path in paths):
            return True
    return False


def diff_search(words: list[str], cwd: Path | None = None, home: Path | None = None) -> Search | None:
    """`diff -r A B` and `diff --recursive A B` read every file below A and B, and so
    does `git diff --no-index A B`, which cannot exclude a name, and `git diff A B`
    with a path outside the work tree, which runs as `--no-index`. None for any other
    diff."""
    program = os.path.basename(words[0])
    args = words[1:]
    if program == "git":
        subcommand = None
        skip = False
        for index, arg in enumerate(args):
            if skip:
                skip = False
            elif arg in ("-C", "-c", "--git-dir", "--work-tree", "--namespace"):
                skip = True
            elif not arg.startswith("-"):
                subcommand = index
                break
        if subcommand is None or args[subcommand] != "diff":
            return None
        rest = args[subcommand + 1:]
        operands = [arg for arg in rest if not arg.startswith("-") or arg == "-"]
        if "--" in rest:
            operands = [arg for arg in rest[:rest.index("--")] if not arg.startswith("-")] \
                + rest[rest.index("--") + 1:]
        no_index = any(arg.startswith("--no-i") and "--no-index".startswith(arg) for arg in rest)
        if not no_index and not (cwd is not None and home is not None
                                 and git_diff_reads_outside_the_work_tree(operands, cwd, home)):
            return None
        return Search(operands or ["."], skips_hidden=False, program="git",
                      explicit_starts=bool(operands))
    recursive, filters, positions, operands, i = False, [], set(), [], 0
    while i < len(args):
        first, arg, i = i + 1, args[i], i + 1  # `first` indexes arg in `words`
        if arg == "--":
            operands += args[i:]
            break
        if arg.startswith("--"):
            name, separator, value = arg.partition("=")
            name = resolve_long_option(name, DIFF_LONG_OPTIONS) or name
            if name in DIFF_VALUE_LONG_OPTIONS and not separator:
                value, i = (args[i] if i < len(args) else ""), i + 1
            recursive |= name == "--recursive"
            if name == "--exclude":
                filters.append(NameFilter(True, value))
                positions.update(range(first, i + 1))
        elif arg.startswith("-") and len(arg) > 1:
            for j, letter in enumerate(arg[1:]):
                recursive |= letter in "rR"
                if letter in DIFF_VALUE_LETTERS:
                    value = arg[j + 2:]
                    if not value:
                        value, i = (args[i] if i < len(args) else ""), i + 1
                    if letter == "x":
                        filters.append(NameFilter(True, value))
                        positions.update(range(first, i + 1))
                    break
        else:
            operands.append(arg)
    if not recursive:
        return None
    return Search(operands or ["."], skips_hidden=False, filters=tuple(filters),
                  exclusion_words=frozenset(positions), program="diff",
                  explicit_starts=bool(operands))


def rg_glob_filter(value: str, ignore_case: bool) -> NameFilter | None:
    """An rg glob as a filter on names. `!NAME`, `!**/NAME` and `!NAME/` exclude a
    name wherever it occurs; a glob with another `/` is read by its last part and can
    only include, so that it never counts as an exclusion it may not be."""
    exclude = value.startswith("!")
    pattern = value[1:] if exclude else value
    while pattern.startswith("**/"):
        pattern = pattern[3:]
    applies_to = "both"
    if pattern.endswith("/"):
        pattern, applies_to = pattern.rstrip("/"), "directory"
    if "/" in pattern:
        if exclude:
            return None
        pattern = pattern.rsplit("/", 1)[1]
    return NameFilter(exclude, pattern, applies_to, ignore_case) if pattern else None


def search_starts(words: list[str], cwd: Path | None = None,
                  home: Path | None = None) -> Search | None:
    """Where a recursive search starts (rg, or grep with -r, -R, --recursive or
    -d recurse, or a recursive diff; default `.`), whether it skips hidden files and
    directories, as rg does without --hidden or -uu, and the filters on names it
    carries. None for any other stage. With the stage's directory and the home
    directory, `git diff` of a path outside the work tree counts too."""
    if not words:
        return None
    if os.path.basename(words[0]) in ("diff", "git"):
        return diff_search(words, cwd, home)
    if os.path.basename(words[0]) not in RECURSIVE_SEARCHERS:
        return None
    rg = os.path.basename(words[0]) == "rg"
    if rg and "--files" in words:
        return None  # lists file names, reads no contents
    values = RG_VALUE_OPTIONS if rg else GREP_VALUE_OPTIONS
    recursive, hidden, unrestricted, pattern_given = rg, False, 0, False
    filters: list[NameFilter] = []
    positions: set[int] = set()
    operands, args, i = [], words[1:], 0
    while i < len(args):
        first, arg, i = i + 1, args[i], i + 1  # `first` indexes arg in `words`
        if arg == "--":
            operands += args[i:]
            break
        if arg.startswith("--"):
            name, separator, value = arg.partition("=")
            if not rg:  # grep reads an unambiguous prefix as the full option
                resolved = resolve_long_option(name, GREP_LONG_OPTIONS)
                if resolved is None and "include".startswith(name[2:]) and len(name) > 2:
                    resolved = "--include"
                name = resolved or name
            if name in values and not separator:
                value, i = (args[i] if i < len(args) else ""), i + 1
            pattern_given |= name in ("--regexp", "--file")
            hidden |= name == "--hidden"
            unrestricted += name == "--unrestricted"
            recursive |= name in ("--recursive", "--dereference-recursive") or (
                name == "--directories" and value == "recurse")
            entry = None
            if not rg and name in ("--include", "--exclude", "--exclude-dir"):
                directory = name == "--exclude-dir"
                entry = NameFilter(name != "--include", value.rstrip("/") if directory else value,
                                   "directory" if directory else "file")
            elif rg and name in ("--glob", "--iglob"):
                entry = rg_glob_filter(value, ignore_case=name == "--iglob")
            if entry is not None:
                filters.append(entry)
                positions.update(range(first, i + 1))
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
                    if rg and letter == "g":
                        entry = rg_glob_filter(value, ignore_case=False)
                        if entry is not None:
                            filters.append(entry)
                            positions.update(range(first, i + 1))
                    break
            continue
        operands.append(arg)
    if not recursive:
        return None
    if not pattern_given:
        operands = operands[1:]
    # A ripgrep config file can turn --hidden on for every search.
    configured = bool(os.environ.get("RIPGREP_CONFIG_PATH")) and "--no-config" not in args
    return Search(operands or ["."], rg and not hidden and unrestricted < 2 and not configured,
                  tuple(filters), frozenset(positions), "rg" if rg else "grep",
                  explicit_starts=bool(operands))


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


def recursive_search_denial(stages: list[Stage], home: Path,
                            secret_paths: tuple[str, ...]) -> str | None:
    """Why a recursive search or recursive reader is denied, or None. It is denied when
    it would read a secret area (`~/.ssh`), when it starts at or inside a `.git`
    directory, and when it does not clearly exclude `.env`, `.env.*` and `.git`, which
    hold credentials and remote URLs. No tree is read to find out whether they exist."""
    for stage in stages:
        search = search_starts(stage.words, stage.cwds[-1], home)
        if search is None:
            continue
        for start in stage_paths(stage, home, search.starts):
            reached = secret_below(start, home, search.skips_hidden, secret_paths)
            if reached is not None:
                return (f"a recursive search from {start} would read {reached}, which holds "
                        "keys, credentials or session transcripts. Search a directory that "
                        "does not contain it")
            if inside_a_git_directory(start):
                return (f"a recursive search from {start} starts inside a .git directory, "
                        "which holds .git/config and its remote URLs, and no exclusion "
                        "applies to a start path. Search the work tree and exclude .git")
        if reads_only_stdin_or_files(stage, search, home):
            continue
        missing = uncovered_secrets(search)
        if missing:
            return search_denial(search, missing)
    return None


def reads_only_stdin_or_files(stage: Stage, search: Search, home: Path) -> bool:
    """Whether a search names no tree to walk: rg with no path that reads a pipe or a
    redirect (grep -r with no path walks the working directory instead), or only
    existing regular files."""
    reads_stdin = stage.piped or any(word in ("<", "<<<", HEREDOC_MARKER) for word in stage.raw)
    if not search.explicit_starts:
        return search.program == "rg" and reads_stdin
    return all(path_is_file(start) for start in stage_paths(stage, home, search.starts))


def search_denial(search: Search, missing: list[str]) -> str:
    """Why a recursive search is denied, and the flags that let it through."""
    if search.program == "git":
        return ("`git diff --no-index`, and `git diff` of a path outside the work tree, reads "
                "every file below its paths, including .env files and .git/config, which hold "
                "credentials, and cannot exclude any. Use `diff -r -x .env -x '.env.*' -x .git` "
                "instead")
    flags = {
        "rg": "-g '!.env' -g '!.env.*' -g '!.git' (after any -g that matches them)",
        "diff": "-x .env -x '.env.*' -x .git",
    }.get(search.program, "--exclude=.env --exclude='.env.*' --exclude-dir=.git (after any "
                          "--include that matches them; spell the options in full)")
    return (f"a recursive {search.program} would read {', '.join(missing)}, which hold "
            f"credentials or remote URLs. Rerun it with {flags}")


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


def is_git_directory(path: Path) -> bool:
    """True when path is itself a git directory, recognised the way git does, by the
    contents it reads to find one: a `HEAD` file, beside either an `objects/` and a `refs/`
    directory or a `commondir` file (a linked worktree's git directory, whose objects and
    refs live in the directory `commondir` names). This covers `.git`, a bare repository, a
    submodule's git directory, a worktree git directory and a GIT_DIR laid out by hand under
    any name. git reads such a directory's `config` and runs the programs it names
    (core.fsmonitor, diff textconv). An ordinary work tree is not one: it holds a `.git`
    entry rather than these."""
    try:
        if not path_is_file(path / "HEAD"):
            return False
        return (((path_is_dir(path / "objects") and path_is_dir(path / "refs"))
                or path_is_file(path / "commondir")))
    except OSError:
        return False


def git_settings_match(path: Path, home: Path) -> Path | None:
    """The git settings file that path is, or shares a file with, or None. git runs the
    programs these files name (core.fsmonitor, diff drivers' textconv). They are
    ~/.gitconfig and ~/.config/git/config, which git reads on every run, and a `config`
    under a `.git` directory (a repository's, or a submodule's .git/modules/<name>/config)
    or directly inside any directory that is a git directory by content (see
    is_git_directory, which covers a git directory under a name other than .git), which git
    reads when it runs in that repository. A name matches in any letter case.
    A path shares a file with a settings file when it is a symbolic or hard link to it,
    checked with os.path.samefile against those files and the .git/config files above
    path. Not seen: a hard link to a settings file of a repository that does not contain
    path (a sibling, or one elsewhere under home), since only the files above path are
    checked; `cp -l` and `cp --link` make such a link only after the classifier, and the
    file tools then allow writes through it. Also not seen: the file a .git/config in a
    repository below path links to."""
    home_settings = (home / ".gitconfig", home / ".config" / "git" / "config")
    lowered = str(path).lower()
    for setting in home_settings:
        if lowered == str(setting).lower():
            return setting
    if path.name.lower() == "config" and (
            any(p.lower() == ".git" for p in path.parts[:-1])
            or is_git_directory(path.parent)):
        return path
    if not path_is_file(path):
        return None
    for setting in (*home_settings, *repository_settings(path)):
        try:
            if path_is_file(setting) and os.path.samefile(path, setting):
                return setting
        except OSError:
            continue
    return None


def repository_settings(path: Path) -> list[Path]:
    """The `.git/config` and submodule `.git/modules/*/config` files of the directories
    above path."""
    settings: list[Path] = []
    for directory in path.parents:
        git_dir = directory / ".git"
        if path_is_dir(git_dir):
            settings.append(git_dir / "config")
            settings.extend(submodule_settings(git_dir / "modules"))
    return settings


def submodule_settings(modules: Path) -> list[Path]:
    """The `config` of each submodule git directory under `modules`, nested submodules
    included. Only the module directories are listed, never their objects."""
    try:
        entries = [entry for entry in modules.iterdir() if path_is_dir(entry)]
    except OSError:
        return []
    settings: list[Path] = []
    for module in entries:
        settings.append(module / "config")
        settings.extend(submodule_settings(module / "modules"))
    return settings


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


# How GNU sed reads a script, for sed_commands: the blanks and `;` between
# commands, a line or step address (`3`, `$`, `1~2`), the `+N`/`~N` end of a range,
# an `s` flag list, and the characters that may follow a command.
SED_GAP = re.compile(r"[\s;]*")
SED_BLANKS = re.compile(r"[ \t]*")
SED_LINE_ADDRESS = re.compile(r"\d+(?:~\d+)?|\$")
SED_RANGE_OFFSET = re.compile(r"[+~]?\d+")
SED_FLAGS = re.compile(r"[0-9gpiImMe]*")
SED_COMMAND_END = ";\n}#"


def sed_bracket_end(script: str, i: int) -> int | None:
    """The index after the bracket expression that opens at script[i] (`[`), read as
    GNU sed reads it: a `]` right after `[` or `[^` is a member, `[:class:]`, `[=c=]`
    and `[.c.]` are members, and a backslash is an ordinary member. None when no `]`
    closes it."""
    j = i + 1
    if script.startswith("^", j):
        j += 1
    if script.startswith("]", j):
        j += 1
    while j < len(script):
        if script[j] == "[" and script[j + 1:j + 2] in (":", "=", "."):
            close = script.find(script[j + 1] + "]", j + 2)
            if close < 0:
                return None
            j = close + 2
        elif script[j] == "]":
            return j + 1
        else:
            j += 1
    return None


def sed_delimited_end(script: str, i: int, delimiter: str, brackets: bool) -> int | None:
    """The index of the delimiter that ends the regex (brackets=True) or replacement
    text starting at script[i]: a backslash escapes the next character, and in a
    regex a bracket expression may hold the delimiter. None when an unescaped newline
    or the end of the script comes first."""
    while i < len(script):
        character = script[i]
        if character == "\\":
            i += 2
        elif character == delimiter:
            return i
        elif character == "\n":
            return None
        elif character == "[" and brackets:
            end = sed_bracket_end(script, i)
            if end is None:
                return None
            i = end
        else:
            i += 1
    return None


def sed_address_end(script: str, i: int) -> int | None:
    """The index after the address at script[i] (`3`, `$`, `1~2`, `/re/`, `\\%re%`,
    a regex followed by I or M), or i itself when none starts there. None when a
    regex address is not closed."""
    line = SED_LINE_ADDRESS.match(script, i)
    if line:
        return line.end()
    if script.startswith("/", i):
        delimiter, start = "/", i + 1
    elif script.startswith("\\", i) and i + 1 < len(script) and script[i + 1] != "\n":
        delimiter, start = script[i + 1], i + 2
    else:
        return i
    end = sed_delimited_end(script, start, delimiter, brackets=True)
    return None if end is None else re.compile(r"[IM]*").match(script, end + 1).end()


def sed_line_end(script: str, i: int) -> int:
    end = script.find("\n", i)
    return len(script) if end < 0 else end


def sed_commands(script: str) -> list[tuple[str, str]] | None:
    """The commands of a sed script, read left to right as GNU sed reads them, each
    as `(letter, argument)`: the file of r, R, w and W, the command of e, the flags
    of s (an `s///w FILE` adds a `("w", FILE)`), the text of a, i and c, and "" for
    the rest. None when the script does not parse, which GNU sed refuses to run."""
    commands: list[tuple[str, str]] = []
    i = 0
    while True:
        i = SED_GAP.match(script, i).end()
        if i >= len(script):
            return commands
        end = sed_address_end(script, i)
        if end is None:
            return None
        if end > i:
            i = SED_BLANKS.match(script, end).end()
            if script.startswith(",", i):
                i = SED_BLANKS.match(script, i + 1).end()
                offset = SED_RANGE_OFFSET.match(script, i)
                end = offset.end() if offset else sed_address_end(script, i)
                if end is None or end == i:
                    return None
                i = end
        i = re.compile(r"[\s!]*").match(script, i).end()
        if i >= len(script):
            return None
        command = script[i]
        if command in "{}":
            commands.append((command, ""))
            i += 1
            continue
        if command in "#rRwWe":   # a comment, a file name or a command: the rest of the line,
            # past its leading blanks
            end = sed_line_end(script, i)
            commands.append((command, script[i + 1:end].lstrip(" \t")))
            i = end
            continue
        if command in "aic":   # text up to a newline no odd run of backslashes escapes
            end = sed_line_end(script, i)
            while end < len(script) and (len(script[:end]) - len(script[:end].rstrip("\\"))) % 2:
                end = sed_line_end(script, end + 1)
            commands.append((command, script[i + 1:end]))
            i = end
            continue
        if command in ":btT":   # a label ends at a blank or `;`, and a command may follow it
            commands.append((command, ""))
            i = re.compile(r"[ \t]*[^\s;]*").match(script, i + 1).end()
            continue
        if command in "sy":
            delimiter = script[i + 1:i + 2]
            if delimiter in ("", "\n", "\\"):
                return None
            middle = sed_delimited_end(script, i + 2, delimiter, brackets=command == "s")
            last = None if middle is None else sed_delimited_end(script, middle + 1, delimiter,
                                                                  brackets=False)
            if last is None:
                return None
            i = last + 1
            if command == "s":
                flags_end = SED_FLAGS.match(script, i).end()
                commands.append(("s", script[i:flags_end]))
                i = flags_end
                if script.startswith("w", i):
                    end = sed_line_end(script, i)
                    commands.append(("w", script[i + 1:end].lstrip(" \t")))
                    i = end
                    continue
            else:
                commands.append(("y", ""))
        elif command in SED_PRINTING_COMMANDS:
            commands.append((command, ""))
            i += 1
            if command in "lqQ":
                i = re.compile(r"[ \t]*\d*").match(script, i).end()
        elif command == "v":
            commands.append((command, ""))
            i = re.compile(r"[ \t]*[\d.]*").match(script, i + 1).end()
        else:
            return None
        i = SED_BLANKS.match(script, i).end()
        if i < len(script) and script[i] not in SED_COMMAND_END:
            return None


def sed_script_targets(script: str) -> list[str] | None:
    """The files a sed script writes: the file of each `w`/`W` command and `s///w`
    flag. None when the script does not parse as sed_commands reads it."""
    commands = sed_commands(script)
    return None if commands is None else [file for letter, file in commands
                                          if letter in "wW" and file]


def sed_targets(args: list[str]) -> list[str] | None:
    """The files sed writes besides standard output: the `w` targets of its
    scripts (sed_scripts). None when it rewrites its input files (-i), runs a
    script file the hook cannot see (-f), has an option not in SED_OPTIONS or a
    script that does not parse: then every operand may be written."""
    parsed = read_options(args, SED_OPTIONS)
    if parsed is None or any(name in SED_EDITS_FILES for name, _ in parsed[0]):
        return None
    targets = [sed_script_targets(script) for script in sed_scripts(args) or []]
    if any(found is None for found in targets):
        return None
    return [target for found in targets for target in found or []]


def sed_files(args: list[str]) -> list[str]:
    """sed's input files: its operands after the script, which is the first
    operand unless -e, --expression, -f or --file gives it. Every word that is no
    option when an option is not in SED_OPTIONS."""
    parsed = read_options(args, SED_OPTIONS)
    if parsed is None:
        return [arg for arg in args if not arg.startswith("-")]
    options, operands = parsed
    script_given = any(name in ("-e", "--expression", "-f", "--file") for name, _ in options)
    return operands if script_given else operands[1:]


# --- Reader programs: which of their options and script commands only read and print.
# Each option check is a positive list: an option not on it makes the program a
# possible writer or runner, which the classifier then judges. The awk and jq program
# checks are the exception: they refuse the names and characters that run, write or
# reach the environment (AWK_RUNS_OR_REACHES, JQ_REACHES).


@dataclass(frozen=True)
class OptionSpec:
    """A program's options as getopt reads them. Short letters stand alone
    (`short_flags`), take a value attached or in the next word (`short_valued`), or
    take one only attached (`short_optional`, like sed's `-i[SUFFIX]`). Each long
    name takes `long[name]` values, 0, 1 or 2, in the words after it or one after
    `=`; a name in `long_optional` takes a value only after `=`."""
    short_flags: str
    short_valued: str
    long: dict[str, int]
    short_optional: str = ""
    long_optional: frozenset[str] = frozenset()


def long_option(word: str, names: Any) -> str | None:
    """The long option `word` (`--name` or `--name=value`) names, as getopt_long
    resolves it: the exact name, or the one name it is a prefix of. None when it is
    unknown or ambiguous, which the program refuses."""
    name = word.partition("=")[0]
    if name in names:
        return name
    matches = [candidate for candidate in names if candidate.startswith(name)]
    return matches[0] if len(matches) == 1 else None


def read_options(args: list[str], spec: OptionSpec
                 ) -> tuple[list[tuple[str, str | None]], list[str]] | None:
    """`(options, operands)` of a program's arguments: each option as `(name, value)`
    (`-k`, `--key`; value None for a flag), read in any order before `--`, as GNU
    getopt permutes them. None when a word is an option not in `spec`, or lacks its
    value: the hook cannot tell what the program then does."""
    options: list[tuple[str, str | None]] = []
    operands: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            operands += args[i:]
            break
        if arg.startswith("--"):
            name = long_option(arg, spec.long.keys() | spec.long_optional)
            if name is None:
                return None
            if "=" in arg:
                if spec.long.get(name, 1) != 1:
                    return None
                options.append((name, arg.partition("=")[2]))
                continue
            count = spec.long.get(name, 0)
            if i + count > len(args):
                return None
            options.append((name, " ".join(args[i:i + count]) if count else None))
            i += count
        elif arg.startswith("-") and len(arg) > 1:
            for position, letter in enumerate(arg[1:], start=2):
                rest = arg[position:]
                if letter in spec.short_optional:
                    options.append(("-" + letter, rest or None))
                    break
                if letter in spec.short_valued:
                    if not rest:
                        if i >= len(args):
                            return None
                        rest, i = args[i], i + 1
                    options.append(("-" + letter, rest))
                    break
                if letter not in spec.short_flags:
                    return None
                options.append(("-" + letter, None))
        else:
            operands.append(arg)
    return options, operands


# GNU sed's options; -i, --in-place, -f and --file are not read-only.
SED_OPTIONS = OptionSpec(
    short_flags="nErsuz", short_valued="efl", short_optional="i",
    long={"--quiet": 0, "--silent": 0, "--debug": 0, "--expression": 1, "--file": 1,
          "--follow-symlinks": 0, "--line-length": 1, "--null-data": 0, "--zero-terminated": 0,
          "--posix": 0, "--regexp-extended": 0, "--sandbox": 0, "--separate": 0,
          "--unbuffered": 0, "--binary": 0, "--help": 0, "--version": 0},
    long_optional=frozenset({"--in-place"}))
SED_EDITS_FILES = {"-i", "--in-place", "-f", "--file"}
# sed commands that only print or edit the pattern and hold spaces; l, q and Q take
# an optional number. Not here: e (runs a command), r and R (read a file), w and W
# (write one).
SED_PRINTING_COMMANDS = set("dDFgGhHlnNpPqQxz=")
# Commands that print or edit too, and the flags of a read-only `s///`: no e (runs
# the pattern space) and no w (writes).
SED_EDITING_COMMANDS = set("{}#aic:btTyv")
SED_PRINTING_FLAGS = set("0123456789gpiImM")


def sed_script_reads_only(script: str) -> bool:
    """True when every command of the sed script, as sed_commands reads it, only
    prints or edits its input: one of SED_PRINTING_COMMANDS or SED_EDITING_COMMANDS,
    or `s` with flags of SED_PRINTING_FLAGS."""
    commands = sed_commands(script)
    return commands is not None and all(
        letter in SED_PRINTING_COMMANDS or letter in SED_EDITING_COMMANDS
        or letter == "s" and set(argument) <= SED_PRINTING_FLAGS
        for letter, argument in commands)


def sed_scripts(args: list[str]) -> list[str] | None:
    """sed's scripts: its -e and --expression values, or else its first operand.
    None when an option is not in SED_OPTIONS or a script file (-f) gives it."""
    parsed = read_options(args, SED_OPTIONS)
    if parsed is None:
        return None
    options, operands = parsed
    if any(name in ("-f", "--file") for name, _ in options):
        return None
    return [value or "" for name, value in options if name in ("-e", "--expression")] \
        or operands[:1]


def sed_read_files(args: list[str]) -> list[str]:
    """The files sed's `r` and `R` commands read, which its operands do not name."""
    return [file for script in sed_scripts(args) or []
            for letter, file in sed_commands(script) or [] if letter in "rR" and file]


def sed_reads_only(args: list[str]) -> bool:
    """True when sed only prints: every option is in SED_OPTIONS but -i and -f,
    and every command of its scripts (sed_scripts) passes sed_script_reads_only."""
    parsed = read_options(args, SED_OPTIONS)
    if parsed is None or any(name in SED_EDITS_FILES for name, _ in parsed[0]):
        return False
    scripts = sed_scripts(args)
    return bool(scripts) and all(sed_script_reads_only(script) for script in scripts)


# file's options. -C and --compile write X.mgc for each magic file X, -p and
# --preserve-date reset the files' access times, and -f and --files-from read
# every file a list names.
FILE_OPTIONS = OptionSpec(
    short_flags="vzZbcCikLlhnN0prsSd", short_valued="meFPf",
    long={"--help": 0, "--version": 0, "--magic-file": 1, "--uncompress": 0,
          "--uncompress-noreport": 0, "--brief": 0, "--checking-printout": 0, "--exclude": 1,
          "--exclude-quiet": 1, "--files-from": 1, "--separator": 1, "--mime": 0, "--apple": 0,
          "--extension": 0, "--mime-type": 0, "--mime-encoding": 0, "--keep-going": 0,
          "--list": 0, "--dereference": 0, "--no-dereference": 0, "--no-buffer": 0,
          "--no-pad": 0, "--print0": 0, "--preserve-date": 0, "--parameter": 1, "--raw": 0,
          "--special-files": 0, "--compile": 0, "--debug": 0})
FILE_WRITES_OR_LISTS = {"-C", "--compile", "-p", "--preserve-date", "-f", "--files-from"}


def file_reads_only(args: list[str]) -> bool:
    """True when every option of file is in FILE_OPTIONS and none is in FILE_WRITES_OR_LISTS."""
    parsed = read_options(args, FILE_OPTIONS)
    return parsed is not None and not any(name in FILE_WRITES_OR_LISTS for name, _ in parsed[0])


# The options of POSIX awk and gawk's long spellings of them: a field separator and
# variable assignments. Any other option (-f, -e, --source, -i, -l, -W, ...) may
# load or run code the hook cannot see.
AWK_OPTIONS = OptionSpec(short_flags="", short_valued="Fv",
                         long={"--field-separator": 1, "--assign": 1})
AWK_PROGRAMS = {"awk", "gawk", "mawk", "nawk"}
# What an awk program uses to run a command, read a file or variable no word names,
# or write: system, getline, the environment (ENVIRON, or SYMTAB that reaches it),
# ARGV and ARGC (the files it reads next), @ (gawk's @load, @include and indirect
# calls), and the redirect |.
AWK_RUNS_OR_REACHES = re.compile(
    r"\b(?:system|getline|ENVIRON|SYMTAB|FUNCTAB|ARGV|ARGC)\b|[@|]")
# `>` writes a file only in a print or printf statement; elsewhere it compares.
AWK_PRINTS = re.compile(r"\bprintf?\b")


def awk_reads_only(args: list[str]) -> bool:
    """True when awk's options are all in AWK_OPTIONS and its program (the first
    operand) uses nothing of AWK_RUNS_OR_REACHES, nor `>` beside print or printf."""
    parsed = read_options(args, AWK_OPTIONS)
    if parsed is None or not parsed[1]:
        return False
    program = parsed[1][0]
    return not (AWK_RUNS_OR_REACHES.search(program)
                or ">" in program and AWK_PRINTS.search(program))


# GNU sort's options. -o and --output write a file, -T and --temporary-directory
# write files into a directory, --compress-program runs a program, and
# --files0-from reads every file a list names.
SORT_OPTIONS = OptionSpec(
    short_flags="bcCdfghiMmnRrsuVz", short_valued="koStT",
    long={"--ignore-leading-blanks": 0, "--dictionary-order": 0, "--ignore-case": 0,
          "--general-numeric-sort": 0, "--ignore-nonprinting": 0, "--month-sort": 0,
          "--human-numeric-sort": 0, "--numeric-sort": 0, "--random-sort": 0,
          "--random-source": 1, "--reverse": 0, "--sort": 1, "--version-sort": 0,
          "--batch-size": 1, "--compress-program": 1, "--debug": 0, "--files0-from": 1,
          "--key": 1, "--merge": 0, "--output": 1, "--stable": 0, "--buffer-size": 1,
          "--field-separator": 1, "--temporary-directory": 1, "--parallel": 1,
          "--unique": 0, "--zero-terminated": 0, "--help": 0, "--version": 0},
    long_optional=frozenset({"--check"}))
SORT_WRITES_OR_RUNS = {"-o", "--output", "-T", "--temporary-directory", "--compress-program",
                       "--files0-from"}


def sort_outputs(args: list[str]) -> list[str] | None:
    """The files sort's -o and --output name, also inside a cluster (`-ro FILE`).
    None when an option is not in SORT_OPTIONS."""
    parsed = read_options(args, SORT_OPTIONS)
    if parsed is None:
        return None
    return [value for name, value in parsed[0] if name in ("-o", "--output") and value]


def sort_reads_only(args: list[str]) -> bool:
    """True when every option of sort is in SORT_OPTIONS and none is in SORT_WRITES_OR_RUNS."""
    parsed = read_options(args, SORT_OPTIONS)
    return parsed is not None and not any(name in SORT_WRITES_OR_RUNS for name, _ in parsed[0])


# GNU uniq's options. Its second operand is the file it writes.
UNIQ_OPTIONS = OptionSpec(
    short_flags="cdDiuz", short_valued="fsw",
    long={"--count": 0, "--repeated": 0, "--skip-fields": 1, "--ignore-case": 0,
          "--skip-chars": 1, "--unique": 0, "--zero-terminated": 0, "--check-chars": 1,
          "--help": 0, "--version": 0},
    long_optional=frozenset({"--all-repeated", "--group"}))


def uniq_outputs(args: list[str]) -> list[str] | None:
    """The file uniq writes, its second operand. None when an option is not in UNIQ_OPTIONS."""
    parsed = read_options(args, UNIQ_OPTIONS)
    return None if parsed is None else parsed[1][1:2]


# tree's short options that take the next unused word as their value; tree reads a
# cluster letter by letter, so `-ao FILE` and `-Po PATTERN FILE` write FILE.
TREE_VALUED = "LPIHTo"
# What tree's -R writes into every directory at the -L depth limit.
TREE_RERUN_OUTPUT = "00Tree.html"


def tree_outputs(args: list[str]) -> list[str]:
    """The files tree's -o letters name, each the next word no earlier letter took,
    and TREE_RERUN_OUTPUT for -R. A value attached to `o` is the output instead, for
    a tree that reads `-oFILE` as getopt does (tree 2.3.1 refuses it)."""
    outputs, taken = [], set()
    for index, arg in enumerate(args):
        if index in taken or not arg.startswith("-") or arg.startswith("--"):
            continue
        following = index + 1
        for position, letter in enumerate(arg[1:], start=2):
            if letter == "o" and arg[position:]:
                outputs.append(arg[position:])
                break
            if letter in TREE_VALUED:
                while following in taken:
                    following += 1
                taken.add(following)
                if letter == "o":
                    outputs.append(args[following] if following < len(args) else "")
                following += 1
            elif letter == "R":
                outputs.append(TREE_RERUN_OUTPUT)
    return outputs


# jq's options. -f and --from-file load the program from a file, and -L and
# --library-path load modules, which the hook cannot see.
JQ_OPTIONS = OptionSpec(
    short_flags="nRscrjaSCMeVh", short_valued="L",
    long={"--null-input": 0, "--raw-input": 0, "--slurp": 0, "--compact-output": 0,
          "--raw-output": 0, "--raw-output0": 0, "--join-output": 0, "--ascii-output": 0,
          "--sort-keys": 0, "--color-output": 0, "--monochrome-output": 0, "--tab": 0,
          "--indent": 1, "--unbuffered": 0, "--stream": 0, "--stream-errors": 0, "--seq": 0,
          "--from-file": 0, "--library-path": 1, "--arg": 2, "--argjson": 2,
          "--slurpfile": 2, "--rawfile": 2, "--args": 0, "--jsonargs": 0,
          "--exit-status": 0, "--version": 0, "--build-configuration": 0, "--help": 0})
JQ_LOADS_CODE = {"-f", "--from-file", "-L", "--library-path"}
# What a jq program reads the environment or other files with: `env`, `$ENV`, and
# the module directives import and include. A key `.env` is no such use.
JQ_REACHES = re.compile(r"\$ENV\b|(?<![.\w$])env\b|\b(?:import|include)\b")


def jq_reads_only(args: list[str]) -> bool:
    """True when jq's options are all in JQ_OPTIONS but those of JQ_LOADS_CODE, and
    its program (the first operand) uses nothing of JQ_REACHES."""
    parsed = read_options(args, JQ_OPTIONS)
    if parsed is None or not parsed[1]:
        return False
    options, operands = parsed
    return (not any(name in JQ_LOADS_CODE for name, _ in options)
            and not JQ_REACHES.search(operands[0]))


# procps ps options that take the next word as their value, in UNIX (-p), BSD (p)
# and long (--pid) spelling.
PS_VALUED = {"-C", "-G", "--Group", "-g", "--group", "-p", "p", "--pid", "--ppid", "-q", "q",
             "--quick-pid", "-s", "--sid", "-t", "t", "--tty", "-u", "U", "--user", "-U",
             "--User", "-D", "-O", "O", "-o", "o", "--format", "k", "--sort", "--cols",
             "--columns", "--width", "--rows", "--lines", "--help"}


def prints_environment(words: list[str]) -> bool:
    """True for ps with the BSD `e` option (`ps e`, `ps auxe`, `ps -ef e`), which
    prints each process's environment, API keys included. `-e` (every process) is
    another option."""
    if not words or os.path.basename(words[0]) != "ps":
        return False
    takes_value = False
    for word in words[1:]:
        if takes_value:
            takes_value = False
            continue
        if not word.startswith("-") and re.fullmatch(r"[A-Za-z]+", word) and "e" in word:
            return True
        takes_value = word in PS_VALUED or (
            not word.startswith("-") and word[-1:] in "pqtUOok" and word.isalpha())
    return False


# procps-ng ps does not read its words as getopt does. A word's first characters set
# how it is read: `--name` is a long option (exact names only), `-xyz` UNIX letters,
# a word that starts with a letter BSD letters, and one that starts with a digit
# begins the list of pids that ends the command. A letter that takes a value ends
# its word; the value is the rest of the word, or else the next word. After any
# error, ps rereads every word as BSD letters, where `e` prints each process's
# environment: `ps -efx` (x is no UNIX letter) and `ps -ueve` (no user `eve`) print it.
PS_UNIX_FLAGS = set("AadefFHjlLMNTwycZ")
PS_UNIX_VALUED = set("CGgoOpqstuU")
PS_BSD_FLAGS = set("AaCcfgHhjlMmnrSsTuvwXxZ")  # BSD's letters but e (the environment)
PS_BSD_VALUED = set("kOopqtU")
# Letters whose value BSD letters read the same way, so a reread keeps it a value.
PS_VALUED_IN_BOTH = set("oOpqtU")
PS_LONG_FLAGS = {"cumulative", "deselect", "forest", "header", "headers", "heading",
                 "headings", "no-header", "no-headers", "no-heading", "no-headings",
                 "noheader", "noheaders", "noheading", "noheadings", "context", "signames"}
PS_LONG_VALUED = {"Group", "User", "cols", "columns", "width", "date-format", "format",
                  "group", "pid", "ppid", "quick-pid", "rows", "lines", "sid", "sort",
                  "tty", "user"}
# A ps command with `e` among its UNIX letters is fast-allowed only when every word
# is one ps reads without error in both passes: these letters, values of this form,
# pids. Its words then never get reread.
PS_STRICT_UNIX_FLAGS = set("AadefFjlwy")
PS_STRICT_VALUE = {
    "o": re.compile(r"[a-z_]+(?:,[a-z_]+)*"), "O": re.compile(r"[a-z_]+(?:,[a-z_]+)*"),
    "p": re.compile(r"\d+(?:,\d+)*"), "q": re.compile(r"\d+(?:,\d+)*"),
    "format": re.compile(r"[a-z_]+(?:,[a-z_]+)*"), "pid": re.compile(r"\d+(?:,\d+)*"),
    "ppid": re.compile(r"\d+(?:,\d+)*"), "sort": re.compile(r"[+-]?[a-z_]+(?:,[+-]?[a-z_]+)*"),
}
PS_STRICT_LONG_FLAGS = {"forest", "headers", "no-headers", "cumulative"}
# Format names that hold the environment (procps-ng 4.0.4 prints nothing for them).
PS_ENVIRONMENT_FORMATS = re.compile(r"(?:^|[,\s])(?:environ|env)(?:[=:,\s]|$)")
PS_FORMAT_LETTERS = set("oO")
PS_FORMAT_LONG = {"format"}


def ps_reads_only(args: list[str]) -> bool:
    """True when ps prints no environment however it reads its words: each word is
    an option of the lists above or a pid, no BSD word has an `e`, no format names
    the environment, and an `e` among UNIX letters (or in a value a reread would
    take for letters) comes only with PS_STRICT words."""
    strict, has_e = True, False
    i = 0
    while i < len(args):
        word = args[i]
        i += 1
        if word.startswith("--"):
            name, separator, value = word[2:].partition("=")
            if name in PS_LONG_FLAGS and not separator:
                strict &= name in PS_STRICT_LONG_FLAGS
                continue
            if name not in PS_LONG_VALUED:
                return False
            if not separator:
                if i >= len(args):
                    return False
                value, i = args[i], i + 1
            if name in PS_FORMAT_LONG and PS_ENVIRONMENT_FORMATS.search(value):
                return False
            strict &= bool(name in PS_STRICT_VALUE and PS_STRICT_VALUE[name].fullmatch(value))
            continue
        if re.fullmatch(r"\d+(?:,\d+)*", word):
            return all(re.fullmatch(r"[-+]?\d+(?:,\d+)*", rest) for rest in args[i:]) and (
                strict or not has_e)
        unix = word.startswith("-")
        letters = word[1:] if unix else word
        if not letters or not letters[0].isalpha():
            return False
        flags, valued = (PS_UNIX_FLAGS, PS_UNIX_VALUED) if unix else (PS_BSD_FLAGS, PS_BSD_VALUED)
        for position, letter in enumerate(letters):
            if letter in valued:
                value = letters[position + 1:]
                glued = bool(value)
                if not glued:
                    if i >= len(args) or not args[i]:
                        return False
                    value, i = args[i], i + 1
                if letter in PS_FORMAT_LETTERS and PS_ENVIRONMENT_FORMATS.search(value):
                    return False
                if unix:
                    strict &= bool(letter in PS_STRICT_VALUE
                                   and PS_STRICT_VALUE[letter].fullmatch(value))
                    if letter not in PS_VALUED_IN_BOTH and (glued or value.startswith("-")):
                        has_e |= "e" in value  # a reread takes it for letters
                break
            if not unix and letter.isdigit():  # pids glued to BSD letters: `p1` is `p 1`
                if not re.fullmatch(r"\d+(?:,\d+)*", letters[position:]):
                    return False
                break
            if letter not in flags:
                return False
            if unix:
                strict &= letter in PS_STRICT_UNIX_FLAGS
                has_e |= letter == "e"
            else:
                strict = False
    return strict or not has_e


# less and more options that only change how a file is shown. Others load a lesskey
# file or text, which can set LESSOPEN to a command less runs (-k, --lesskey-src,
# --lesskey-content), write a log (-o, -O, --log-file), or take a value the hook does
# not check. Long names must be exact: less resolves a prefix among its own names.
PAGER_FLAGS = set("aABcdeEfFgGiIJKLmMnNqQrRsSuUVwWX~")
PAGER_NUMBER_LETTERS = set("bhjxyz#")  # each with digits attached: -x4, -j10
PAGER_LONG_FLAGS = {
    "search-skip-screen", "SEARCH-SKIP-SCREEN", "auto-buffers", "clear-screen", "dumb",
    "quit-at-eof", "QUIT-AT-EOF", "force", "quit-if-one-screen", "hilite-search",
    "HILITE-SEARCH", "ignore-case", "IGNORE-CASE", "status-column", "quit-on-intr",
    "no-lessopen", "long-prompt", "LONG-PROMPT", "line-numbers", "LINE-NUMBERS", "quiet",
    "QUIET", "silent", "SILENT", "raw-control-chars", "RAW-CONTROL-CHARS",
    "squeeze-blank-lines", "chop-long-lines", "underline-special", "UNDERLINE-SPECIAL",
    "version", "hilite-unread", "HILITE-UNREAD", "no-init", "tilde", "help", "mouse",
    "no-keypad", "no-histdups", "incsearch", "use-color", "wordwrap", "status-line",
    "redraw-on-quit", "file-size", "follow-name", "no-vbell",
    # util-linux more
    "logical", "no-pause", "print-over", "clean-print", "exit-on-eof", "squeeze", "plain",
}
PAGER_LONG_NUMBERS = {"buffers", "max-back-scroll", "jump-target", "tabs", "max-forw-scroll",
                      "window", "shift", "lines", "line-num-width"}
# Initial commands: a line number, the end (G) or follow (F), or more's `+/pattern`.
PAGER_INITIAL_COMMAND = re.compile(r"\+(?:\d+|G|F|/[ -~]*)")


def pager_reads_only(args: list[str]) -> bool:
    """True when every option of less or more is in the lists above; after `--`
    every word is a file."""
    for index, word in enumerate(args):
        if word == "--":
            return True
        if word.startswith("--"):
            name, separator, value = word[2:].partition("=")
            if not (name in PAGER_LONG_FLAGS and not separator
                    or name in PAGER_LONG_NUMBERS and re.fullmatch(r"\d+(?:[.,]\d+)*", value)):
                return False
        elif word.startswith("+"):
            if not PAGER_INITIAL_COMMAND.fullmatch(word):
                return False
        elif word.startswith("-") and len(word) > 1:
            letters = word[1:]
            if letters.isdigit():  # more -10: lines per screen
                continue
            for position, letter in enumerate(letters):
                if letter in PAGER_NUMBER_LETTERS:
                    if not re.fullmatch(r"\d+(?:[.,]\d+)*", letters[position + 1:]):
                        return False
                    break
                if letter not in PAGER_FLAGS:
                    return False
    return True


def program_writes(words: list[str]) -> bool:
    """True unless the stage's program only reads the files it names; redirects
    are judged separately, by their targets."""
    if not words:
        return False
    program, args = os.path.basename(words[0]), words[1:]
    if program not in READ_ONLY_PROGRAMS:
        return True
    if program == "sed":
        return not sed_reads_only(args)
    if program == "sort":
        return not sort_reads_only(args)
    if program == "uniq":
        return uniq_outputs(args) != []
    if program == "file":
        return not file_reads_only(args)
    if program == "find":
        return find_writes(args)
    if program == "tree":
        return bool(tree_outputs(args))
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
    it reads: a copy's destination, the -o file of sort and tree, uniq's second
    operand, sed's `w` files (or its input files with -i or -f), a creating
    archiver's archive. Every operand otherwise; redirects never."""
    program, args = os.path.basename(words[0]), words[1:]
    if program in COPIERS:
        return copy_destination(program, args)
    if program == "sort":
        outputs = sort_outputs(args)
        return operand_words(words) if outputs is None else outputs
    if program == "uniq":
        outputs = uniq_outputs(args)
        return operand_words(words) if outputs is None else outputs
    if program == "tree":
        return tree_outputs(args)
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
    "run or allow. Change it with the edit tool if the edit tool allows that change, or "
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
    code, i, n = [], 1, len(words)
    while i < n:
        arg = words[i]
        if arg == "-":
            return [*code, *words[i + 1:]]
        if arg in ("-m", "--"):
            return code
        if arg.startswith(("--eval=", "--print=")):
            code.append(arg.split("=", 1)[1])
        elif (arg in ("--eval", "--print") or re.fullmatch(r"-[A-Za-z]*[cep]", arg)) and i + 1 < n:
            code.append(words[i + 1])
            i += 2
            continue
        elif not arg.startswith("-") and not code:
            return []
        i += 1
    return code


LINK_CONTROL = (
    "this command makes a hard link to {control}, which decides what the harnesses, git or "
    "the guard run or allow, and a write through the link would change it. Use a symbolic "
    "link (`ln -s`), or leave it to the user"
)


def ln_command(words: list[str]) -> tuple[bool, list[str]]:
    """Whether an `ln` command makes symbolic links, and the words that may name the
    files it touches: its operands and the `-t`/`--target-directory` directory. The value
    of `-S` and `--suffix` is read as a value, so a `-s` after `-S` is a suffix, not the
    symbolic-link flag."""
    symbolic = False
    names: list[str] = []
    rest = iter(words[1:])
    for word in rest:
        if word == "--":
            names.extend(rest)
            break
        if word.startswith("--"):
            option, equals, value = word.partition("=")
            if option == "--symbolic":
                symbolic = True
            elif option in ("--suffix", "--target-directory"):
                if not equals:
                    value = next(rest, "")
                if option == "--target-directory":
                    names.append(value)
            continue
        if word.startswith("-") and len(word) > 1:
            for index, letter in enumerate(word[1:], start=1):
                if letter == "s":
                    symbolic = True
                elif letter in "St":
                    value = word[index + 1:] or next(rest, "")
                    if letter == "t":
                        names.append(value)
                    break
            continue
        names.append(word)
    return symbolic, names


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


def git_directory_above(start: Path) -> Path | None:
    """The git directory git would discover for a command whose working directory is
    `start`, when that git directory is reached by content rather than through a `.git`
    entry. git walks up from `start`; at each level it takes the directory as the git
    directory when it is one by content (is_git_directory), else follows a `.git` entry
    when present. So the walk stops at the first directory that is a git directory by
    content (returned: the fast path must refuse) or that holds a `.git` entry (None: an
    ordinary work tree, which the fast path still allows)."""
    for directory in (start, *start.parents):
        if is_git_directory(directory):
            return directory
        if path_exists(directory / ".git"):
            return None
    return None


def git_directory_run_in(stage: Stage, home: Path) -> Path | None:
    """The git directory a `git` stage operates in when that directory is itself a git
    directory (not a work tree): found by walking up, git's way, from its working directory
    after any `cd` and from each `-C` target, or named directly by an explicit `--git-dir`.
    git reads that directory's `config` there, so a planted core.fsmonitor runs. None for
    the common case, git in an ordinary work tree, which the fast path still allows. GIT_DIR
    in the environment already refuses the stage."""
    if not stage.words or os.path.basename(stage.words[0]) != "git":
        return None
    args = stage.words[1:]
    i = git_subcommand_index(args)
    head = args[:i] if i is not None else args
    base = stage.cwds[-1]
    for j, arg in enumerate(head):
        value = arg.split("=", 1)[1] if arg.startswith("--git-dir=") else (
            head[j + 1] if arg == "--git-dir" and j + 1 < len(head) else None)
        if value is not None:
            try:
                resolved = resolve_word(value, base, home)
            except (ValueError, OSError, RuntimeError):
                continue
            if is_git_directory(resolved):  # --git-dir names the git directory directly
                return resolved
    for start in (base, *git_c_directories(stage, home)):
        found = git_directory_above(start)
        if found is not None:
            return found
    return None


def git_top(path: Path) -> Path | None:
    """The working tree path lies in: the nearest directory at or above it with a
    `.git` entry (a directory in a main clone, a file in a linked worktree)."""
    return next((d for d in (path, *path.parents) if path_exists(d / ".git")), None)


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
        searched = search_starts(stage.words)
        # The names a search excludes (`--exclude=.env`) are patterns, not paths it reads.
        named = [word for position, word in enumerate(stage.words)
                 if searched is None or position not in searched.exclusion_words]
        if stage.words and os.path.basename(stage.words[0]) == "sed":
            named += sed_read_files(stage.words[1:])   # `r FILE` names FILE inside the script
        for path in stage_paths(stage, home, named):
            if secret_paths is not None and secret(path, secret_paths):
                return f"{path} holds keys or credentials, which no tool may read or write"
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
        if program == "ln":
            symbolic, names = ln_command(stage.words)
            if not symbolic:
                # Any operand may be the control file: the source, or the one `ln -t DIR` names.
                for path in stage_paths(stage, home, names):
                    if harness_control(path, home):
                        return LINK_CONTROL.format(control=path)
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


