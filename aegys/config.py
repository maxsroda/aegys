"""The per-user aegys settings in ~/.gemini/aegys/config.json, and the policy lists.

The policy lists are the shipped defaults in ``aegys/data/default-config.json``
merged with the user's entries. Both files have the same keys:

- ``shellCommandRules``: ``allow``, ``ask`` and ``deny``, each a list of glob
  patterns for a whole shell command (``git status*``). ``allow`` lets a command
  run without the classifier, ``ask`` makes agy confirm it, ``deny`` blocks it.
  In an ``allow`` entry a first word that ends in ``*`` is a whole program name:
  ``ls*`` allows ``ls -la`` but not ``lsblk``. A first word with a ``/``
  (``./scripts/*``) or a bare ``*`` is an ordinary glob. In a ``deny`` or ``ask`` entry a `` * `` between two words
  also matches no arguments: ``find * -fprint*`` matches ``find -fprint out``.
- ``allowWhileGuardOff``: command prefixes, or ``regex:`` patterns, that agy may
  run while the guard is off (``/aegys off``).
- ``deniedHosts``: an object from a reason to a list of hosts. A host is denied
  when it equals an entry or ends with ``.`` and the entry. Host names ignore case.
- ``secretPaths``: fnmatch glob patterns for paths that no tool may read or write.
  An entry that starts with ``~/`` is read from the home directory. An entry also
  covers everything below what it matches: ``*/.mysecret`` covers ``*/.mysecret/x``.

Shell rules and secret paths are matched without regard to letter case.

The user's config adds entries to these lists. Shipped and user entries alike lose
their surrounding whitespace, and empty entries are dropped. ``removeDefaults``
removes entries from the effective list, shipped entries and the user's own alike.
It has the same keys, except that for ``deniedHosts`` it is one flat list of hosts,
removed from every reason. A removed entry matches only when spelled as written,
except host names, which match in any letter case. The effective list keeps each
entry once, shipped entries first.

The user's config also takes ``classifierModel`` and ``anthropicBaseUrl``, strings
that name the classifier's model and API base URL.

A missing user config gives the shipped lists alone. If the shipped file cannot be
read, or the user's config does not parse, has an unknown key, or has a value of
the wrong type, ``load_policy`` returns None, and the guard holds every call it
would have to check (see ``aegys/guard.py``). ``policy_problem`` says why and
names the file.

``harnessConfigRepository`` names the harness config repository: a git clone that
installs and configures the coding-agent harnesses (their hooks, launchers and
settings). Writing it changes what the harnesses run or allow, so the guard
protects it. Its keys, each a list of directories relative to ``path``:

- ``launcherDirs``: hooks and launchers the harnesses run. No tool may write them.
- ``scriptDirs``: scripts the user runs, such as an installer. No shell command
  may write them; a file tool's write goes to the classifier. A shell command
  that runs one of these files is the user's own code and is not held to its
  operands.
- ``harnessSettingsDirs``: settings and rules of the harnesses. No shell command
  may write them; a file tool's write goes to the classifier.
- ``permissionSettingsDirs``: permission settings of the harnesses. No tool may
  write them, and inline code that names one is denied.
- ``controlSpellings``: file names that, written anywhere in inline code, count
  as a write to the repository's control files.

Its ``path`` is a string, and ``~/`` in it is read as home. Any other write inside
``path`` goes to the classifier. Without ``harnessConfigRepository`` no repository
is protected.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


def user_config_path(home: Path) -> Path:
    """The user's config file under home."""
    return home / ".gemini" / "aegys" / "config.json"


def load_aegys_config(home: Path) -> dict[str, Any]:
    """The settings in the user's config file. Missing or unreadable means none."""
    try:
        data = json.loads(user_config_path(home).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_CONFIG_PATH = DATA_DIR / "default-config.json"
# The keys the loader reads from the user's config.
TOP_LEVEL_KEYS = frozenset({
    "classifierModel", "anthropicBaseUrl", "harnessConfigRepository", "removeDefaults",
    "shellCommandRules", "allowWhileGuardOff", "deniedHosts", "secretPaths",
})
RULE_KINDS = ("allow", "ask", "deny")
# The keys removeDefaults may name.
REMOVABLE_KEYS = frozenset({"shellCommandRules", "allowWhileGuardOff", "deniedHosts", "secretPaths"})
HARNESS_REPOSITORY_KEYS = frozenset({
    "path", "launcherDirs", "scriptDirs", "harnessSettingsDirs", "permissionSettingsDirs",
    "controlSpellings",
})


@dataclass(frozen=True)
class Policy:
    """The effective policy lists: the shipped defaults merged with the user's config."""
    shell_allow: tuple[str, ...]
    shell_ask: tuple[str, ...]
    shell_deny: tuple[str, ...]
    allow_while_guard_off: tuple[str, ...]
    denied_hosts: dict[str, str]  # host -> the reason it is denied
    secret_paths: tuple[str, ...]


def is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def shipped_lists() -> Optional[dict[str, Any]]:
    """The shipped policy from DEFAULT_CONFIG_PATH, or None when the file cannot be
    read or does not hold every list with the right type."""
    try:
        data = json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    rules = data.get("shellCommandRules")
    hosts = data.get("deniedHosts")
    if not (
        isinstance(rules, dict)
        and all(is_string_list(rules.get(kind)) for kind in RULE_KINDS)
        and is_string_list(data.get("allowWhileGuardOff"))
        and is_string_list(data.get("secretPaths"))
        and isinstance(hosts, dict)
        and all(is_string_list(v) for v in hosts.values())
    ):
        return None
    return data


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> list[str]:
    """The entries of a list, stripped of surrounding whitespace, with empty ones dropped."""
    if not isinstance(value, list):
        return []
    return [entry.strip() for entry in value if isinstance(entry, str) and entry.strip()]


def _expand_home(entry: str, home: Path) -> str:
    """A secret path that starts with ~/ names a path under home."""
    return f"{home.resolve()}{entry[1:]}" if entry.startswith("~/") else entry


def _merged(shipped: list[str], user: list[str], removed: list[str]) -> tuple[str, ...]:
    """The shipped entries, then the user's, minus the removed ones, each once."""
    gone = set(removed)
    return tuple(dict.fromkeys(entry for entry in (*shipped, *user) if entry not in gone))


def _denied_hosts(shipped: dict[str, Any], user: dict[str, Any], removed: list[str]) -> dict[str, str]:
    """Each denied host with its reason. Where a host is listed twice, the first reason wins."""
    gone = {host.lower() for host in removed}
    reasons: dict[str, str] = {}
    for by_reason in (shipped, user):
        for reason, hosts in by_reason.items():
            reason = reason.strip()
            if not reason:
                continue
            for host in _strings(hosts):
                host = host.lower()
                if host not in gone:
                    reasons.setdefault(host, reason)
    return reasons


def load_policy(home: Path) -> Optional[Policy]:
    """The effective policy for home, or None when it cannot be applied: the shipped
    lists are unreadable, or the user's config has a problem (see policy_problem)."""
    shipped = shipped_lists()
    if shipped is None or config_problem(home) is not None:
        return None
    user = load_aegys_config(home)
    removed = _mapping(user.get("removeDefaults"))
    user_rules = _mapping(user.get("shellCommandRules"))
    removed_rules = _mapping(removed.get("shellCommandRules"))
    shipped_rules = shipped["shellCommandRules"]

    def rule_list(kind: str) -> tuple[str, ...]:
        return _merged(_strings(shipped_rules[kind]), _strings(user_rules.get(kind)),
                       _strings(removed_rules.get(kind)))

    def secret_list(entries: Any) -> list[str]:
        return [_expand_home(entry, home) for entry in _strings(entries)]

    return Policy(
        shell_allow=rule_list("allow"),
        shell_ask=rule_list("ask"),
        shell_deny=rule_list("deny"),
        allow_while_guard_off=_merged(
            _strings(shipped["allowWhileGuardOff"]), _strings(user.get("allowWhileGuardOff")),
            _strings(removed.get("allowWhileGuardOff"))),
        denied_hosts=_denied_hosts(
            shipped["deniedHosts"], _mapping(user.get("deniedHosts")),
            _strings(removed.get("deniedHosts"))),
        secret_paths=_merged(
            secret_list(shipped["secretPaths"]), secret_list(user.get("secretPaths")),
            secret_list(removed.get("secretPaths"))),
    )


def shipped_problem() -> Optional[str]:
    """Why the shipped policy cannot be used, or None. Used by the status line."""
    return None if shipped_lists() is not None else "default-config.json unreadable"


def _list_problem(value: Any, where: str) -> Optional[str]:
    return None if is_string_list(value) else f"{where} is not a list of strings"


def _object_problem(value: Any, where: str) -> Optional[str]:
    return None if isinstance(value, dict) else f"{where} is not an object"


def _string_problem(value: Any, where: str) -> Optional[str]:
    return None if isinstance(value, str) else f"{where} is not a string"


def _rules_problem(value: Any, where: str) -> Optional[str]:
    problem = _object_problem(value, where)
    if problem is not None:
        return problem
    for kind, entries in value.items():
        if kind not in RULE_KINDS:
            return f"unknown key {kind} in {where}"
        problem = _list_problem(entries, f"{where}.{kind}")
        if problem is not None:
            return problem
    return None


def _hosts_problem(value: Any, where: str) -> Optional[str]:
    problem = _object_problem(value, where)
    if problem is not None:
        return problem
    for reason, hosts in value.items():
        if not reason.strip():
            return f"{where} has an empty reason"
        problem = _list_problem(hosts, f"{where}.{reason}")
        if problem is not None:
            return problem
    return None


def _removed_problem(value: Any) -> Optional[str]:
    problem = _object_problem(value, "removeDefaults")
    if problem is not None:
        return problem
    for key, entries in value.items():
        if key not in REMOVABLE_KEYS:
            return f"unknown key {key} in removeDefaults"
        if key == "shellCommandRules":
            problem = _rules_problem(entries, "removeDefaults.shellCommandRules")
        else:
            problem = _list_problem(entries, f"removeDefaults.{key}")
        if problem is not None:
            return problem
    return None


def _repository_problem(value: Any) -> Optional[str]:
    problem = _object_problem(value, "harnessConfigRepository")
    if problem is not None:
        return problem
    for key, item in value.items():
        if key not in HARNESS_REPOSITORY_KEYS:
            return f"unknown config key {key}"
        if key == "path":
            problem = _string_problem(item, "harnessConfigRepository.path")
        else:
            problem = _list_problem(item, f"harnessConfigRepository.{key}")
        if problem is not None:
            return problem
    return None


def config_problem(home: Path) -> Optional[str]:
    """Why the user's config cannot be applied as written, or None. A missing file is
    fine. Otherwise the first problem is reported: the file does not parse or is not
    a JSON object, a key is unknown, or a value has the wrong type."""
    try:
        data = json.loads(user_config_path(home).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return "config.json does not parse"
    if not isinstance(data, dict):
        return "config.json is not a JSON object"
    for key in data:
        if key not in TOP_LEVEL_KEYS:
            return f"unknown config key {key}"
    checks = (
        ("shellCommandRules", lambda v: _rules_problem(v, "shellCommandRules")),
        ("allowWhileGuardOff", lambda v: _list_problem(v, "allowWhileGuardOff")),
        ("secretPaths", lambda v: _list_problem(v, "secretPaths")),
        ("deniedHosts", lambda v: _hosts_problem(v, "deniedHosts")),
        ("removeDefaults", _removed_problem),
        ("harnessConfigRepository", _repository_problem),
        ("classifierModel", lambda v: _string_problem(v, "classifierModel")),
        ("anthropicBaseUrl", lambda v: _string_problem(v, "anthropicBaseUrl")),
    )
    for key, check in checks:
        if key in data:
            problem = check(data[key])
            if problem is not None:
                return problem
    return None


def policy_problem(home: Path) -> Optional[str]:
    """Why the guard cannot apply the policy, naming the file that holds the problem,
    or None."""
    if shipped_problem() is not None:
        return f"{DEFAULT_CONFIG_PATH} is unreadable or malformed"
    problem = config_problem(home)
    if problem is not None:
        return f"{user_config_path(home)}: {problem}"
    return None


@dataclass(frozen=True)
class HarnessConfigRepository:
    path: Path
    launcher_dirs: tuple[Path, ...]
    script_dirs: tuple[Path, ...]
    harness_settings_dirs: tuple[Path, ...]
    permission_settings_dirs: tuple[Path, ...]
    control_spellings: tuple[str, ...]

    @property
    def control_dirs(self) -> tuple[Path, ...]:
        """The directories no shell command may write."""
        return (*self.launcher_dirs, *self.script_dirs, *self.harness_settings_dirs)

    @property
    def code_dir_names(self) -> tuple[str, ...]:
        """launcherDirs and scriptDirs as written in the config, relative to path."""
        return tuple(str(d.relative_to(self.path)) for d in (*self.launcher_dirs, *self.script_dirs))

    @property
    def harness_control_spellings(self) -> tuple[str, ...]:
        """harnessSettingsDirs as written in the config, each with a trailing slash, and
        controlSpellings."""
        return (*(f"{d.relative_to(self.path)}/" for d in self.harness_settings_dirs),
                *self.control_spellings)

    @property
    def permission_control_spellings(self) -> tuple[str, ...]:
        """permissionSettingsDirs as written in the config, each with a trailing slash."""
        return tuple(f"{d.relative_to(self.path)}/" for d in self.permission_settings_dirs)


def harness_config_repository(home: Path) -> Optional[HarnessConfigRepository]:
    """The repository named by ``harnessConfigRepository``, with ``~`` read as home,
    or None when the config names none."""
    entry = load_aegys_config(home).get("harnessConfigRepository")
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        return None
    raw = entry["path"]
    path = (home / raw[2:] if raw.startswith("~/") else Path(raw)).resolve()

    def names(key: str) -> tuple[str, ...]:
        values = entry.get(key)
        return tuple(v for v in values if isinstance(v, str) and v) if isinstance(values, list) else ()

    return HarnessConfigRepository(
        path=path,
        launcher_dirs=tuple(path / d for d in names("launcherDirs")),
        script_dirs=tuple(path / d for d in names("scriptDirs")),
        harness_settings_dirs=tuple(path / d for d in names("harnessSettingsDirs")),
        permission_settings_dirs=tuple(path / d for d in names("permissionSettingsDirs")),
        control_spellings=names("controlSpellings"),
    )
