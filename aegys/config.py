"""The per-user aegys settings in ~/.gemini/aegys/config.json, and the policy lists.

The policy lists are the shipped defaults in ``aegys/data/default-config.json``
merged with the user's entries. Both files have the same keys:

- ``shellCommandRules``: ``allow``, ``ask`` and ``deny``, each a list of glob
  patterns for a whole shell command (``git status*``). ``allow`` lets a command
  run without the classifier, ``ask`` makes agy confirm it, ``deny`` blocks it.
- ``allowWhileGuardOff``: command prefixes, or ``regex:`` patterns, that agy may
  run while the guard is off (``/aegys off``).
- ``deniedHosts``: an object from a reason to a list of hosts. A host is denied
  when it equals an entry or ends with ``.`` and the entry.
- ``secretPaths``: glob patterns for paths that no tool may read or write, in
  any letter case.

The user's config adds entries to these lists. ``removeDefaults`` removes shipped
entries: it has the same keys, except that for ``deniedHosts`` it is one flat list
of hosts, removed from every reason. The effective list is the shipped entries
plus the user's, minus the removed ones, each entry once. Entries that are not
strings are ignored, and so is a value of the wrong type, key by key. A missing
user config gives the shipped lists alone. If the shipped file cannot be read or
does not hold every list, ``load_policy`` returns None and the guard fails closed.

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

Any other write inside ``path`` goes to the classifier. Without
``harnessConfigRepository`` no repository is protected.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


def load_aegys_config(home: Path) -> dict[str, Any]:
    """The settings in home/.gemini/aegys/config.json. Missing or unreadable means
    the defaults."""
    try:
        data = json.loads((home / ".gemini" / "aegys" / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


DATA_DIR = Path(__file__).resolve().parent / "data"
DEFAULT_CONFIG_PATH = DATA_DIR / "default-config.json"
# The keys of harnessConfigRepository that the loader reads.
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
        and all(is_string_list(rules.get(kind)) for kind in ("allow", "ask", "deny"))
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
    """The non-empty string entries of a list; anything else is ignored."""
    if not isinstance(value, list):
        return []
    return [entry.strip() for entry in value if isinstance(entry, str) and entry.strip()]


def _merged(shipped: list[str], user: list[str], removed: list[str]) -> tuple[str, ...]:
    """The shipped entries, then the user's, minus the removed ones, each once."""
    gone = set(removed)
    return tuple(dict.fromkeys(entry for entry in (*shipped, *user) if entry not in gone))


def _denied_hosts(shipped: dict[str, Any], user: dict[str, Any], removed: list[str]) -> dict[str, str]:
    """Each denied host with its reason. A reason whose value is not a list is ignored;
    where a host is listed twice, the first reason wins."""
    gone = {host.lower() for host in removed}
    reasons: dict[str, str] = {}
    for by_reason in (shipped, user):
        for reason, hosts in by_reason.items():
            if not isinstance(reason, str) or not reason.strip() or not isinstance(hosts, list):
                continue
            for host in _strings(hosts):
                host = host.lower()
                if host not in gone:
                    reasons.setdefault(host, reason.strip())
    return reasons


def load_policy(home: Path) -> Optional[Policy]:
    """The effective policy for home, or None when the shipped lists cannot be read."""
    shipped = shipped_lists()
    if shipped is None:
        return None
    user = load_aegys_config(home)
    removed = _mapping(user.get("removeDefaults"))
    user_rules = _mapping(user.get("shellCommandRules"))
    removed_rules = _mapping(removed.get("shellCommandRules"))
    shipped_rules = shipped["shellCommandRules"]

    def rule_list(kind: str) -> tuple[str, ...]:
        return _merged(shipped_rules[kind], _strings(user_rules.get(kind)),
                       _strings(removed_rules.get(kind)))

    return Policy(
        shell_allow=rule_list("allow"),
        shell_ask=rule_list("ask"),
        shell_deny=rule_list("deny"),
        allow_while_guard_off=_merged(
            shipped["allowWhileGuardOff"], _strings(user.get("allowWhileGuardOff")),
            _strings(removed.get("allowWhileGuardOff"))),
        denied_hosts=_denied_hosts(
            shipped["deniedHosts"], _mapping(user.get("deniedHosts")),
            _strings(removed.get("deniedHosts"))),
        secret_paths=_merged(
            shipped["secretPaths"], _strings(user.get("secretPaths")),
            _strings(removed.get("secretPaths"))),
    )


def shipped_problem() -> Optional[str]:
    """Why the shipped policy cannot be used, or None. The guard then fails closed."""
    return None if shipped_lists() is not None else "default-config.json unreadable"


def config_problem(home: Path) -> Optional[str]:
    """Why the user's config.json cannot be used as written, or None. A missing file is
    fine. An unreadable or unparsable one, or an unknown key under
    harnessConfigRepository, is not: the guard would silently ignore what it says."""
    try:
        data = json.loads((home / ".gemini" / "aegys" / "config.json").read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return "config.json does not parse"
    if not isinstance(data, dict):
        return "config.json does not parse"
    repository = data.get("harnessConfigRepository")
    for key in _mapping(repository):
        if key not in HARNESS_REPOSITORY_KEYS:
            return f"unknown config key {key}"
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
