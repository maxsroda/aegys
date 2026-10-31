"""The per-user aegys settings in ~/.gemini/aegys/config.json.

``harnessConfigRepository`` names the harness config repository: a git clone that
installs and configures the coding-agent harnesses (their hooks, launchers and
settings). Writing it changes what the harnesses run or allow, so the guard
protects it. Its keys, each a list of directories relative to ``path``:

- ``launcherDirs``: hooks and launchers the harnesses run. No tool may write them.
- ``scriptDirs``: scripts the user runs, such as an installer. No shell command
  may write them; a file tool's write goes to the classifier. A shell command
  that runs one of these files is the user's own code and is not held to its
  operands.
- ``vibeSettingsDirs``: Mistral Vibe settings and rules. No shell command may
  write them; a shell read of a Vibe settings file there is sent to ``read_file``.
- ``agySettingsDirs``: agy and pi-automode settings. No tool may write them, and
  inline code that names one is denied.
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


@dataclass(frozen=True)
class HarnessConfigRepository:
    path: Path
    launcher_dirs: tuple[Path, ...]
    script_dirs: tuple[Path, ...]
    vibe_settings_dirs: tuple[Path, ...]
    agy_settings_dirs: tuple[Path, ...]
    control_spellings: tuple[str, ...]

    @property
    def control_dirs(self) -> tuple[Path, ...]:
        """The directories no shell command may write."""
        return (*self.launcher_dirs, *self.script_dirs, *self.vibe_settings_dirs)

    @property
    def code_dir_names(self) -> tuple[str, ...]:
        """launcherDirs and scriptDirs as written in the config, relative to path."""
        return tuple(str(d.relative_to(self.path)) for d in (*self.launcher_dirs, *self.script_dirs))

    @property
    def vibe_control_spellings(self) -> tuple[str, ...]:
        """vibeSettingsDirs as written in the config, each with a trailing slash, and
        controlSpellings."""
        return (*(f"{d.relative_to(self.path)}/" for d in self.vibe_settings_dirs),
                *self.control_spellings)

    @property
    def agy_control_spellings(self) -> tuple[str, ...]:
        """agySettingsDirs as written in the config, each with a trailing slash."""
        return tuple(f"{d.relative_to(self.path)}/" for d in self.agy_settings_dirs)


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
        vibe_settings_dirs=tuple(path / d for d in names("vibeSettingsDirs")),
        agy_settings_dirs=tuple(path / d for d in names("agySettingsDirs")),
        control_spellings=names("controlSpellings"),
    )
