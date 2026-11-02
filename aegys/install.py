"""`aegys install`: wire aegys into agy. `aegys uninstall` removes exactly that again.

It merges three things into the user's agy config, keeping everything else:

1. ``~/.gemini/config/hooks.json``: an ``aegys`` entry that runs the guard before
   every guarded tool call (``PreToolUse``) and reads ``/aegys`` switches
   (``PreInvocation``). An existing ``aegys`` entry is replaced.
2. ``~/.gemini/antigravity-cli/settings.json``, ``permissions.allow``: the grants that
   let agy run what the hook allows instead of asking again. Missing grants are
   appended; the user's other grants stay.
3. The same file's ``statusLine``: the aegys chip. A status line that is not aegys's
   is kept, and the install says so.

The hooks are written before the grants, since the grants alone let agy run
anything. Each file is copied to ``<name>.aegys-backup`` before it changes and is
replaced in one step. If ``~/.local/bin/aegys`` is missing or either file does not
parse, nothing is written.

Uninstall removes the grants first and the hooks second, and keeps a status line
that is not aegys's. It does not need the launcher.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from .guard import GUARDED_TOOL_NAMES

LAUNCHER = '"$HOME/.local/bin/aegys"'

AEGYS_HOOKS = {
    "PreToolUse": [
        {
            "matcher": "|".join(GUARDED_TOOL_NAMES),
            "hooks": [{"type": "command", "command": LAUNCHER, "timeout": 30}],
        }
    ],
    "PreInvocation": [
        {"type": "command", "command": f"{LAUNCHER} --pre-invocation", "timeout": 10}
    ],
}

AEGYS_GRANTS = ("command(regex:(?s).*)", "read_file($HOME)", "write_file($HOME)")

AEGYS_STATUS_LINE = {
    "type": "command",
    "command": f"{LAUNCHER} --statusline",
    "enabled": True,
    "stack_with_default": True,
}


class InstallError(Exception):
    """A config file aegys install cannot safely change."""


def read_json_object(path: Path) -> dict[str, Any]:
    """The JSON object in path, or {} when the file does not exist."""
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as err:
        raise InstallError(f"{path} does not parse ({err}); fix it and run aegys install again.") from err
    if not isinstance(value, dict):
        raise InstallError(f"{path} does not hold a JSON object; fix it and run aegys install again.")
    return value


def write_json_object(path: Path, value: dict[str, Any]) -> bool:
    """Write value to path, backing up the old file first. False when nothing changed."""
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") == text:
            return False
        shutil.copy2(path, path.with_name(path.name + ".aegys-backup"))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)  # agy never reads a half-written file
    return True


def install(home: Path) -> list[str]:
    """Wire aegys into agy's config under home. Returns one note per thing done or left."""
    hooks_path = home / ".gemini" / "config" / "hooks.json"
    settings_path = home / ".gemini" / "antigravity-cli" / "settings.json"
    launcher = home / ".local" / "bin" / "aegys"
    if not os.access(launcher, os.X_OK):
        # agy refuses every guarded tool call whose hook program is missing, so
        # wiring a hook to a missing program would leave agy unusable.
        raise InstallError(
            f"{launcher} is missing or not executable, and the hooks run it from there. "
            "Install aegys with uv tool install (which puts it there by default), "
            "then run aegys install again. Nothing was changed."
        )
    hooks = read_json_object(hooks_path)
    settings = read_json_object(settings_path)
    notes: list[str] = []

    hooks["aegys"] = AEGYS_HOOKS
    hooks_written = write_json_object(hooks_path, hooks)
    if hooks_written:
        notes.append(f"Wrote the aegys hooks to {hooks_path}.")

    permissions = settings.get("permissions")
    if not isinstance(permissions, dict):
        permissions = settings["permissions"] = {}
    allow = permissions.get("allow")
    if not isinstance(allow, list):
        allow = permissions["allow"] = []
    allow.extend(grant for grant in AEGYS_GRANTS if grant not in allow)

    status_line = settings.get("statusLine")
    if status_line is None or status_line == AEGYS_STATUS_LINE:
        settings["statusLine"] = AEGYS_STATUS_LINE
    else:
        notes.append(
            f"Kept your statusLine in {settings_path}; to see the aegys chip, set its "
            f"command to {AEGYS_STATUS_LINE['command']}."
        )
    settings_written = write_json_object(settings_path, settings)
    if settings_written:
        notes.append(f"Wrote the grants and the status line to {settings_path}.")
    if not (hooks_written or settings_written):
        notes.insert(0, "aegys was already wired into agy; nothing changed.")
    return notes


def uninstall(home: Path) -> list[str]:
    """Remove what install added from agy's config under home, keeping the rest.
    Returns one note per thing done or left."""
    hooks_path = home / ".gemini" / "config" / "hooks.json"
    settings_path = home / ".gemini" / "antigravity-cli" / "settings.json"
    hooks = read_json_object(hooks_path)
    settings = read_json_object(settings_path)
    settings_before = copy.deepcopy(settings)
    notes: list[str] = []

    # Grants first: without them agy asks again, so a stop between the two writes
    # leaves agy asking, not open.
    permissions = settings.get("permissions")
    allow = permissions.get("allow") if isinstance(permissions, dict) else None
    if isinstance(allow, list):
        permissions["allow"] = [grant for grant in allow if grant not in AEGYS_GRANTS]
        if not permissions["allow"]:
            del permissions["allow"]
        if not permissions:
            del settings["permissions"]
    if settings.get("statusLine") == AEGYS_STATUS_LINE:
        del settings["statusLine"]
    if settings != settings_before and write_json_object(settings_path, settings):
        notes.append(f"Removed the aegys grants and status line from {settings_path}.")

    if "aegys" in hooks:
        del hooks["aegys"]
        write_json_object(hooks_path, hooks)
        notes.append(f"Removed the aegys hooks from {hooks_path}.")

    if not notes:
        notes.append("aegys was not wired into agy; nothing changed.")
    return notes


def main(command: str = "install") -> int:
    try:
        notes = (install if command == "install" else uninstall)(Path.home())
    except InstallError as err:
        print(f"aegys install: {err}", file=sys.stderr)
        return 1
    for note in notes:
        print(note)
    if command == "install":
        print("Set ANTHROPIC_API_KEY in the shell that starts agy.")
    else:
        print("Now run: uv tool uninstall aegys")
    return 0
