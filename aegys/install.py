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

What install added is recorded in ``~/.gemini/aegys/installed.json``.

The hooks are written before the grants, since the grants alone let agy run
anything. Each file is copied to ``<name>.aegys-backup`` before it changes and is
replaced in one step. If ``~/.local/bin/aegys`` is missing or either file does not
parse, nothing is written.

Uninstall removes the grants install recorded (all three if the record is missing
or broken), and always the catch-all ``command(...)`` grant, which only defers to
the hook. Then it removes the hooks and any status line that runs aegys. It backs
up to ``<name>.aegys-uninstall-backup`` so the pre-install backup survives, and it
does not need the launcher.
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

CATCH_ALL_GRANT = "command(regex:(?s).*)"
AEGYS_GRANTS = (CATCH_ALL_GRANT, "read_file($HOME)", "write_file($HOME)")

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


def write_json_object(path: Path, value: dict[str, Any], backup_suffix: str | None = ".aegys-backup") -> bool:
    """Write value to path, backing up the old file first unless backup_suffix is None.
    False when nothing changed."""
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if path.exists():
        if path.read_text(encoding="utf-8") == text:
            return False
        if backup_suffix is not None:
            shutil.copy2(path, path.with_name(path.name + backup_suffix))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)  # agy never reads a half-written file
    return True


def is_aegys_status_line(status_line: object) -> bool:
    """True for a status line that runs the aegys chip, however it was written."""
    command = str(status_line.get("command", "")) if isinstance(status_line, dict) else ""
    return ".local/bin/aegys" in command and "--statusline" in command


def config_paths(home: Path) -> tuple[Path, Path, Path]:
    """agy's hooks file, agy's settings file, and the record of what install added."""
    return (
        home / ".gemini" / "config" / "hooks.json",
        home / ".gemini" / "antigravity-cli" / "settings.json",
        home / ".gemini" / "aegys" / "installed.json",
    )


def install(home: Path) -> list[str]:
    """Wire aegys into agy's config under home. Returns one note per thing done or left."""
    hooks_path, settings_path, record_path = config_paths(home)
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
    record = read_json_object(record_path)
    notes: list[str] = []

    permissions = settings.get("permissions")
    if not isinstance(permissions, dict):
        permissions = settings["permissions"] = {}
    allow = permissions.get("allow")
    created_allow_list = not isinstance(allow, list)
    if created_allow_list:
        allow = permissions["allow"] = []
    added_grants = [grant for grant in AEGYS_GRANTS if grant not in allow]
    allow.extend(added_grants)

    status_line = settings.get("statusLine")
    if status_line is None:
        settings["statusLine"] = AEGYS_STATUS_LINE
    elif not is_aegys_status_line(status_line):
        notes.append(
            f"Kept your statusLine in {settings_path}; to see the aegys chip, set its "
            f"command to {AEGYS_STATUS_LINE['command']}."
        )

    # The record goes first, so uninstall knows what to take back even if a later
    # write fails. A reinstall adds to it.
    previous_grants = record.get("addedGrants") if isinstance(record.get("addedGrants"), list) else []
    record = {
        "addedGrants": [g for g in AEGYS_GRANTS if g in previous_grants or g in added_grants],
        "createdAllowList": bool(record.get("createdAllowList")) or created_allow_list,
    }
    write_json_object(record_path, record, backup_suffix=None)

    hooks["aegys"] = AEGYS_HOOKS
    hooks_written = write_json_object(hooks_path, hooks)
    if hooks_written:
        notes.append(f"Wrote the aegys hooks to {hooks_path}.")
    settings_written = write_json_object(settings_path, settings)
    if settings_written:
        notes.append(f"Wrote the grants and the status line to {settings_path}.")
    if not (hooks_written or settings_written):
        notes.insert(0, "aegys was already wired into agy; nothing changed.")
    return notes


def uninstall(home: Path) -> list[str]:
    """Remove what install added from agy's config under home, keeping the rest.
    Returns one note per thing done or left."""
    hooks_path, settings_path, record_path = config_paths(home)
    hooks = read_json_object(hooks_path)
    settings = read_json_object(settings_path)
    try:
        record = read_json_object(record_path)
    except InstallError:
        record = {}  # a broken record means no record: take back all aegys grants
    settings_before = copy.deepcopy(settings)
    notes: list[str] = []

    has_record = isinstance(record.get("addedGrants"), list)
    if has_record:
        # The catch-all grant only defers to the hook, so it goes with the hook even
        # when the user had it before install.
        removed_grants = [g for g in AEGYS_GRANTS if g in record["addedGrants"] or g == CATCH_ALL_GRANT]
        created_allow_list = bool(record.get("createdAllowList"))
    else:
        # Wired by hand or by an older aegys: nothing says which grants were the user's.
        removed_grants = list(AEGYS_GRANTS)
        created_allow_list = True
    # Grants first: without them agy asks again, so a stop between the writes
    # leaves agy asking, not open.
    permissions = settings.get("permissions")
    allow = permissions.get("allow") if isinstance(permissions, dict) else None
    if isinstance(allow, list):
        still_there = [g for g in removed_grants if g in allow]
        permissions["allow"] = [grant for grant in allow if grant not in removed_grants]
        if not has_record and still_there:
            notes.append(
                "No record of what aegys install added, so all aegys grants were removed: "
                + ", ".join(still_there) + ". Add back any you had before."
            )
        elif has_record and CATCH_ALL_GRANT in still_there and CATCH_ALL_GRANT not in record["addedGrants"]:
            notes.append(
                f"Removed {CATCH_ALL_GRANT} although you had it before: without the aegys "
                "hook it lets agy run every command unasked."
            )
        if created_allow_list and not permissions["allow"]:
            del permissions["allow"]
            if not permissions:
                del settings["permissions"]
    if is_aegys_status_line(settings.get("statusLine")):
        del settings["statusLine"]
    if settings != settings_before:
        write_json_object(settings_path, settings, ".aegys-uninstall-backup")
        notes.insert(0, f"Removed the aegys grants and status line from {settings_path}.")

    if "aegys" in hooks:
        del hooks["aegys"]
        write_json_object(hooks_path, hooks, ".aegys-uninstall-backup")
        notes.append(f"Removed the aegys hooks from {hooks_path}.")
    if record_path.exists():
        record_path.unlink()

    if not notes:
        notes.append("aegys was not wired into agy; nothing changed.")
    else:
        notes.append(f"Left your aegys config in {record_path.parent} alone.")
    return notes


def main(command: str = "install") -> int:
    try:
        notes = (install if command == "install" else uninstall)(Path.home())
    except InstallError as err:
        print(f"aegys {command}: {err}", file=sys.stderr)
        return 1
    except OSError as err:
        print(f"aegys {command}: could not write {err.filename}: {err.strerror}", file=sys.stderr)
        return 1
    for note in notes:
        print(note)
    if command == "install":
        print("Set ANTHROPIC_API_KEY in the shell that starts agy.")
    else:
        print("Now run: uv tool uninstall aegys")
    return 0
