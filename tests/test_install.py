"""Tests for aegys/install.py: `aegys install` wires the hooks, grants and status line into agy."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from aegys.guard import hook_install_problem
from aegys.install import InstallError, install

AEGYS_STATUS_LINE = {
    "type": "command",
    "command": '"$HOME/.local/bin/aegys" --statusline',
    "enabled": True,
    "stack_with_default": True,
}


class InstallTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.home.mkdir()
        self.hooks = self.home / ".gemini" / "config" / "hooks.json"
        self.settings = self.home / ".gemini" / "antigravity-cli" / "settings.json"
        self.launcher = self.home / ".local" / "bin" / "aegys"
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_text("#!/bin/sh\n", encoding="utf-8")
        self.launcher.chmod(0o755)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")

    def read(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    def test_fresh_home_gets_a_hook_the_status_line_accepts(self) -> None:
        install(self.home)
        self.assertIsNone(hook_install_problem(self.home))

    def test_fresh_home_gets_the_grants_and_the_status_line(self) -> None:
        install(self.home)
        settings = self.read(self.settings)
        self.assertEqual(
            settings["permissions"]["allow"],
            ["command(regex:(?s).*)", "read_file($HOME)", "write_file($HOME)"],
        )
        self.assertEqual(settings["statusLine"], AEGYS_STATUS_LINE)

    def test_other_hooks_and_settings_are_kept(self) -> None:
        self.write(self.hooks, {"lint": {"PostToolUse": []}})
        self.write(self.settings, {"theme": "light", "permissions": {"allow": ["command(ls)"], "deny": ["x"]}})
        install(self.home)
        self.assertIn("lint", self.read(self.hooks))
        settings = self.read(self.settings)
        self.assertEqual(settings["theme"], "light")
        self.assertEqual(settings["permissions"]["deny"], ["x"])
        self.assertEqual(settings["permissions"]["allow"][0], "command(ls)")

    def test_running_twice_changes_nothing_more(self) -> None:
        install(self.home)
        first = (self.hooks.read_text(), self.settings.read_text())
        install(self.home)
        self.assertEqual((self.hooks.read_text(), self.settings.read_text()), first)

    def test_an_outdated_aegys_hook_is_replaced(self) -> None:
        self.write(self.hooks, {"aegys": {"PreToolUse": [{"matcher": "run_command", "hooks": []}]}})
        install(self.home)
        self.assertIsNone(hook_install_problem(self.home))

    def test_another_status_line_is_kept_and_reported(self) -> None:
        own = {"type": "command", "command": "my-status", "enabled": True}
        self.write(self.settings, {"statusLine": own})
        notes = install(self.home)
        self.assertEqual(self.read(self.settings)["statusLine"], own)
        self.assertTrue(any("statusLine" in note for note in notes))

    def test_changed_files_are_backed_up_first(self) -> None:
        self.write(self.settings, {"theme": "light"})
        install(self.home)
        backup = self.settings.with_name("settings.json.aegys-backup")
        self.assertEqual(self.read(backup), {"theme": "light"})

    def test_a_file_that_does_not_parse_stops_the_install_before_any_write(self) -> None:
        self.write(self.settings, "{not json")
        with self.assertRaises(InstallError) as caught:
            install(self.home)
        self.assertIn(str(self.settings), str(caught.exception))
        self.assertFalse(self.hooks.exists())
        self.assertEqual(self.settings.read_text(), "{not json")

    def test_without_the_launcher_nothing_is_written(self) -> None:
        self.launcher.unlink()
        with self.assertRaises(InstallError) as caught:
            install(self.home)
        self.assertIn(".local/bin/aegys", str(caught.exception))
        self.assertFalse(self.hooks.exists())
        self.assertFalse(self.settings.exists())

    def test_the_atomic_write_leaves_no_temporary_file(self) -> None:
        install(self.home)
        leftovers = [p.name for p in self.settings.parent.iterdir() if p.name.endswith(".tmp")]
        self.assertEqual(leftovers, [])


if __name__ == "__main__":
    unittest.main()
