"""Tests for aegys/config.py: the shipped policy lists merged with the user's config."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegys import config
from aegys.config import config_problem, load_policy

# The entries the shipped defaults must not hold: they run code from the workspace,
# or act outside the machine. The user's own config adds them.
MOVED_ALLOW = (
    "orca snapshot*", "orca tab current*", "orca tab list*", "orca tab show*",
    "orca terminal list*", "orca terminal show*", "julia --version*", "firecrawl*",
    "git push*", "git commit*", "gh pr create*", "gh issue create*", "gh pr comment*", "pytest*",
    "python3 -m pytest*", "python3 -m unittest*", "python3 tests/*", "bash tests/*",
    "tests/*", "scripts/install.sh*", "uv run pytest*", "cargo test*", "cargo test* 2>&1",
    "cargo clippy*", "cargo clippy* 2>&1",
)
MOVED_DENY = (
    "*EventKit*", "icalBuddy * editConfig*", "icalBuddy editConfig*", "osascript *Calendar*",
    "osascript *Mail*", "osascript *Reminders*", "osascript *iCal*",
)
MOVED_ALLOW_WHILE_OFF = (
    "orca snapshot", "orca tab current", "orca tab list", "orca tab show",
    "orca terminal list", "orca terminal show", "julia --version", "firecrawl", "git push",
    "git commit", "gh pr create", "gh issue create", "gh pr comment", "cargo test", "cargo clippy",
    "regex:bash tests/.*", "regex:python3 tests/.*",
)


class TestHome(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        (self.home / ".gemini" / "aegys").mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write_user_config(self, config_value: object) -> None:
        text = config_value if isinstance(config_value, str) else json.dumps(config_value)
        (self.home / ".gemini" / "aegys" / "config.json").write_text(text, encoding="utf-8")


class ShippedDefaultsTest(TestHome):
    def test_the_generic_rules_are_shipped(self) -> None:
        policy = load_policy(self.home)
        self.assertIsNotNone(policy)
        self.assertIn("git status*", policy.shell_allow)
        self.assertIn("gh repo delete*", policy.shell_deny)
        self.assertIn("git status", policy.allow_while_guard_off)
        self.assertIn(".ssh", " ".join(policy.secret_paths))
        self.assertEqual(
            policy.denied_hosts["webhook.site"], "data exfiltration / out-of-band endpoint"
        )
        self.assertEqual(policy.denied_hosts["bit.ly"], "URL shortener hides the destination")
        self.assertEqual(policy.denied_hosts["iplogger.com"], "IP logger")
        self.assertEqual(policy.denied_hosts["1337x.to"], "on-the-fence site")

    def test_no_shipped_default_runs_workspace_code_or_acts_outside(self) -> None:
        policy = load_policy(self.home)
        shipped = {*policy.shell_allow, *policy.shell_ask, *policy.shell_deny,
                   *policy.allow_while_guard_off}
        for entry in (*MOVED_ALLOW, *MOVED_DENY, *MOVED_ALLOW_WHILE_OFF):
            self.assertNotIn(entry, shipped)

    def test_no_user_config_gives_the_defaults(self) -> None:
        policy = load_policy(self.home)
        self.assertIn("git status*", policy.shell_allow)
        self.assertIn("gh repo delete*", policy.shell_deny)
        self.assertIn("webhook.site", policy.denied_hosts)
        self.assertIn("*/.netrc", policy.secret_paths)

    def test_an_unparsable_user_config_gives_the_defaults(self) -> None:
        self.write_user_config("{not json")
        self.assertIn("git status*", load_policy(self.home).shell_allow)


class MergeTest(TestHome):
    def test_user_entries_are_added_to_every_list(self) -> None:
        self.write_user_config({
            "shellCommandRules": {"allow": ["mytool --check*"], "deny": ["mytool --publish*"]},
            "allowWhileGuardOff": ["mytool"],
            "deniedHosts": {"internal test": ["evil.example"]},
            "secretPaths": ["*/.mysecret/*"],
        })
        policy = load_policy(self.home)
        self.assertIn("mytool --check*", policy.shell_allow)
        self.assertIn("git status*", policy.shell_allow)
        self.assertIn("mytool --publish*", policy.shell_deny)
        self.assertIn("gh repo delete*", policy.shell_deny)
        self.assertIn("mytool", policy.allow_while_guard_off)
        self.assertIn("git status", policy.allow_while_guard_off)
        self.assertEqual(policy.denied_hosts["evil.example"], "internal test")
        self.assertEqual(policy.denied_hosts["webhook.site"], "data exfiltration / out-of-band endpoint")
        self.assertIn("*/.mysecret/*", policy.secret_paths)
        self.assertIn("*/.netrc", policy.secret_paths)

    def test_remove_defaults_removes_a_default_from_each_list(self) -> None:
        self.write_user_config({
            "removeDefaults": {
                "shellCommandRules": {"deny": ["gh repo delete*"]},
                "allowWhileGuardOff": ["git status"],
                "deniedHosts": ["webhook.site"],
                "secretPaths": ["*/.netrc"],
            },
        })
        policy = load_policy(self.home)
        self.assertNotIn("gh repo delete*", policy.shell_deny)
        self.assertNotIn("git status", policy.allow_while_guard_off)
        self.assertNotIn("webhook.site", policy.denied_hosts)
        self.assertNotIn("*/.netrc", policy.secret_paths)
        # Only the named entries go.
        self.assertIn("git status*", policy.shell_allow)
        self.assertIn("bit.ly", policy.denied_hosts)
        self.assertIn("*/.ssh", policy.secret_paths)

    def test_remove_defaults_for_shell_rules_only_touches_the_named_list(self) -> None:
        self.write_user_config({"removeDefaults": {"shellCommandRules": {"deny": ["gh repo delete*"]}}})
        policy = load_policy(self.home)
        self.assertNotIn("gh repo delete*", policy.shell_deny)
        self.assertIn("git status*", policy.shell_allow)

    def test_duplicates_collapse_and_non_strings_are_ignored(self) -> None:
        self.write_user_config({
            "shellCommandRules": {"allow": ["git status*", "git status*", 7, None, "mytool*"]},
        })
        policy = load_policy(self.home)
        self.assertEqual(policy.shell_allow.count("git status*"), 1)
        self.assertEqual(policy.shell_allow.count("mytool*"), 1)
        self.assertNotIn(7, policy.shell_allow)
        self.assertNotIn(None, policy.shell_allow)

    def test_wrong_typed_values_are_ignored_key_by_key(self) -> None:
        self.write_user_config({
            "shellCommandRules": {"allow": "git status*", "deny": ["mytool --publish*"]},
            "allowWhileGuardOff": {"mytool": True},
            "deniedHosts": ["evil.example"],
            "secretPaths": "*/.mysecret/*",
            "removeDefaults": "everything",
        })
        policy = load_policy(self.home)
        self.assertIn("git status*", policy.shell_allow)
        self.assertIn("mytool --publish*", policy.shell_deny)
        self.assertIn("git status", policy.allow_while_guard_off)
        self.assertNotIn("evil.example", policy.denied_hosts)
        self.assertNotIn("*/.mysecret/*", policy.secret_paths)
        self.assertIn("gh repo delete*", policy.shell_deny)

    def test_a_user_can_name_a_new_reason_for_hosts(self) -> None:
        self.write_user_config({"deniedHosts": {"my reason": ["Evil.Example"]}})
        self.assertEqual(load_policy(self.home).denied_hosts["evil.example"], "my reason")

    def test_remove_defaults_for_hosts_is_one_flat_list(self) -> None:
        self.write_user_config({"removeDefaults": {"deniedHosts": ["bit.ly", "iplogger.com"]}})
        policy = load_policy(self.home)
        self.assertNotIn("bit.ly", policy.denied_hosts)
        self.assertNotIn("iplogger.com", policy.denied_hosts)
        self.assertIn("tinyurl.com", policy.denied_hosts)


class FailClosedTest(TestHome):
    def test_an_unreadable_default_file_gives_no_policy(self) -> None:
        missing = self.home / "no-such-default-config.json"
        with patch.object(config, "DEFAULT_CONFIG_PATH", missing):
            self.assertIsNone(load_policy(self.home))

    def test_an_unparsable_default_file_gives_no_policy(self) -> None:
        broken = self.home / "default-config.json"
        broken.write_text("{", encoding="utf-8")
        with patch.object(config, "DEFAULT_CONFIG_PATH", broken):
            self.assertIsNone(load_policy(self.home))

    def test_a_default_file_missing_a_list_gives_no_policy(self) -> None:
        partial = self.home / "default-config.json"
        partial.write_text(json.dumps({"shellCommandRules": {"allow": []}}), encoding="utf-8")
        with patch.object(config, "DEFAULT_CONFIG_PATH", partial):
            self.assertIsNone(load_policy(self.home))


class ConfigProblemTest(TestHome):
    def test_a_missing_or_valid_config_has_no_problem(self) -> None:
        self.assertIsNone(config_problem(self.home))
        self.write_user_config({"harnessConfigRepository": {"path": "~/x", "launcherDirs": ["h"]}})
        self.assertIsNone(config_problem(self.home))

    def test_an_unparsable_config_is_reported(self) -> None:
        self.write_user_config("{not json")
        self.assertEqual(config_problem(self.home), "config.json does not parse")

    def test_an_unknown_harness_repository_key_is_reported(self) -> None:
        self.write_user_config({"harnessConfigRepository": {"path": "~/x", "vibeSettingsDirs": []}})
        self.assertEqual(config_problem(self.home), "unknown config key vibeSettingsDirs")


if __name__ == "__main__":
    unittest.main()
