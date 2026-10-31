"""Tests for aegys/config.py: the shipped policy lists merged with the user's config."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegys import config
from aegys.config import config_problem, load_policy


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

    def test_no_user_config_gives_the_defaults(self) -> None:
        policy = load_policy(self.home)
        self.assertIn("git status*", policy.shell_allow)
        self.assertIn("gh repo delete*", policy.shell_deny)
        self.assertIn("webhook.site", policy.denied_hosts)
        self.assertIn("*/.netrc", policy.secret_paths)

    def test_shipped_entries_are_stripped_and_empty_ones_dropped(self) -> None:
        shipped = json.loads(config.DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))
        shipped["secretPaths"] = ["", "  */.padded/*  "]
        path = self.home / "default-config.json"
        path.write_text(json.dumps(shipped), encoding="utf-8")
        with patch.object(config, "DEFAULT_CONFIG_PATH", path):
            policy = load_policy(self.home)
        self.assertEqual(policy.secret_paths, ("*/.padded/*",))


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

    def test_remove_defaults_also_removes_the_users_own_entries(self) -> None:
        self.write_user_config({
            "shellCommandRules": {"allow": ["mytool --check*"]},
            "removeDefaults": {"shellCommandRules": {"allow": ["mytool --check*"]}},
        })
        self.assertNotIn("mytool --check*", load_policy(self.home).shell_allow)

    def test_remove_defaults_for_shell_rules_only_touches_the_named_list(self) -> None:
        self.write_user_config({"removeDefaults": {"shellCommandRules": {"deny": ["gh repo delete*"]}}})
        policy = load_policy(self.home)
        self.assertNotIn("gh repo delete*", policy.shell_deny)
        self.assertIn("git status*", policy.shell_allow)

    def test_remove_defaults_matches_shell_rules_spelled_exactly(self) -> None:
        self.write_user_config({"removeDefaults": {"shellCommandRules": {"allow": ["GIT STATUS*"]}}})
        self.assertIn("git status*", load_policy(self.home).shell_allow)

    def test_remove_defaults_matches_host_names_in_any_case(self) -> None:
        self.write_user_config({"removeDefaults": {"deniedHosts": ["BIT.LY"]}})
        self.assertNotIn("bit.ly", load_policy(self.home).denied_hosts)

    def test_duplicates_collapse(self) -> None:
        self.write_user_config({
            "shellCommandRules": {"allow": ["git status*", "git status*", "mytool*", "mytool*"]},
        })
        policy = load_policy(self.home)
        self.assertEqual(policy.shell_allow.count("git status*"), 1)
        self.assertEqual(policy.shell_allow.count("mytool*"), 1)

    def test_user_entries_are_stripped_and_empty_ones_dropped(self) -> None:
        self.write_user_config({"shellCommandRules": {"allow": ["  mytool*  ", ""]}})
        policy = load_policy(self.home)
        self.assertIn("mytool*", policy.shell_allow)
        self.assertNotIn("", policy.shell_allow)

    def test_a_user_can_name_a_new_reason_for_hosts(self) -> None:
        self.write_user_config({"deniedHosts": {"my reason": ["Evil.Example"]}})
        self.assertEqual(load_policy(self.home).denied_hosts["evil.example"], "my reason")

    def test_remove_defaults_for_hosts_is_one_flat_list(self) -> None:
        self.write_user_config({"removeDefaults": {"deniedHosts": ["bit.ly", "iplogger.com"]}})
        policy = load_policy(self.home)
        self.assertNotIn("bit.ly", policy.denied_hosts)
        self.assertNotIn("iplogger.com", policy.denied_hosts)
        self.assertIn("tinyurl.com", policy.denied_hosts)

    def test_a_secret_path_starting_with_a_tilde_is_read_from_home(self) -> None:
        self.write_user_config({"secretPaths": ["~/.mysecret/*"]})
        self.assertIn(f"{self.home.resolve()}/.mysecret/*", load_policy(self.home).secret_paths)

    def test_remove_defaults_matches_a_tilde_secret_path_as_written_in_the_user_config(self) -> None:
        self.write_user_config({
            "secretPaths": ["~/.mysecret/*"],
            "removeDefaults": {"secretPaths": ["~/.mysecret/*"]},
        })
        policy = load_policy(self.home)
        self.assertNotIn(f"{self.home.resolve()}/.mysecret/*", policy.secret_paths)
        self.assertNotIn("~/.mysecret/*", policy.secret_paths)


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

    def test_an_unparsable_user_config_holds_the_policy(self) -> None:
        self.write_user_config("{not json")
        self.assertIsNone(load_policy(self.home))

    def test_an_unknown_key_holds_the_policy(self) -> None:
        self.write_user_config({"secretpaths": ["*/.mysecret/*"]})
        self.assertIsNone(load_policy(self.home))

    def test_a_wrong_typed_value_holds_the_policy(self) -> None:
        self.write_user_config({"removeDefaults": "everything"})
        self.assertIsNone(load_policy(self.home))

    def test_a_non_string_entry_holds_the_policy(self) -> None:
        self.write_user_config({"shellCommandRules": {"allow": ["git status*", 7]}})
        self.assertIsNone(load_policy(self.home))


class ConfigProblemTest(TestHome):
    def test_a_missing_or_valid_config_has_no_problem(self) -> None:
        self.assertIsNone(config_problem(self.home))
        self.write_user_config({"harnessConfigRepository": {"path": "~/x", "launcherDirs": ["h"]}})
        self.assertIsNone(config_problem(self.home))

    def test_every_known_key_with_the_right_type_has_no_problem(self) -> None:
        self.write_user_config({
            "classifierModel": "anthropic/claude-haiku-5-5",
            "anthropicBaseUrl": "https://api.anthropic.com",
            "harnessConfigRepository": {
                "path": "~/harness-config", "launcherDirs": ["hooks"], "scriptDirs": ["scripts"],
                "harnessSettingsDirs": ["h"], "permissionSettingsDirs": ["p"],
                "controlSpellings": ["bin/x.sh"],
            },
            "removeDefaults": {
                "shellCommandRules": {"allow": [], "ask": [], "deny": []},
                "allowWhileGuardOff": [], "deniedHosts": [], "secretPaths": [],
            },
            "shellCommandRules": {"allow": ["a*"], "ask": ["b*"], "deny": ["c*"]},
            "allowWhileGuardOff": ["d"],
            "deniedHosts": {"my reason": ["e.example"]},
            "secretPaths": ["*/f"],
        })
        self.assertIsNone(config_problem(self.home))

    def test_an_unparsable_config_is_reported(self) -> None:
        self.write_user_config("{not json")
        self.assertEqual(config_problem(self.home), "config.json does not parse")

    def test_a_config_that_is_not_an_object_is_reported(self) -> None:
        self.write_user_config("[]")
        self.assertEqual(config_problem(self.home), "config.json is not a JSON object")

    def test_an_unknown_top_level_key_is_reported(self) -> None:
        self.write_user_config({"secretpaths": ["*/x"]})
        self.assertEqual(config_problem(self.home), "unknown config key secretpaths")

    def test_an_unknown_harness_repository_key_is_reported(self) -> None:
        self.write_user_config({"harnessConfigRepository": {"path": "~/x", "vibeSettingsDirs": []}})
        self.assertEqual(config_problem(self.home), "unknown config key vibeSettingsDirs")

    def test_a_list_key_that_is_not_a_list_of_strings_is_reported(self) -> None:
        self.write_user_config({"secretPaths": "*/x"})
        self.assertEqual(config_problem(self.home), "secretPaths is not a list of strings")
        self.write_user_config({"allowWhileGuardOff": ["ok", 3]})
        self.assertEqual(config_problem(self.home), "allowWhileGuardOff is not a list of strings")

    def test_a_section_that_is_not_an_object_is_reported(self) -> None:
        for key in ("shellCommandRules", "deniedHosts", "removeDefaults", "harnessConfigRepository"):
            self.write_user_config({key: []})
            self.assertEqual(config_problem(self.home), f"{key} is not an object", key)

    def test_a_shell_rule_list_must_be_a_list_of_strings(self) -> None:
        self.write_user_config({"shellCommandRules": {"allow": "git status*"}})
        self.assertEqual(config_problem(self.home), "shellCommandRules.allow is not a list of strings")

    def test_an_unknown_shell_rule_kind_is_reported(self) -> None:
        self.write_user_config({"shellCommandRules": {"allows": []}})
        self.assertEqual(config_problem(self.home), "unknown key allows in shellCommandRules")

    def test_a_denied_host_reason_must_hold_a_list_of_strings(self) -> None:
        self.write_user_config({"deniedHosts": {"my reason": "evil.example"}})
        self.assertEqual(config_problem(self.home), "deniedHosts.my reason is not a list of strings")

    def test_an_unknown_key_in_remove_defaults_is_reported(self) -> None:
        self.write_user_config({"removeDefaults": {"secretpaths": []}})
        self.assertEqual(config_problem(self.home), "unknown key secretpaths in removeDefaults")

    def test_remove_defaults_shell_rules_are_checked(self) -> None:
        self.write_user_config({"removeDefaults": {"shellCommandRules": {"deny": "x"}}})
        self.assertEqual(
            config_problem(self.home),
            "removeDefaults.shellCommandRules.deny is not a list of strings",
        )

    def test_the_harness_path_must_be_a_string(self) -> None:
        self.write_user_config({"harnessConfigRepository": {"path": ["~/x"]}})
        self.assertEqual(config_problem(self.home), "harnessConfigRepository.path is not a string")

    def test_the_harness_list_keys_must_be_lists_of_strings(self) -> None:
        self.write_user_config({"harnessConfigRepository": {"path": "~/x", "launcherDirs": "h"}})
        self.assertEqual(
            config_problem(self.home),
            "harnessConfigRepository.launcherDirs is not a list of strings",
        )

    def test_the_classifier_settings_must_be_strings(self) -> None:
        self.write_user_config({"classifierModel": 3})
        self.assertEqual(config_problem(self.home), "classifierModel is not a string")
        self.write_user_config({"anthropicBaseUrl": ["x"]})
        self.assertEqual(config_problem(self.home), "anthropicBaseUrl is not a string")

    def test_the_policy_problem_names_the_config_file_and_the_problem(self) -> None:
        self.write_user_config({"secretpaths": ["*/x"]})
        self.assertEqual(
            config.policy_problem(self.home),
            f"{self.home / '.gemini' / 'aegys' / 'config.json'}: unknown config key secretpaths",
        )

    def test_the_policy_problem_is_none_without_a_problem(self) -> None:
        self.assertIsNone(config.policy_problem(self.home))


if __name__ == "__main__":
    unittest.main()
