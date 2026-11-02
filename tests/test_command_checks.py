"""Tests for aegys/command_checks.py: the URLs the guard checks in a command and
the hosts it denies."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from aegys.command_checks import (
    bash_path_denial,
    command_stages,
    critical_removal,
    host_denial_reason,
    urls_in,
)
from aegys.config import load_policy
from aegys.guard import agy_bash_control_denial


class UrlsInTest(unittest.TestCase):
    def test_full_urls_are_found(self) -> None:
        self.assertEqual(
            list(urls_in({"command": "curl https://evil.example/x"})),
            ["https://evil.example/x"],
        )

    def test_a_bare_host_is_not_a_url(self) -> None:
        self.assertEqual(list(urls_in({"url": "evil.example"})), [])
        self.assertEqual(list(urls_in({"url": "https://evil.example/x"})), ["https://evil.example/x"])


class HostDenialReasonTest(unittest.TestCase):
    DENIED = {"webhook.site": "exfiltration"}

    def test_a_subdomain_of_a_denied_host_is_denied(self) -> None:
        self.assertEqual(host_denial_reason("sub.webhook.site", self.DENIED), "exfiltration")

    def test_a_host_that_only_ends_in_the_same_letters_is_not_denied(self) -> None:
        self.assertIsNone(host_denial_reason("notwebhook.site", self.DENIED))


class CommandStagesAndSubstitutionsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.work = Path(self.tmp.name) / "work"
        self.home.mkdir(parents=True)
        self.work.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_read_only_for_loop_with_command_substitution_and_stderr_redirect_is_not_a_write(self) -> None:
        cmd = (
            'cd ~/.gemini/antigravity-cli/auto-guard-state && '
            'for f in default.json conv.json; do echo "$f: $(jq -c \'{enabled}\' $f 2>&1)"; done'
        )
        self.assertIsNone(agy_bash_control_denial(cmd, self.work, self.home))
        policy = load_policy(self.home)
        self.assertIsNone(bash_path_denial(cmd, self.work, self.home, policy=policy))

    def test_command_substitution_inside_quotes_is_walked_as_a_stage(self) -> None:
        stages = command_stages('echo "$(jq -c \'{enabled}\' default.json 2>&1)"', self.work, self.home)
        self.assertIsNotNone(stages)
        words_list = [s.words for s in stages if s.words]
        self.assertIn(["jq", "-c", "{enabled}", "default.json"], words_list)

    def test_write_inside_command_substitution_is_still_denied(self) -> None:
        cmd_control = 'echo "$(rm ~/.gemini/aegys/config.json)"'
        self.assertIsNotNone(agy_bash_control_denial(cmd_control, self.work, self.home))
        cmd_crit = 'echo "$(rm -rf ~)"'
        self.assertIsNotNone(critical_removal(cmd_crit, self.work, self.home))
        cmd_secret = 'echo "$(cat ~/.ssh/id_rsa)"'
        policy = load_policy(self.home)
        self.assertIsNotNone(bash_path_denial(cmd_secret, self.work, self.home, policy=policy))
        cmd_for_secret = 'for f in ~/.ssh/id_rsa; do echo "$f"; done'
        self.assertIsNotNone(bash_path_denial(cmd_for_secret, self.work, self.home, policy=policy))


if __name__ == "__main__":
    unittest.main()
