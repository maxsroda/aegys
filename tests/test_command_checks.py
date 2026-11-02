"""Tests for aegys/command_checks.py: the URLs the guard checks in a command and
the hosts it denies."""
from __future__ import annotations

import unittest

from aegys.command_checks import host_denial_reason, urls_in


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


if __name__ == "__main__":
    unittest.main()
