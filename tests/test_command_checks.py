"""Tests for aegys/command_checks.py: the URLs the guard checks in a command."""
from __future__ import annotations

import unittest

from aegys.command_checks import urls_in


class UrlsInTest(unittest.TestCase):
    def test_full_urls_are_found(self) -> None:
        self.assertEqual(
            list(urls_in({"command": "curl https://evil.example/x"})),
            ["https://evil.example/x"],
        )

    def test_a_bare_host_is_not_a_url(self) -> None:
        self.assertEqual(list(urls_in({"url": "evil.example"})), [])
        self.assertEqual(list(urls_in({"url": "https://evil.example/x"})), ["https://evil.example/x"])


if __name__ == "__main__":
    unittest.main()
