"""README must state what the classifier receives and how search tools are gated."""
from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


class ReadmeClassifierInputsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    def test_readme_lists_what_the_classifier_receives(self) -> None:
        self.assertIn("What the classifier sees", self.readme)
        for name in ("AGENTS.md", "GEMINI.md", "CLAUDE.md"):
            self.assertIn(name, self.readme)
        self.assertIn("tool outputs", self.readme.lower())

    def test_readme_says_search_tools_leave_the_workspace_and_ignore_aegys_off(self) -> None:
        for tool in ("list_directory", "grep_search", "find"):
            self.assertIn(f"`{tool}`", self.readme)
        self.assertIn("outside the workspace", self.readme)
        self.assertIn("/aegys off", self.readme)


if __name__ == "__main__":
    unittest.main()
