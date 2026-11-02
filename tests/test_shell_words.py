"""Tests for aegys/shell_words.py: splitting a shell command into stages, unwrapping
wrapper commands, and the program sets the command checks use."""
from __future__ import annotations

import unittest
from pathlib import Path

from aegys import shell_words as words


class SplitStagesTest(unittest.TestCase):
    def test_pipelines_and_chains_split_into_stages(self) -> None:
        self.assertEqual(
            words.split_stages("git log | head -n 3"),
            [["git", "log"], ["head", "-n", "3"]],
        )
        self.assertEqual(
            words.split_stages("cd src && git status; ls"),
            [["cd", "src"], ["git", "status"], ["ls"]],
        )

    def test_a_newline_separates_commands(self) -> None:
        self.assertEqual(words.split_stages("ls\npwd"), [["ls"], ["pwd"]])

    def test_quoted_separators_stay_inside_their_word(self) -> None:
        self.assertEqual(
            words.split_stages("git commit -m 'a; b | c'"),
            [["git", "commit", "-m", "a; b | c"]],
        )

    def test_process_substitution_starts_a_stage(self) -> None:
        self.assertEqual(
            words.split_stages("diff <(ls a) <(ls b)"),
            [["diff"], ["ls", "a"], ["ls", "b"]],
        )

    def test_comments_are_dropped_unless_asked_to_keep_them(self) -> None:
        self.assertEqual(words.split_stages("ls # note"), [["ls"]])
        self.assertEqual(
            words.split_stages("ls # note", comments=False), [["ls", "#", "note"]]
        )

    def test_an_unbalanced_quote_does_not_parse(self) -> None:
        with self.assertRaises(ValueError):
            words.split_stages("echo 'open")


class UnwrapTest(unittest.TestCase):
    def test_assignments_and_env_options_are_stripped(self) -> None:
        self.assertEqual(
            words.unwrap(["FOO=1", "env", "-u", "BAR", "git", "status"]),
            (["git", "status"], None),
        )

    def test_keywords_and_function_headers_are_stripped(self) -> None:
        self.assertEqual(words.unwrap(["if", "git", "push"]), (["git", "push"], None))
        self.assertEqual(
            words.unwrap(["function", "f", "{", "git", "push"]), (["git", "push"], None)
        )
        self.assertEqual(words.unwrap(["done"]), ([], None))
        self.assertEqual(words.unwrap(["fi"]), ([], None))
        self.assertEqual(words.unwrap(["esac"]), ([], None))
        self.assertEqual(words.unwrap(["}"]), ([], None))
        self.assertEqual(
            words.unwrap(["for", "f", "in", "a.json", "b.json"]),
            (["for", "a.json", "b.json"], None),
        )
        self.assertEqual(words.unwrap(["for", "f"]), ([], None))
        self.assertEqual(
            words.unwrap(["for", "f", "do", "rm", "-rf", "~"]),
            (["rm", "-rf", "~"], None),
        )
        self.assertEqual(
            words.unwrap(["select", "opt", "in", "x", "y"]),
            (["select", "x", "y"], None),
        )
        self.assertEqual(
            words.unwrap(["select", "opt", "do", "rm", "-rf", "~"]),
            (["rm", "-rf", "~"], None),
        )
        self.assertEqual(words.unwrap(["case", "$x", "in"]), (["case", "$x"], None))

    def test_a_timeout_duration_is_skipped(self) -> None:
        self.assertEqual(words.unwrap(["timeout", "5", "rm", "x"]), (["rm", "x"], None))

    def test_an_option_value_of_a_wrapper_is_skipped(self) -> None:
        self.assertEqual(
            words.unwrap(["xargs", "-I", "{}", "rm", "{}"]), (["rm", "{}"], None)
        )

    def test_a_redirect_of_git_or_node_is_a_denial(self) -> None:
        self.assertEqual(
            words.unwrap(["GIT_DIR=/x", "git", "status"]),
            ([], "GIT_DIR redirects git or node; not needed here"),
        )

    def test_env_alone_prints_the_environment(self) -> None:
        self.assertEqual(words.unwrap(["env"]), ([], words.ENV_DUMP_WHY))


class ProgramSetsTest(unittest.TestCase):
    def test_writers_readers_and_printers(self) -> None:
        self.assertIn("rm", words.WRITERS)
        self.assertNotIn("rm", words.READERS)
        self.assertIn("cat", words.READERS)
        self.assertIn("rg", words.SEARCHERS)
        self.assertIn("rg", words.READERS)
        self.assertIn("echo", words.PRINTERS)


class GitHelpersTest(unittest.TestCase):
    def test_git_config_reads_and_writes(self) -> None:
        self.assertFalse(words.git_config_writes(["--get"], ["user.name"]))
        self.assertFalse(words.git_config_writes([], ["get", "user.name"]))
        self.assertFalse(words.git_config_writes([], ["user.name"]))
        self.assertTrue(words.git_config_writes([], ["user.name", "Ann"]))
        self.assertTrue(words.git_config_writes([], ["set", "a", "b"]))
        self.assertTrue(words.git_config_writes(["--unset"], ["core.x"]))

    def test_the_subcommand_follows_git_options(self) -> None:
        self.assertEqual(words.git_subcommand_index(["-C", "dir", "status"]), 2)
        self.assertEqual(words.git_subcommand_index(["--no-pager", "log"]), 1)
        self.assertIsNone(words.git_subcommand_index(["--no-pager"]))


class StringHelpersTest(unittest.TestCase):
    def test_brace_alternatives_expand(self) -> None:
        self.assertEqual(words.brace_expansions("a{b,c}d"), ["abd", "acd"])
        self.assertEqual(words.brace_expansions("plain"), ["plain"])
        self.assertEqual(
            words.brace_expansions("{a,b}{c,d}"), ["ac", "ad", "bc", "bd"]
        )

    def test_brace_expansion_stops_at_the_limit(self) -> None:
        self.assertEqual(words.brace_expansions("{a,b}{c,d}", limit=3), ["ac", "ad", "bc"])

    def test_inside_includes_the_root_and_its_children_only(self) -> None:
        root = Path("/a")
        self.assertTrue(words.inside(Path("/a"), root))
        self.assertTrue(words.inside(Path("/a/b"), root))
        self.assertFalse(words.inside(Path("/ab"), root))


if __name__ == "__main__":
    unittest.main()
