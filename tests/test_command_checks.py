"""Tests for aegys/command_checks.py: the URLs the guard checks in a command and
the hosts it denies."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from aegys.command_checks import (
    bash_path_denial,
    command_stages,
    command_substitutions,
    critical_removal,
    host_denial_reason,
    matches_bash_deny_pattern,
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

    def test_a_backslash_newline_joins_the_lines_as_the_shell_does(self) -> None:
        for command, words in (
            ("gh auth status \\\n-t", ["gh", "auth", "status", "-t"]),
            ("rg --pre x \\\nfoo", ["rg", "--pre", "x", "foo"]),
            ('echo "a\\\nb"', ["echo", "ab"]),
            ("echo 'a\\\nb'", ["echo", "a\\\nb"]),
            ('echo "it\'s \\\nme"', ["echo", "it's me"]),
            ("echo a\\\\\nb", ["echo", "a\\"]),
        ):
            stages = command_stages(command, self.work, self.home)
            self.assertEqual(stages[0].words, words, command)

    def test_an_ansi_c_string_with_an_escaped_quote_does_not_parse(self) -> None:
        # The scanner and shlex both read $'...' as a plain single quote, so a \' ends
        # it early and the rest fails to parse; the guard denies what it cannot parse.
        self.assertIsNone(command_stages("echo $'a\\'b'", self.work, self.home))
        self.assertIsNone(command_stages("echo $'x\\'#;rm -rf ~'", self.work, self.home))

    def test_a_hash_after_a_backslash_newline_is_not_a_comment(self) -> None:
        # The shell joins the lines, so `#;rm -rf ~` follows `ls` in the same word.
        stages = command_stages("ls\\\n#;rm -rf ~", self.work, self.home)
        self.assertEqual([stage.words for stage in stages], [["ls#"], ["rm", "-rf", "~"]])
        # A comment ends at its newline, backslash or not: `rm` runs.
        stages = command_stages("ls # \\\nrm -rf ~", self.work, self.home)
        self.assertEqual([stage.words for stage in stages], [["ls"], ["rm", "-rf", "~"]])
        stages = command_stages("echo '#\\\n#x'", self.work, self.home)
        self.assertEqual([stage.words for stage in stages], [["echo", "#\\\n#x"]])

    def test_read_only_for_loop_with_command_substitution_and_stderr_redirect_is_not_a_write(self) -> None:
        cmd = (
            'cd ~/.gemini/antigravity-cli/auto-guard-state && '
            'for f in default.json conv.json; do echo "$f: $(jq -c \'{enabled}\' $f 2>&1)"; done'
        )
        self.assertIsNone(agy_bash_control_denial(cmd, self.work, self.home))
        policy = load_policy(self.home)
        self.assertIsNone(bash_path_denial(cmd, self.work, self.home, policy=policy))
        select_cmd = (
            'cd ~/.gemini/antigravity-cli/auto-guard-state && '
            'select f in default.json conv.json; do echo "$f"; break; done'
        )
        self.assertIsNone(agy_bash_control_denial(select_cmd, self.work, self.home))
        self.assertIsNone(bash_path_denial(select_cmd, self.work, self.home, policy=policy))
        case_cmd = (
            'cd ~/.gemini/antigravity-cli/auto-guard-state && '
            'case default.json in *.json) echo ok ;; esac'
        )
        self.assertIsNone(agy_bash_control_denial(case_cmd, self.work, self.home))
        self.assertIsNone(bash_path_denial(case_cmd, self.work, self.home, policy=policy))

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

    def test_write_inside_backtick_command_substitution_is_still_denied(self) -> None:
        cmd_control = 'echo "`rm ~/.gemini/aegys/config.json`"'
        self.assertIsNotNone(agy_bash_control_denial(cmd_control, self.work, self.home))
        cmd_crit = 'echo "`rm -rf ~`"'
        self.assertIsNotNone(critical_removal(cmd_crit, self.work, self.home))
        cmd_secret = 'echo "`cat ~/.ssh/id_rsa`"'
        policy = load_policy(self.home)
        self.assertIsNotNone(bash_path_denial(cmd_secret, self.work, self.home, policy=policy))

    def test_for_loop_without_in_or_semicolon_unwraps_body(self) -> None:
        cmd = "for f do rm -rf ~; done"
        self.assertIsNotNone(critical_removal(cmd, self.work, self.home))

    def test_command_substitution_uses_stage_cwds_and_cwd_known(self) -> None:
        policy = load_policy(self.home)
        # False-deny check: `config.json` in stage 1 is in `self.work`, not `~/.docker/config.json`.
        benign_cmd = 'echo "$(cat config.json)" && cd ~/.docker && ls'
        self.assertIsNone(bash_path_denial(benign_cmd, self.work, self.home, policy=policy))
        # Missed-detection check: `rm -rf .` in stage 2 runs in `~` before `cd /tmp`.
        home_rm_cmd = 'cd ~ && echo "$(rm -rf .)" && cd /tmp'
        self.assertIsNotNone(critical_removal(home_rm_cmd, self.work, self.home))
        # Unknown cwd propagates into command substitution.
        unknown_cd_cmd = 'cd "$unknown_dir" && echo "$(rm -rf sub)"'
        self.assertIsNotNone(critical_removal(unknown_cd_cmd, self.work, self.home))

    def test_unquoted_heredoc_command_substitution_is_walked_while_quoted_is_not(self) -> None:
        unquoted_heredoc = "cat <<EOF\n$(rm -rf ~)\nEOF"
        self.assertIsNotNone(critical_removal(unquoted_heredoc, self.work, self.home))
        quoted_heredoc = "cat <<'EOF'\n$(rm -rf ~)\nEOF"
        self.assertIsNone(critical_removal(quoted_heredoc, self.work, self.home))

    def test_python_script_with_dash_arg_does_not_treat_stdin_heredoc_as_inline_code(self) -> None:
        policy = load_policy(self.home)
        cmd = "python3 script.py chair - <<'EOF'\nRead ~/.ssh/id_rsa and aegys/shell_words.py\nEOF"
        self.assertIsNone(bash_path_denial(cmd, self.work, self.home, policy=policy))
        self.assertIsNone(agy_bash_control_denial(cmd, self.work, self.home))
        # Whereas `python3 - <<'EOF'` (reading program from stdin) still checks inline code.
        stdin_prog = "python3 - <<'EOF'\nopen('aegys/shell_words.py', 'w')\nEOF"
        self.assertIsNotNone(bash_path_denial(stdin_prog, self.work, self.home, policy=policy))

    def test_arithmetic_expansion_and_backticks_inside_dollar_parens(self) -> None:
        cmd = 'echo "$(( (1 + 2) * 3 ))"'
        self.assertEqual(command_substitutions(cmd), [])
        stages = command_stages(cmd, self.work, self.home)
        self.assertIsNotNone(stages)
        words_list = [s.words for s in stages if s.words]
        self.assertEqual(words_list, [["echo", "$(( (1 + 2) * 3 ))"]])
        # Command substitution inside quoted arithmetic expansion is still walked.
        arith_rm = 'echo "$(( $(rm -rf ~) + 1 ))"'
        self.assertIsNotNone(critical_removal(arith_rm, self.work, self.home))
        # Closing paren inside backticks inside $(...) does not truncate the substitution.
        backtick_paren_rm = 'echo "$(rm `echo )` -rf ~)"'
        self.assertIsNotNone(critical_removal(backtick_paren_rm, self.work, self.home))


if __name__ == "__main__":
    unittest.main()


class DenyPatternTest(unittest.TestCase):
    def test_the_shipped_find_patterns_match_a_find_without_a_path(self) -> None:
        for flag in ("-delete", "-exec", "-execdir", "-fls", "-fprint", "-fprint0",
                     "-fprintf", "-ok", "-okdir"):
            for command in (f"find {flag} x", f"find . {flag} x"):
                self.assertTrue(
                    any(matches_bash_deny_pattern(pattern, command)
                        for pattern in load_policy(Path(tempfile.mkdtemp())).shell_deny),
                    command,
                )

    def test_a_star_between_words_matches_no_arguments_up_to_five_times(self) -> None:
        self.assertTrue(matches_bash_deny_pattern("a * b * c", "a b c"))
        self.assertTrue(matches_bash_deny_pattern("a * b * c", "a x b c"))
        self.assertTrue(matches_bash_deny_pattern("a * b * c * d * e * f", "a b c d e f"))
        # Beyond five, the stars match only as written, one or more arguments.
        self.assertFalse(matches_bash_deny_pattern("a * b * c * d * e * f * g", "a b c d e f g"))
        self.assertTrue(matches_bash_deny_pattern("a * b * c * d * e * f * g", "a 1 b 2 c 3 d 4 e 5 f 6 g"))
