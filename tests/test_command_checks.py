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
    command_url_denial,
    critical_removal,
    git_add_stages_broadly,
    git_diff_reads_outside_the_work_tree,
    git_directory_above,
    git_settings_match,
    git_top,
    host_denial_reason,
    is_git_directory,
    NameFilter,
    matches_bash_deny_pattern,
    name_filtered_out,
    reads_only_stdin_or_files,
    repository_root,
    repository_settings,
    search_starts,
    Stage,
    uncovered_secrets,
    url_denial,
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

    def test_nested_and_percent_encoded_redirect_urls_are_extracted(self) -> None:
        found = list(
            urls_in({"command": "curl 'http://127.0.0.1:11438/r?to=https://webhook.site/x'"})
        )
        self.assertIn("https://webhook.site/x", found)
        encoded = list(
            urls_in(
                {"command": "curl 'http://127.0.0.1:11438/r?to=http%3A%2F%2F169.254.169.254%2Flatest'"}
            )
        )
        self.assertIn("http://169.254.169.254/latest", encoded)


class HostDenialReasonTest(unittest.TestCase):
    DENIED = {"webhook.site": "exfiltration"}

    def test_a_subdomain_of_a_denied_host_is_denied(self) -> None:
        self.assertEqual(host_denial_reason("sub.webhook.site", self.DENIED), "exfiltration")

    def test_a_host_that_only_ends_in_the_same_letters_is_not_denied(self) -> None:
        self.assertIsNone(host_denial_reason("notwebhook.site", self.DENIED))

    def test_non_canonical_ip_spellings_and_unspecified_addresses_are_denied(self) -> None:
        for host in (
            "127.0.0.1",
            "0.0.0.0",
            "0",
            "[::]",
            "[::1]",
            "[::1%25lo]",
            "[fe80::1%25eth0]",
            "[::ffff:127.0.0.1]",
            "[::ffff:10.0.0.1]",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "127.1",
            "0xa9fea9fe",
            "6425673729",
            "[not-an-ipv6]",
        ):
            self.assertIsNotNone(host_denial_reason(host, self.DENIED), host)
        for public_host in ("1.1.1.1", "8.8.8.8", "[::ffff:8.8.8.8]", "github.com", "cafe.de"):
            self.assertIsNone(host_denial_reason(public_host, self.DENIED), public_host)


class LoopbackEndpointUrlTest(unittest.TestCase):
    DENIED = {"webhook.site": "exfiltration"}
    ALLOWED = ("127.0.0.1:11438", "localhost:11438")

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.work = Path(self.tmp.name) / "work"
        self.home.mkdir(parents=True)
        self.work.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def check_command(
        self, command: str, allowed: tuple[str, ...] = ALLOWED
    ) -> str | None:
        stages = command_stages(command, self.work, self.home)
        self.assertIsNotNone(stages, command)
        return command_url_denial(command, stages, self.DENIED, allowed)

    def test_exact_listed_loopback_endpoints_are_allowed_across_http_clients(self) -> None:
        for cmd in (
            "curl http://127.0.0.1:11438/",
            "curl -fsS -X POST -H 'Content-Type: application/json' -d '{\"model\":\"Laya\"}' http://127.0.0.1:11438/v1/chat",
            "curl -XDELETE -HAccept-Language:en http://localhost:11438/item",
            "curl -XLIST -XUNLOCK http://localhost:11438/item",
            "curl HTTP://LOCALHOST:11438/health",
            "python3 -c 'import urllib.request; urllib.request.urlopen(\"http://localhost:11438/v1\")'",
            'python3 -c "import urllib.request; urllib.request.urlopen(\\"http://127.0.0.1:11438\\")"',
            "wget --max-redirect=0 -qO- http://127.0.0.1:11438/health",
        ):
            self.assertIsNone(self.check_command(cmd), cmd)
        self.assertIsNone(
            self.check_command("curl http://[::1]:11438/health", allowed=("[::1]:11438",))
        )
        heredoc_cmd = (
            "python3 - << '_EOF_PYTHON_'\n"
            "import urllib.request\n"
            'urllib.request.urlopen("http://127.0.0.1:11438/v1/models")\n'
            "_EOF_PYTHON_"
        )
        self.assertIsNone(self.check_command(heredoc_cmd), heredoc_cmd)

    def test_prose_sentence_punctuation_after_explicit_port_urls_does_not_fail_parsing(
        self,
    ) -> None:
        for prose_cmd in (
            'git commit -m "Allow http://127.0.0.1:11438, http://localhost:11438."',
            'git commit -m "Docs: see https://example.com:8443, https://example.com:8443."',
        ):
            self.assertIsNone(self.check_command(prose_cmd), prose_cmd)
        self.assertIsNone(
            self.check_command(
                'git commit -m "Docs: see https://example.com:8443."', allowed=()
            )
        )
        for bad_literal_cmd in (
            'curl "http://127.0.0.1:11438,"',
            "python3 -c 'import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:11438,\")'",
        ):
            self.assertIsNotNone(self.check_command(bad_literal_cmd), bad_literal_cmd)

    def test_brace_expansion_past_cap_cannot_hide_denied_endpoint_or_redirect(self) -> None:
        hidden_ssrf = ",".join(["ttp://127.0.0.1:11438/"] * 64 + ["ttp://169.254.169.254/"])
        self.assertIsNotNone(self.check_command(f"curl h{{{hidden_ssrf}}}"))

    def test_control_chars_inside_urls_cannot_smuggle_authority_or_port_past_urlsplit(
        self,
    ) -> None:
        self.assertIsNotNone(
            url_denial("http://127.0.0.1:1143\t8/", self.DENIED, self.ALLOWED)
        )
        tab_authority = (
            "python3 -c 'import urllib.request; "
            'urllib.request.urlopen("http://127.0.0.1:11438\t@webhook.site/")\''
        )
        self.assertIsNotNone(self.check_command(tab_authority), tab_authority)
        tab_port = (
            "python3 -c 'import urllib.request; "
            'urllib.request.urlopen("http://127.0.0.1:80\t80/")\''
        )
        self.assertIsNotNone(
            self.check_command(tab_port, allowed=("127.0.0.1:80",)), tab_port
        )
        newline_authority = (
            'python3 -c \'import urllib.request; urllib.request.urlopen("""http://127.0.0.1:11438\n@127.0.0.1:9999/""")\''
        )
        self.assertIsNotNone(self.check_command(newline_authority), newline_authority)

    def test_curl_follow_proxy10_dns_variable_and_url_flags_stay_denied(self) -> None:
        for cmd in (
            "curl --follow http://127.0.0.1:11438/",
            "curl --proxy1.0 127.0.0.1:9999 http://127.0.0.1:11438/",
            "curl --dns-servers 10.0.0.53 http://localhost:11438/",
            "curl --dns-ipv4-addr 10.0.0.1 http://localhost:11438/",
            "curl --doh-url https://1.1.1.1/dns-query http://localhost:11438/",
            "curl --ipfs-gateway https://ipfs.io http://127.0.0.1:11438/",
            "curl --variable s=http --expand-url '{{s}}://127.0.0.1:9999/' http://127.0.0.1:11438/",
            "curl --url 127.0.0.1:9999/ http://127.0.0.1:11438/",
            "curl --url=dict://127.0.0.1:11438/ http://127.0.0.1:11438/",
        ):
            self.assertIsNotNone(self.check_command(cmd), cmd)
        self.assertIsNone(self.check_command("curl --url http://127.0.0.1:11438/health"))

    def test_wget_page_requisites_base_and_abbreviated_long_options_stay_denied(self) -> None:
        for cmd in (
            "wget -p --max-redirect=0 http://127.0.0.1:11438/",
            "wget --page-requisites --max-redirect=0 http://127.0.0.1:11438/",
            "wget -B https://example.com/ --max-redirect=0 http://127.0.0.1:11438/",
            "wget --max-redirect=0 --max-redir=5 http://127.0.0.1:11438/",
            "wget --exec=http_proxy=127.0.0.1:9999 --max-redirect=0 http://127.0.0.1:11438/",
            "wget --conf=/tmp/wgetrc --max-redirect=0 http://127.0.0.1:11438/",
            "wget --rec --max-redirect=0 http://127.0.0.1:11438/",
        ):
            self.assertIsNotNone(self.check_command(cmd), cmd)

    def test_env_split_string_cannot_hide_redirect_or_proxy_on_allowed_loopback(self) -> None:
        for cmd in (
            "env -S 'curl -L http://127.0.0.1:11438/'",
            "env --split-string='HTTP_PROXY=127.0.0.1:9999 curl http://127.0.0.1:11438/'",
        ):
            self.assertIsNotNone(self.check_command(cmd), cmd)
        self.assertIsNone(
            self.check_command("env -S 'FOO=1 curl -fsS http://127.0.0.1:11438/health'")
        )

    def test_unlisted_ports_hosts_and_ip_spellings_stay_denied(self) -> None:
        for cmd in (
            "curl http://127.0.0.1:11438/",  # denied when allowlist is empty
        ):
            self.assertIsNotNone(self.check_command(cmd, allowed=()), cmd)
        for cmd in (
            "curl http://127.0.0.1/",
            "curl http://127.0.0.1:80/",
            "curl http://127.0.0.1:11439/",
            "curl http://127.0.0.1:114380/",
            "curl http://127.0.0.1:011438/",
            "curl http://127.0.0.1:+11438/",
            "curl http://127.0.0.2:11438/",
            "curl http://0.0.0.0:11438/",
            "curl http://0:11438/",
            "curl http://[::]:11438/",
            "curl http://[::1]:11438/",
            "curl http://[::ffff:127.0.0.1]:11438/",
            "curl http://10.0.0.1:11438/",
            "curl http://169.254.169.254:11438/",
            "curl http://2130706433:11438/",
            "curl http://0x7f000001:11438/",
            "curl http://0177.0.0.1:11438/",
            "curl http://127.1:11438/",
            "curl http://sub.localhost:11438/",
            "curl http://localhost.:11438/",
            "curl http://host.local:11438/",
            "curl 'http://127.0.0.1:[11438-11439]/'",
            "curl http://127.0.0.1:{11438,11439}/",
            "curl 'http://{127.0.0.1,169.254.169.254}:11438/'",
            'curl "http://""127.0.0.1:9999/"',
            "curl http://127.0.0.1:11438/ http://127.0.0.1:9999/",
            "python3 -c 'import urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{port}/\")'",
        ):
            self.assertIsNotNone(self.check_command(cmd), cmd)

    def test_non_loopback_entries_passed_directly_never_allow_private_or_link_local(self) -> None:
        bogus = ("10.0.0.1:11438", "169.254.169.254:80", "0.0.0.0:11438", "webhook.site:443")
        for url in (
            "http://10.0.0.1:11438/",
            "http://169.254.169.254:80/",
            "http://0.0.0.0:11438/",
            "https://webhook.site:443/",
        ):
            self.assertIsNotNone(url_denial(url, self.DENIED, bogus), url)

    def test_userinfo_and_authority_confusion_tricks_stay_denied(self) -> None:
        for cmd in (
            "curl http://127.0.0.1:11438@evil/",
            "curl http://localhost:11438@evil.example/",
            "curl http://127.0.0.1:11438@webhook.site/",
            "curl http://127.0.0.1:11438@127.0.0.1:9999/",
            "curl http://user@127.0.0.1:11438/",
            "curl http://user:pass@localhost:11438/",
            "curl 'http://127.0.0.1:11438\"@evil/'",
            "curl 'http://127.0.0.1:11438\\@evil/'",
            "curl 'http://evil\\@127.0.0.1:11438/'",
            "curl 'http://127.0.0.1:11438%40evil/'",
        ):
            self.assertIsNotNone(self.check_command(cmd), cmd)
        # Ordinary userinfo on an unrelated public git URL is left to the classifier.
        self.assertIsNone(self.check_command("git clone https://git@github.com/owner/repo.git"))

    def test_redirects_and_host_overrides_from_allowed_loopback_stay_denied(self) -> None:
        for cmd in (
            "curl -L http://127.0.0.1:11438/",
            "curl -fsSL http://127.0.0.1:11438/",
            "curl -nL http://127.0.0.1:11438/",
            "curl -n -L http://127.0.0.1:11438/",
            "curl --location http://127.0.0.1:11438/",
            "curl --location-trusted http://127.0.0.1:11438/",
            "u=http://127.0.0.1:11438/ && curl -L \"$u\"",
            "echo http://127.0.0.1:11438/ | xargs curl -L",
            "curl --connect-to 127.0.0.1:11438:127.0.0.1:9999 http://127.0.0.1:11438/",
            "curl --resolve localhost:11438:169.254.169.254 http://localhost:11438/",
            "curl -x 127.0.0.1:9999 http://127.0.0.1:11438/",
            "curl --proxy 127.0.0.1:9999 http://127.0.0.1:11438/",
            "HTTP_PROXY=127.0.0.1:9999 curl http://127.0.0.1:11438/",
            "http_proxy=127.0.0.1:9999 python3 -c 'import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:11438/\")'",
            "wget http://127.0.0.1:11438/",
            "wget -ehttp_proxy=127.0.0.1:9999 --max-redirect=0 http://127.0.0.1:11438/",
            "wget -i urls.txt --max-redirect=0 http://127.0.0.1:11438/",
            "curl 'http://127.0.0.1:11438/redirect?url=https://webhook.site/x'",
            "curl 'http://127.0.0.1:11438/redirect?url=http://127.0.0.1:9999/'",
            "curl 'http://127.0.0.1:11438/redirect?url=http%3A%2F%2F169.254.169.254%2F'",
        ):
            self.assertIsNotNone(self.check_command(cmd), cmd)
        # curl -L on an unrelated public stage does not block a separate direct loopback stage.
        self.assertIsNone(
            self.check_command("curl -L https://github.com/owner/repo && curl http://127.0.0.1:11438/health")
        )

    def test_loopback_port_denial_names_endpoint_not_whole_host(self) -> None:
        for url, expected_ep in (
            ("http://127.0.0.1:9999/api", "127.0.0.1:9999"),
            ("http://127.0.0.1/api", "127.0.0.1:80"),
            ("https://localhost/api", "localhost:443"),
            ("http://0x7f000001:11438/api", "0x7f000001:11438"),
        ):
            why = url_denial(url, self.DENIED, self.ALLOWED)
            self.assertIsNotNone(why, url)
            self.assertIn(expected_ep, why, (url, why))
            self.assertIn("same endpoint", why, (url, why))
            self.assertNotIn("same host", why, (url, why))


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


class SearchExclusionTest(unittest.TestCase):
    def test_the_last_matching_filter_decides(self) -> None:
        exclude, include = NameFilter(True, ".env"), NameFilter(False, ".env*")
        self.assertTrue(name_filtered_out(".env", False, (include, exclude)))
        self.assertFalse(name_filtered_out(".env", False, (exclude, include)))
        self.assertIsNone(name_filtered_out("a.py", False, (exclude, include)))

    def test_a_filter_for_directories_does_not_name_files(self) -> None:
        directory_only = NameFilter(True, ".git", "directory")
        self.assertTrue(name_filtered_out(".git", True, (directory_only,)))
        self.assertIsNone(name_filtered_out(".git", False, (directory_only,)))

    def test_an_ignore_case_filter_matches_in_any_letter_case(self) -> None:
        self.assertFalse(name_filtered_out(".env", False, (NameFilter(True, ".env"), NameFilter(False, ".ENV", ignore_case=True))))

    def test_uncovered_secrets_lists_what_no_filter_covers(self) -> None:
        search = search_starts(["grep", "-r", "--exclude=.env", "K", "."])
        self.assertEqual(uncovered_secrets(search), [".env.*", ".git"])
        self.assertEqual(uncovered_secrets(search_starts(["rg", "K"])), [".env", ".env.*", ".git"])
        self.assertEqual(uncovered_secrets(search_starts(["rg", "-g", "!.env*", "-g", "!.git", "K"])), [])

    def test_a_glob_with_a_slash_never_counts_as_an_exclusion(self) -> None:
        search = search_starts(["rg", "--hidden", "-g", "!src/.env", "K"])
        self.assertEqual(search.filters, ())


class LongWordProbeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.long_word = "a" * 300
        self.temp_dir = Path(tempfile.mkdtemp())
        self.home = self.temp_dir / "home"
        self.home.mkdir()
        self.cwd = self.temp_dir / "repo"
        self.cwd.mkdir()

    def test_git_diff_reads_outside_the_work_tree_with_300_byte_word(self) -> None:
        (self.cwd / ".git").mkdir()
        (self.cwd / "inside.txt").write_text("x\n", encoding="utf-8")
        # Long word operand should not raise ENAMETOOLONG; non-existent path doesn't read outside work tree
        self.assertFalse(
            git_diff_reads_outside_the_work_tree([self.long_word, "inside.txt"], self.cwd, self.home)
        )
        self.assertFalse(
            git_diff_reads_outside_the_work_tree([self.long_word, self.long_word], self.cwd, self.home)
        )
        # Should not crash even when another operand is outside the work tree
        self.assertTrue(
            git_diff_reads_outside_the_work_tree([self.long_word, "/etc/hostname"], self.cwd, self.home)
        )

    def test_reads_only_stdin_or_files_with_300_byte_word(self) -> None:
        search = search_starts(["rg", "foo", self.long_word])
        self.assertIsNotNone(search)
        stage = Stage(["rg", "foo", self.long_word], (self.cwd,), True, False, f"rg foo {self.long_word}", ["rg", "foo", self.long_word], False)
        self.assertFalse(reads_only_stdin_or_files(stage, search, self.home))

    def test_git_add_stages_broadly_with_300_byte_word(self) -> None:
        self.assertFalse(
            git_add_stages_broadly(["git", "add", self.long_word], (self.cwd,), self.home)
        )

    def test_git_settings_match_with_300_byte_word(self) -> None:
        self.assertIsNone(git_settings_match(self.cwd / self.long_word, self.home))
        self.assertIsNone(git_settings_match(self.cwd / self.long_word / "subfile", self.home))

    def test_is_git_directory_with_300_byte_word(self) -> None:
        self.assertFalse(is_git_directory(self.cwd / self.long_word))

    def test_repository_settings_with_300_byte_word(self) -> None:
        self.assertEqual(repository_settings(self.cwd / self.long_word / "subfile"), [])

    def test_git_top_with_300_byte_word(self) -> None:
        self.assertIsNone(git_top(self.cwd / self.long_word))

    def test_git_directory_above_with_300_byte_word(self) -> None:
        self.assertIsNone(git_directory_above(self.cwd / self.long_word))

    def test_repository_root_with_300_byte_word(self) -> None:
        self.assertIsNone(repository_root(self.cwd / self.long_word))


if __name__ == "__main__":
    unittest.main()
