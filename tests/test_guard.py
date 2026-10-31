"""Tests for the Antigravity CLI (agy) PreToolUse aegys guard and classifier."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from aegys.guard import (
    CLASSIFIER_DECISION_TOOL_NAME,
    anthropic_messages_call,
    build_classifier_system_prompt,
    build_classifier_transcript,
    evaluate_pre_tool_use,
    format_status_line,
    guard_enabled,
    pre_invocation_response,
    load_guard_state,
)

# The checkout root: the tests run from here, so `python -m aegys.guard` imports this package.
REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = REPO_ROOT / "aegys"
# The harness config repository every test home declares in ~/.gemini/aegys/config.json.
HARNESS_CONFIG_REPOSITORY = {
    "path": "~/harness-config",
    "launcherDirs": ["hooks", "bin"],
    "scriptDirs": ["scripts"],
    "harnessSettingsDirs": ["harness-settings"],
    "permissionSettingsDirs": ["permission-settings"],
    "controlSpellings": ["bin/launcher.sh"],
}


def make_payload(
    command: str,
    bypass_sandbox: bool = False,
    workspace_paths: list[str] | None = None,
    transcript_path: str | None = None,
    last_user_input: str = "Inspect the repo.",
    conversation_id: str = "conv-1234",
) -> dict[str, Any]:
    return {
        "conversationId": conversation_id,
        "workspacePaths": workspace_paths or ["/nonexistent/work/proj"],
        "transcriptPath": transcript_path or "",
        "lastUserInput": last_user_input,
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": command,
                "BypassSandbox": bypass_sandbox,
                "WaitMsBeforeAsync": 5000,
                "toolSummary": "Test command",
            },
        },
    }


DEEP_BLUE = "\x1b[38;5;25m"
ALERT_RED = "\x1b[38;5;160m"
WARN_AMBER = "\x1b[38;5;172m"
HOOK_MATCHER = "run_command|read_file|write_file|edit_file|view_file|list_directory|grep_search|find"
RESET = "\x1b[0m"


def allow_caller(
    sys_prompt: str,
    msgs: list[dict[str, Any]],
    max_tokens: int,
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "0"}]}


def soft_deny_caller(
    sys_prompt: str,
    msgs: list[dict[str, Any]],
    max_tokens: int,
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    if tools is None:
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "1"}]}
    return {
        "stop_reason": "tool_use",
        "content": [
            {
                "type": "tool_use",
                "name": CLASSIFIER_DECISION_TOOL_NAME,
                "input": {
                    "decision": "block",
                    "tier": "soft_deny",
                    "reason": "Blocked by classifier.",
                },
            }
        ],
    }


def sys_prompt_text() -> str:
    return build_classifier_system_prompt()


def unexpected_caller(
    sys_prompt: str,
    msgs: list[dict[str, Any]],
    max_tokens: int,
    tools: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    raise AssertionError("the classifier must not run for this action")


class AegysTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.work = Path(self.tmp.name) / "work" / "proj"
        self.home.mkdir(parents=True)
        self.work.mkdir(parents=True)
        (self.work / ".git").mkdir()
        agy_dir = self.home / ".gemini" / "antigravity-cli"
        agy_dir.mkdir(parents=True)
        (agy_dir / "settings.json").write_text(
            json.dumps({"agentMode": "auto"}), encoding="utf-8"
        )
        self.write_hooks(HOOK_MATCHER)
        self.write_aegys_config({"harnessConfigRepository": HARNESS_CONFIG_REPOSITORY})

    def write_aegys_config(self, config: dict[str, Any]) -> None:
        directory = self.home / ".gemini" / "aegys"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "config.json").write_text(json.dumps(config), encoding="utf-8")

    def write_hooks(self, matcher: str, slash_command: bool = True) -> None:
        config = self.home / ".gemini" / "config"
        config.mkdir(parents=True, exist_ok=True)
        entry: dict[str, Any] = {
            "PreToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [{"type": "command", "command": '"$HOME/.local/bin/aegys"'}],
                }
            ]
        }
        if slash_command:
            entry["PreInvocation"] = [
                {"type": "command", "command": '"$HOME/.local/bin/aegys" --pre-invocation'}
            ]
        (config / "hooks.json").write_text(json.dumps({"aegys": entry}), encoding="utf-8")

    def slash(self, text: str, conversation_id: str = "conv-1234") -> dict[str, Any]:
        return pre_invocation_response(
            {"conversationId": conversation_id, "lastUserInput": text, "invocationNum": 0},
            home=self.home,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def evaluate(
        self,
        command: str,
        bypass_sandbox: bool = False,
        classifier_caller: Any = None,
        last_user_input: str = "Inspect the repo.",
        transcript_path: str | None = None,
    ) -> dict[str, Any]:
        payload = make_payload(
            command,
            bypass_sandbox=bypass_sandbox,
            workspace_paths=[str(self.work)],
            transcript_path=transcript_path,
            last_user_input=last_user_input,
        )
        return evaluate_pre_tool_use(
            payload,
            home=self.home,
            cwd=self.work,
            temp_roots=(),
            classifier_caller=classifier_caller,
        )

    def evaluate_file(
        self,
        tool_name: str,
        path: str,
        workspace: Path | None = None,
        classifier_caller: Any = None,
        last_user_input: str = "Inspect the repo.",
    ) -> dict[str, Any]:
        root = workspace or self.work
        payload = {
            "conversationId": "conv-1234",
            "workspacePaths": [str(root)],
            "lastUserInput": last_user_input,
            "toolCall": {"name": tool_name, "args": {"Path": path}},
        }
        return evaluate_pre_tool_use(
            payload,
            home=self.home,
            cwd=root,
            temp_roots=(),
            classifier_caller=classifier_caller,
        )

    def test_fast_allows_safe_single_commands(self) -> None:
        for cmd in (
            "git status",
            "git log -n 5",
            "git diff HEAD~1",
            "rg TODO src/",
            "ls -la",
            "python3 -m unittest hooks.test_aegys",
            "bash tests/install.sh",
            "gh pr view 42",
        ):
            res = self.evaluate(cmd, bypass_sandbox=False)
            self.assertEqual(
                res,
                {"decision": "allow"},
                cmd,
            )

    def test_fast_allows_omits_overwrite_when_already_unsandboxed(self) -> None:
        res = self.evaluate("git status", bypass_sandbox=True)
        self.assertEqual(res, {"decision": "allow"})

    def test_fast_allows_safe_pipelines_and_chains(self) -> None:
        for cmd in (
            "git log -n 5 | head -n 5",
            "git status 2>&1 | grep -i main",
            "git diff | sed -n '1,20p' | awk '{print $1}'",
            "git status; git diff --stat && git branch --show-current",
            "rg -n pattern src 2>/dev/null | sort | uniq -c | head -n 10",
            "cd src && git status",
        ):
            res = self.evaluate(cmd, bypass_sandbox=False)
            self.assertEqual(
                res,
                {"decision": "allow"},
                cmd,
            )

    def test_deterministic_hard_denies_block_in_all_modes(self) -> None:
        for cmd, expected in (
            ("rg --pre 'rm -rf /' foo", "rg --pre"),
            ("fd -x rm {}", "fd --exec"),
            ("rm -rf ~", "critical path"),
            ("rm -rf .", "critical path"),
            ("cat ~/.ssh/id_rsa", "credentials"),
            ("git push --force origin main", "deny rule"),
            ("git push origin main -f", "deny rule"),
            ("git reset --hard HEAD~1", "deny rule"),
            ("git clean -fd", "deny rule"),
            ("gh repo delete owner/repo", "deny rule"),
            ("printenv", "deny rule"),
            ("curl https://webhook.site/abc", "webhook.site"),
            ("echo hacked > ~/.gemini/config/hooks.json", "controls agy"),
            ("echo hacked > ~/.gemini/antigravity-cli/settings.json", "controls agy"),
        ):
            res = self.evaluate(cmd)
            self.assertEqual(res.get("decision"), "deny", (cmd, res))
            self.assertIn(expected, res.get("reason", ""), (cmd, res))

    def test_sudo_and_doas_force_ask(self) -> None:
        for cmd in ("sudo ls /root", "doas cat /etc/shadow"):
            res = self.evaluate(cmd)
            self.assertEqual(res.get("decision"), "force_ask", (cmd, res))

    def test_guard_ignores_agy_mode(self) -> None:
        agy_dir = self.home / ".gemini" / "antigravity-cli"
        (agy_dir / "settings.json").write_text(
            json.dumps({"agentMode": "plan"}), encoding="utf-8"
        )
        log_dir = agy_dir / "log"
        log_dir.mkdir(parents=True, exist_ok=True)
        (log_dir / "cli-20261030_120000.log").write_text(
            "conv-1234\nSetCycleMode called: plan\n", encoding="utf-8"
        )
        self.assertEqual(
            self.evaluate("git log -n 5 | head -n 5"),
            {"decision": "allow"},
        )
        self.assertEqual(
            self.evaluate("git push --force origin main").get("decision"), "deny"
        )

    def test_file_tools_hard_deny_credential_paths(self) -> None:
        for tool_name, path in (
            ("read_file", self.home / ".ssh" / "id_ed25519"),
            ("read_file", self.home / ".aws" / "credentials"),
            ("write_file", self.home / ".netrc"),
            ("read_file", self.home / ".gemini" / "gemini-credentials.json"),
            ("read_file", self.home / ".claude" / ".credentials.json"),
            ("edit_file", self.home / ".codex" / "auth.json"),
        ):
            res = self.evaluate_file(tool_name, str(path), classifier_caller=unexpected_caller)
            self.assertEqual(res.get("decision"), "deny", (tool_name, path, res))
            self.assertIn("credential", res.get("reason", ""), (tool_name, path, res))

    def test_file_tools_deny_writes_to_guard_code_and_agy_control(self) -> None:
        for tool_name, path in (
            ("write_file", PACKAGE_DIR / "guard.py"),
            ("edit_file", PACKAGE_DIR / "data" / "agy-settings.json"),
            ("write_file", self.home / "harness-config" / "bin" / "lib.sh"),
            ("edit_file", self.home / "harness-config" / "permission-settings" / "rules.json"),
            ("write_file", self.home / ".gemini" / "config" / "hooks.json"),
            (
                "write_file",
                self.home / ".gemini" / "antigravity-cli" / "auto-guard-state" / "conv-1234.json",
            ),
        ):
            # The checkout is the workspace here: guard code is still protected.
            res = self.evaluate_file(
                tool_name,
                str(path),
                workspace=REPO_ROOT,
                classifier_caller=unexpected_caller,
            )
            self.assertEqual(res.get("decision"), "deny", (tool_name, path, res))
            self.assertIn("aegys", res.get("reason", ""), (tool_name, path, res))

    def test_file_tools_allow_workspace_files_without_classifier(self) -> None:
        for tool_name in ("read_file", "write_file", "edit_file"):
            res = self.evaluate_file(
                tool_name,
                str(self.work / "src" / "main.py"),
                classifier_caller=unexpected_caller,
            )
            self.assertEqual(res, {"decision": "allow"}, tool_name)

    def test_home_directory_is_not_a_workspace_for_file_tools(self) -> None:
        # A session started in $HOME must not allow every file under it without a look.
        for tool_name, path in (
            ("read_file", self.home / "notes" / "todo.txt"),
            ("write_file", self.home / "scratch.txt"),
        ):
            calls: list[int] = []

            def counting_caller(
                sys_prompt: str,
                msgs: list[dict[str, Any]],
                max_tokens: int,
                tools: list[dict[str, Any]] | None,
            ) -> dict[str, Any]:
                calls.append(1)
                return allow_caller(sys_prompt, msgs, max_tokens, tools)

            res = self.evaluate_file(
                tool_name, str(path), workspace=self.home, classifier_caller=counting_caller
            )
            self.assertEqual(res, {"decision": "allow"}, tool_name)
            self.assertEqual(len(calls), 1, tool_name)

    def test_file_tools_send_protected_names_in_workspace_to_classifier(self) -> None:
        calls: list[int] = []

        def counting_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            calls.append(1)
            return allow_caller(sys_prompt, msgs, max_tokens, tools)

        res = self.evaluate_file(
            "write_file", str(self.work / ".git" / "config"), classifier_caller=counting_caller
        )
        self.assertEqual(res, {"decision": "allow"})
        self.assertEqual(len(calls), 1)

    def test_file_tools_outside_workspace_follow_classifier_verdict(self) -> None:
        outside = self.home / "notes" / "todo.txt"
        seen_actions: list[str] = []

        def recording_allow(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            seen_actions.extend(part.get("text", "") for m in msgs for part in m["content"])
            return allow_caller(sys_prompt, msgs, max_tokens, tools)

        self.assertEqual(
            self.evaluate_file("read_file", str(outside), classifier_caller=recording_allow),
            {"decision": "allow"},
        )
        self.assertTrue(any('"toolName": "read_file"' in text for text in seen_actions))
        self.assertEqual(
            self.evaluate_file("read_file", str(outside), classifier_caller=soft_deny_caller).get(
                "decision"
            ),
            "deny",
        )

        def failing_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

        res = self.evaluate_file("read_file", str(outside), classifier_caller=failing_caller)
        self.assertEqual(res.get("decision"), "force_ask")
        self.assertIn("aegys warning:", res.get("reason", ""))

    def test_slash_off_stops_the_turn_without_the_model(self) -> None:
        res = self.slash("/aegys off")
        self.assertEqual(res.get("terminationBehavior"), "terminate", res)
        self.assertIn("aegys is off", res["injectSteps"][0]["errorMessage"]["userMessage"])
        self.assertFalse(guard_enabled(self.home, "conv-1234"))

    def test_slash_off_forces_ask_except_hard_denies_and_static_allows(self) -> None:
        self.slash("/aegys off")
        self.assertEqual(self.evaluate("git status"), {"decision": "allow"})
        self.assertEqual(
            self.evaluate("git push --force origin main", classifier_caller=unexpected_caller).get(
                "decision"
            ),
            "deny",
        )
        self.assertEqual(
            self.evaluate("python3 -c 'print(1)'", classifier_caller=unexpected_caller).get(
                "decision"
            ),
            "force_ask",
        )
        self.assertEqual(
            self.evaluate("git log -n 5 | head -n 5", classifier_caller=unexpected_caller).get(
                "decision"
            ),
            "force_ask",
        )
        self.assertEqual(
            self.evaluate_file(
                "read_file", str(self.home / "notes" / "todo.txt"), classifier_caller=unexpected_caller
            ).get("decision"),
            "force_ask",
        )
        self.assertEqual(
            self.evaluate_file(
                "read_file", str(self.work / "a.py"), classifier_caller=unexpected_caller
            ),
            {"decision": "allow"},
        )
        # A hard deny that is recorded must not switch the guard back on.
        self.evaluate("rg --pre 'rm -rf /' foo")
        self.assertFalse(guard_enabled(self.home, "conv-1234"))

    def test_slash_on_restores_the_classifier(self) -> None:
        self.slash("/aegys off")
        res = self.slash("  /AEGYS on ")
        self.assertIn("aegys is on", res["injectSteps"][0]["errorMessage"]["userMessage"])
        self.assertTrue(guard_enabled(self.home, "conv-1234"))
        self.assertEqual(
            self.evaluate("python3 -c 'print(1)'", classifier_caller=allow_caller),
            {"decision": "allow"},
        )

    def test_bare_slash_reports_state_without_changing_it(self) -> None:
        res = self.slash("/aegys")
        self.assertEqual(res.get("terminationBehavior"), "terminate", res)
        self.assertIn("aegys is on", res["injectSteps"][0]["errorMessage"]["userMessage"])
        self.assertTrue(guard_enabled(self.home, "conv-1234"))

    def test_other_prompts_pass_through_and_the_model_cannot_switch(self) -> None:
        for text in ("please run aegys off", "/aegys off now", "/aegysoff", "", "/aegys maybe"):
            self.assertEqual(self.slash(text), {}, text)
        self.assertTrue(guard_enabled(self.home, "conv-1234"))
        # The old command form is an ordinary command now: running it changes nothing.
        self.evaluate(
            '"$HOME/.local/bin/aegys" off',
            last_user_input="/aegys off",
            classifier_caller=soft_deny_caller,
        )
        self.assertTrue(guard_enabled(self.home, "conv-1234"))

    def test_slash_switch_is_per_conversation(self) -> None:
        self.slash("/aegys off")
        self.assertFalse(guard_enabled(self.home, "conv-1234"))
        self.assertTrue(guard_enabled(self.home, "conv-other"))

    def test_pre_invocation_cli_roundtrip_and_bad_input(self) -> None:
        def run(stdin: str) -> dict[str, Any]:
            proc = subprocess.run(
                [sys.executable, "-m", "aegys.guard", "--pre-invocation"],
                input=stdin, capture_output=True, text=True, check=False, timeout=20,
                env={**os.environ, "HOME": str(self.home)},
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return json.loads(proc.stdout)

        res = run(json.dumps({"conversationId": "conv-cli", "lastUserInput": "/aegys off"}))
        self.assertEqual(res.get("terminationBehavior"), "terminate")
        self.assertFalse(guard_enabled(self.home, "conv-cli"))
        # Unreadable input must never block the user's turn.
        self.assertEqual(run("not json"), {})

    def test_non_run_command_tools_are_allowed(self) -> None:
        for tool_name in ("read_file", "edit_file", "write_file", "list_dir"):
            res = evaluate_pre_tool_use(
                {
                    "conversationId": "conv-1234",
                    "workspacePaths": [str(self.work)],
                    "toolCall": {
                        "name": tool_name,
                        "args": {"Path": str(self.work / "README.md")},
                    },
                },
                home=self.home,
                cwd=self.work,
            )
            self.assertEqual(res, {"decision": "allow"}, tool_name)
        self.assertEqual(
            evaluate_pre_tool_use({}, home=self.home, cwd=self.work),
            {"decision": "allow"},
        )

    def test_anthropic_messages_call_uses_valid_messages_and_top_level_effort(self) -> None:
        import urllib.request
        from unittest.mock import MagicMock, patch

        captured: dict[str, Any] = {}

        def fake_urlopen(req: urllib.request.Request, timeout: float = 0) -> Any:
            captured["url"] = req.full_url
            captured["headers"] = dict(req.header_items())
            captured["body"] = json.loads(req.data.decode("utf-8"))
            resp = MagicMock()
            resp.__enter__.return_value = resp
            resp.read.return_value = b'{"stop_reason": "end_turn", "content": [{"type": "text", "text": "0"}]}'
            return resp

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-ant-key"}, clear=False):
            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                out = anthropic_messages_call(
                    "sys prompt",
                    [{"role": "user", "content": "check"}],
                    max_tokens=256,
                    effort="low",
                )
        self.assertEqual(out["stop_reason"], "end_turn")
        body = captured["body"]
        self.assertEqual(body["messages"], [{"role": "user", "content": "check"}])
        self.assertTrue(all(m["role"] in ("user", "assistant") for m in body["messages"]))
        self.assertEqual(body["output_config"], {"effort": "low"})

    def test_classifier_fast_stage_zero_allows(self) -> None:
        calls: list[dict[str, Any]] = []

        def fake_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            calls.append({"msgs": msgs, "max_tokens": max_tokens, "tools": tools})
            return {
                "stop_reason": "end_turn",
                "content": [{"type": "text", "text": "0"}],
            }

        res = self.evaluate(
            "python3 -c 'print(1 + 1)'",
            bypass_sandbox=False,
            classifier_caller=fake_caller,
        )
        self.assertEqual(
            res, {"decision": "allow"}
        )
        self.assertEqual(len(calls), 1)
        self.assertIsNone(calls[0]["tools"])

    def test_classifier_fast_one_then_detailed_allow(self) -> None:
        calls: list[dict[str, Any]] = []

        def fake_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            calls.append({"tools": tools})
            if tools is None:
                return {
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "1"}],
                }
            return {
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "name": CLASSIFIER_DECISION_TOOL_NAME,
                        "input": {
                            "decision": "allow",
                            "tier": "allow",
                            "reason": "Local python one-liner calculation is safe.",
                        },
                    }
                ],
            }

        res = self.evaluate(
            "python3 -c 'print(42)'",
            bypass_sandbox=False,
            classifier_caller=fake_caller,
        )
        self.assertEqual(
            res, {"decision": "allow"}
        )
        self.assertEqual(len(calls), 2)

    def test_classifier_soft_deny_returns_deny_not_ask(self) -> None:
        def fake_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            if tools is None:
                return {
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "1"}],
                }
            return {
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "name": CLASSIFIER_DECISION_TOOL_NAME,
                        "input": {
                            "decision": "block",
                            "tier": "soft_deny",
                            "reason": "Deleting pre-existing tracked file without explicit user intent.",
                        },
                    }
                ],
            }

        res = self.evaluate(
            "rm old_tracked_file.py",
            bypass_sandbox=False,
            classifier_caller=fake_caller,
        )
        self.assertEqual(res.get("decision"), "deny")
        self.assertIn("soft_deny", res.get("reason", ""))
        self.assertIn("Deleting pre-existing tracked file", res.get("reason", ""))

    def test_classifier_forces_ask_and_warns_when_api_unavailable(self) -> None:
        def failing_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")

        res = self.evaluate(
            "python3 -c 'print(1)'",
            classifier_caller=failing_caller,
        )
        self.assertEqual(res.get("decision"), "force_ask")
        self.assertIn("aegys warning:", res.get("reason", ""))
        self.assertIn("ANTHROPIC_API_KEY is not set", res.get("reason", ""))

    def test_classifier_malformed_response_fails_closed_with_deny(self) -> None:
        def malformed_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            if tools is None:
                return {
                    "stop_reason": "end_turn",
                    "content": [{"type": "text", "text": "1"}],
                }
            return {
                "stop_reason": "max_tokens",
                "content": [{"type": "text", "text": "truncated"}],
            }

        res_trunc = self.evaluate(
            "python3 -c 'print(1)'",
            classifier_caller=malformed_caller,
        )
        self.assertEqual(res_trunc.get("decision"), "deny")
        self.assertIn("aegys fails closed", res_trunc.get("reason", ""))

    def test_transcript_builder_extracts_user_and_planner_tool_calls(self) -> None:
        transcript_file = Path(self.tmp.name) / "transcript.jsonl"
        steps = [
            {
                "step_index": 0,
                "type": "USER_INPUT",
                "content": "<USER_REQUEST>\nDelete build/old.txt in this repo.\n</USER_REQUEST>",
            },
            {
                "step_index": 1,
                "type": "PLANNER_RESPONSE",
                "tool_calls": [
                    {"name": "run_command", "args": {"CommandLine": "ls build"}}
                ],
            },
        ]
        transcript_file.write_text(
            "\n".join(json.dumps(s) for s in steps) + "\n", encoding="utf-8"
        )
        rendered = build_classifier_transcript(
            transcript_file, last_user_input="Go ahead and remove it now."
        )
        self.assertIn("User: Delete build/old.txt in this repo.", rendered)
        self.assertIn('ToolCall run_command: {"CommandLine": "ls build"}', rendered)
        self.assertIn("User: Go ahead and remove it now.", rendered)

    def test_cli_stdin_stdout_roundtrip(self) -> None:
        payload = make_payload(
            "git log -n 3 | head -n 3",
            bypass_sandbox=False,
            workspace_paths=[str(self.work)],
        )
        proc = subprocess.run(
            [sys.executable, "-m", "aegys.guard"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "HOME": str(self.home)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(
            out, {"decision": "allow"}
        )

    def test_view_file_follows_read_file_rules(self) -> None:
        res = self.evaluate_file(
            "view_file", str(self.home / ".ssh" / "id_rsa"), classifier_caller=unexpected_caller
        )
        self.assertEqual(res.get("decision"), "deny", res)
        self.assertEqual(
            self.evaluate_file("view_file", str(self.work / "a.py"), classifier_caller=unexpected_caller),
            {"decision": "allow"},
        )
        res = self.evaluate_file(
            "view_file", str(self.home / "notes.txt"), classifier_caller=soft_deny_caller
        )
        self.assertEqual(res.get("decision"), "deny", res)

    def test_listing_and_search_tools_check_credential_paths_only(self) -> None:
        cases = (
            ("list_directory", {"DirectoryPath": str(self.home / ".ssh")}),
            ("grep_search", {"SearchPath": str(self.home / ".aws"), "Query": "key"}),
            ("find", {"SearchDirectory": str(self.home / ".gnupg"), "Pattern": "*"}),
            # A recursive search that starts above a credential area reads it.
            ("grep_search", {"SearchPath": str(self.home), "Query": "secret"}),
        )
        for tool_name, args in cases:
            res = evaluate_pre_tool_use(
                {"conversationId": "conv-1234", "workspacePaths": [str(self.work)],
                 "toolCall": {"name": tool_name, "args": args}},
                home=self.home, cwd=self.work, classifier_caller=unexpected_caller,
            )
            self.assertEqual(res.get("decision"), "deny", (tool_name, args, res))
        for tool_name, args in (
            ("list_directory", {"DirectoryPath": str(self.home / "notes")}),
            ("grep_search", {"SearchPath": str(self.work), "Query": "TODO"}),
            ("find", {"SearchDirectory": "/usr/share", "Pattern": "*.txt"}),
        ):
            res = evaluate_pre_tool_use(
                {"conversationId": "conv-1234", "workspacePaths": [str(self.work)],
                 "toolCall": {"name": tool_name, "args": args}},
                home=self.home, cwd=self.work, classifier_caller=unexpected_caller,
            )
            self.assertEqual(res, {"decision": "allow"}, (tool_name, args))

    def test_writes_inside_the_harness_config_repository_and_gemini_go_to_classifier(self) -> None:
        agents = self.home / "harness-config"
        for tool_name, path in (
            ("write_file", agents / "scripts" / "setup.sh"),
            ("edit_file", agents / "harness-settings" / "config.toml"),
            ("edit_file", agents / "README.md"),
            ("write_file", agents / "notes" / "x.md"),
            ("write_file", self.home / ".gemini" / "projects.json"),
        ):
            # Even when that tree is the workspace, a write is not fast-allowed.
            res = self.evaluate_file(
                tool_name, str(path), workspace=agents, classifier_caller=soft_deny_caller
            )
            self.assertEqual(res.get("decision"), "deny", (tool_name, path, res))
            self.assertIn("classifier", res.get("reason", ""), (tool_name, path, res))
        # Reads in the workspace stay fast.
        self.assertEqual(
            self.evaluate_file(
                "read_file", str(agents / "scripts" / "setup.sh"),
                workspace=agents, classifier_caller=unexpected_caller,
            ),
            {"decision": "allow"},
        )

    def test_shell_writes_into_agent_trees_never_skip_the_classifier(self) -> None:
        # Into the harness config repository's control directories: denied outright,
        # even with the repository as workspace.
        agents = self.home / "harness-config"
        (agents / ".git").mkdir(parents=True)
        for cmd in (
            "sed -i s/a/b/ scripts/setup.sh",
            "echo x > scripts/setup.sh",
            "cp README.md scripts/x.sh",
            "echo x > hooks/x.py",
            "echo x > harness-settings/config.toml",
            "echo x > permission-settings/rules.json",
            "git checkout -- scripts/setup.sh",
            "git checkout -- .",
            "python3 -c \"open('hooks/x.py', 'w')\"",
        ):
            res = evaluate_pre_tool_use(
                make_payload(cmd, workspace_paths=[str(agents)]),
                home=self.home, cwd=agents, temp_roots=(), classifier_caller=unexpected_caller,
            )
            self.assertEqual(res.get("decision"), "deny", (cmd, res))
        # Into ~/.gemini or another tree of the repository: the classifier decides.
        for cmd in (
            "sed -i s/a/b/ ~/.gemini/projects.json",
            "echo x > ~/harness-config/notes/x.md",
            "touch ~/harness-config/notes/new",
        ):
            res = self.evaluate(cmd, classifier_caller=soft_deny_caller)
            self.assertEqual(res.get("decision"), "deny", (cmd, res))
            self.assertIn("classifier", res.get("reason", ""), (cmd, res))

    def test_inline_code_naming_a_control_spelling_is_denied(self) -> None:
        for cmd in (
            "python3 -c \"open('bin/launcher.sh', 'w')\"",
            "python3 -c \"open('permission-settings/rules.json', 'w')\"",
            "python3 -c \"open('harness-settings/config.toml', 'w')\"",
        ):
            res = self.evaluate(cmd, classifier_caller=unexpected_caller)
            self.assertEqual(res.get("decision"), "deny", (cmd, res))

    def test_the_package_modules_are_control_files_by_name(self) -> None:
        for cmd in (
            "python3 -c \"open('aegys/command_checks.py', 'w')\"",
            "python3 -c \"open('aegys/shell_words.py', 'w')\"",
        ):
            res = self.evaluate(cmd, classifier_caller=unexpected_caller)
            self.assertEqual(res.get("decision"), "deny", (cmd, res))

    def test_vibe_settings_are_read_like_any_other_file(self) -> None:
        # Shell reads of ~/.vibe/config.toml are no longer redirected to read_file.
        (self.home / ".vibe").mkdir(exist_ok=True)
        (self.home / ".vibe" / "config.toml").write_text("active_model = 'x'\n", encoding="utf-8")
        self.assertEqual(
            self.evaluate("cat ~/.vibe/config.toml", classifier_caller=allow_caller),
            {"decision": "allow"},
        )

    def test_vibe_session_logs_are_writable_by_the_classifier_only(self) -> None:
        # No .vibe directory is tamper-proof any more: the classifier judges the write.
        self.assertEqual(
            self.evaluate("echo x > ~/.vibe/logs/session.jsonl", classifier_caller=allow_caller),
            {"decision": "allow"},
        )

    def test_recursive_search_inside_vibe_logs_is_not_denied(self) -> None:
        # The session logs are no longer a secret area.
        (self.home / ".vibe" / "logs").mkdir(parents=True, exist_ok=True)
        self.assertEqual(
            self.evaluate("grep -r token ~/.vibe/logs", classifier_caller=allow_caller),
            {"decision": "allow"},
        )

    def test_vibe_directory_named_in_inline_code_is_not_a_control_spelling(self) -> None:
        self.assertEqual(
            self.evaluate(
                "python3 -c \"open('.vibe/notes.txt', 'w')\"", classifier_caller=allow_caller
            ),
            {"decision": "allow"},
        )
        self.assertEqual(
            self.evaluate("echo x > ~/.vibe/notes.txt", classifier_caller=allow_caller),
            {"decision": "allow"},
        )

    def test_without_a_harness_config_repository_no_repository_is_guarded(self) -> None:
        self.write_aegys_config({})
        repository = self.home / "harness-config"
        for tool_name, path in (
            ("write_file", repository / "hooks" / "x.py"),
            ("edit_file", repository / "permission-settings" / "rules.json"),
        ):
            res = self.evaluate_file(
                tool_name, str(path), workspace=repository, classifier_caller=unexpected_caller
            )
            self.assertEqual(res, {"decision": "allow"}, (tool_name, path))

    def test_the_guarded_repository_follows_the_configured_path(self) -> None:
        self.write_aegys_config(
            {"harnessConfigRepository": {**HARNESS_CONFIG_REPOSITORY, "path": "~/elsewhere"}}
        )
        res = self.evaluate_file(
            "write_file", str(self.home / "elsewhere" / "hooks" / "x.py"),
            classifier_caller=unexpected_caller,
        )
        self.assertEqual(res.get("decision"), "deny", res)
        res = self.evaluate_file(
            "write_file", str(self.home / "harness-config" / "hooks" / "x.py"),
            workspace=self.home / "harness-config", classifier_caller=unexpected_caller,
        )
        self.assertEqual(res, {"decision": "allow"})

    def test_classifier_retries_stop_at_the_time_budget(self) -> None:
        import time
        import urllib.error
        from unittest.mock import patch

        import aegys.guard as guard_module

        def slow_fail(req: Any, timeout: float) -> Any:
            time.sleep(min(timeout, 0.2))
            raise urllib.error.URLError("timed out")

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}), patch(
            "urllib.request.urlopen", side_effect=slow_fail
        ), patch.object(guard_module, "CLASSIFIER_TIME_BUDGET_SECONDS", 0.5):
            start = time.monotonic()
            res = self.evaluate("python3 -c 'print(1)'")
            elapsed = time.monotonic() - start
        self.assertEqual(res.get("decision"), "force_ask", res)
        self.assertIn("aegys warning:", res.get("reason", ""))
        self.assertLess(elapsed, 1.5)

    def test_statusline_flags_a_missing_or_incomplete_hook(self) -> None:
        (self.home / ".gemini" / "config" / "hooks.json").unlink()
        line = format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home)
        self.assertTrue(line.startswith(ALERT_RED), line)
        self.assertIn("aegys ✗ hook not installed", line)
        self.write_hooks("run_command")
        line = format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home)
        self.assertIn("aegys ✗ hook misses", line)
        (self.home / ".gemini" / "config" / "hooks.json").write_text(
            json.dumps({"aegys": ["not", "an", "object"]}), encoding="utf-8"
        )
        line = format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home)
        self.assertIn("aegys ✗ hooks.json unreadable", line)
        self.write_hooks(HOOK_MATCHER, slash_command=False)
        line = format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home)
        self.assertIn("aegys ✗ hook misses /aegys", line)
        self.write_hooks(HOOK_MATCHER)
        self.assertTrue(
            format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home).startswith(DEEP_BLUE)
        )

    def set_tool_permission(self, value: str) -> None:
        path = self.home / ".gemini" / "antigravity-cli" / "settings.json"
        settings = json.loads(path.read_text(encoding="utf-8"))
        settings["toolPermission"] = value
        path.write_text(json.dumps(settings), encoding="utf-8")

    def test_always_proceed_turns_every_prompt_into_a_deny(self) -> None:
        # agy runs a force_ask command without asking under always-proceed.
        self.set_tool_permission("always-proceed")
        res = self.evaluate("sudo ls /root")
        self.assertEqual(res.get("decision"), "deny", res)
        self.assertIn("always-proceed", res.get("reason", ""))
        self.slash("/aegys off")
        res = self.evaluate("python3 -c 'print(1)'", classifier_caller=unexpected_caller)
        self.assertEqual(res.get("decision"), "deny", res)
        # Allows and denies are unchanged.
        self.assertEqual(self.evaluate("git status"), {"decision": "allow"})
        self.set_tool_permission("request-review")
        self.assertEqual(self.evaluate("sudo ls /root").get("decision"), "force_ask")

    def test_statusline_warns_in_modes_that_fight_aegys(self) -> None:
        def line(extra: dict[str, Any]) -> str:
            return format_status_line({"conversation_id": "conv-1234", **extra}, home=self.home)

        self.assertEqual(
            line({"cycle_mode": "auto", "sandbox": {"enabled": True}}),
            f"{WARN_AMBER}aegys ● a:0 d:0 ⚠ native auto mode on: aegys covers it, best off{RESET}",
        )
        self.assertEqual(
            line({"cycle_mode": "accept-edits", "sandbox": {"enabled": True}}),
            f"{WARN_AMBER}aegys ● a:0 d:0 ⚠ sandbox on: aegys covers it, best off{RESET}",
        )
        # Default mode (cycle_mode omitted), accept-edits and plan keep the blue chip.
        for extra in ({}, {"cycle_mode": "accept-edits"}, {"cycle_mode": "plan"}):
            self.assertTrue(line(extra).startswith(DEEP_BLUE), extra)
        # A broken install outranks a mode warning.
        (self.home / ".gemini" / "config" / "hooks.json").unlink()
        self.assertTrue(line({}).startswith(ALERT_RED))

    def test_skip_sandbox_overwrite_only_while_the_sandbox_is_on(self) -> None:
        # agy prefixes every rewritten call's result with a notice, so the flag is
        # added only when the status line last reported the sandbox on.
        self.assertEqual(self.evaluate("git status"), {"decision": "allow"})
        format_status_line(
            {"conversation_id": "conv-1234", "cycle_mode": "auto", "sandbox": {"enabled": True}},
            home=self.home,
        )
        self.assertEqual(
            self.evaluate("git status"),
            {"decision": "allow", "overwrite": {"BypassSandbox": True}},
        )
        self.assertEqual(self.evaluate("git status", bypass_sandbox=True), {"decision": "allow"})
        format_status_line(
            {"conversation_id": "conv-1234", "cycle_mode": "accept-edits", "sandbox": {"enabled": False}},
            home=self.home,
        )
        self.assertEqual(self.evaluate("git status"), {"decision": "allow"})

    def test_evasion_and_repeats_are_strikes_with_guidance_to_change_course(self) -> None:
        self.assertEqual(self.evaluate("cat ~/.ssh/id_rsa").get("decision"), "deny")
        seen: list[str] = []

        def evasion_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            seen.extend(part.get("text", "") for m in msgs for part in m["content"])
            if tools is None:
                return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "1"}]}
            return {
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "name": CLASSIFIER_DECISION_TOOL_NAME,
                        "input": {
                            "decision": "block",
                            "tier": "evasion",
                            "reason": "Reads the key the earlier deny protected.",
                        },
                    }
                ],
            }

        for attempt in (1, 2, 3, 4):
            res = self.evaluate(f"python3 -c 'print({attempt})'", classifier_caller=evasion_caller)
            self.assertEqual(res.get("decision"), "deny", res)
            reason = res.get("reason", "")
            self.assertIn(f"attempt {attempt} at a goal aegys already denied", reason)
            self.assertIn("safe alternative or take a different approach", reason)
            self.assertIn("Reads the key the earlier deny protected.", reason)
            self.assertNotIn("reply", reason)
        res = self.evaluate("python3 -c 'print(5)'", classifier_caller=evasion_caller)
        self.assertEqual(res.get("decision"), "deny", res)
        self.assertIn("drop that goal for the rest of this turn", res.get("reason", ""))
        self.assertIn("when the turn ends, report", res.get("reason", ""))
        # The count restarts after the fifth strike.
        res = self.evaluate("python3 -c 'print(6)'", classifier_caller=evasion_caller)
        self.assertIn("attempt 1 at", res.get("reason", ""))
        self.assertTrue(
            any("<recent-denied-actions>" in s and "cat ~/.ssh/id_rsa" in s for s in seen), seen
        )
        self.assertIn("evasion", sys_prompt_text())

    def test_first_deny_is_plain_and_exact_repeats_are_strikes(self) -> None:
        first = self.evaluate("cat ~/.ssh/id_rsa")
        self.assertEqual(first.get("decision"), "deny")
        self.assertNotIn("attempt", first.get("reason", ""))
        res = self.evaluate("cat ~/.ssh/id_rsa")
        self.assertIn("attempt 1 at a goal aegys already denied", res.get("reason", ""))
        # A different denied action is not a strike.
        res = self.evaluate("rg --pre 'rm -rf /' foo")
        self.assertNotIn("attempt", res.get("reason", ""))

    def test_strikes_only_count_within_the_last_ten_actions(self) -> None:
        self.evaluate("cat ~/.ssh/id_rsa")
        for _ in range(10):
            self.evaluate("git status")
        # A repeat eleven actions later is a fresh deny, not a strike.
        res = self.evaluate("cat ~/.ssh/id_rsa")
        self.assertNotIn("attempt", res.get("reason", ""))
        res = self.evaluate("cat ~/.ssh/id_rsa")
        self.assertIn("attempt 1 at", res.get("reason", ""))
        for _ in range(10):
            self.evaluate("git status")
        # An old strike is forgotten too: the next one is attempt 1 again.
        self.evaluate("cat ~/.ssh/id_rsa")
        res = self.evaluate("cat ~/.ssh/id_rsa")
        self.assertIn("attempt 1 at", res.get("reason", ""))

    def test_amber_chip_keeps_live_counters_and_flags_auto_without_sandbox(self) -> None:
        self.evaluate("git status")
        self.evaluate("rg --pre 'rm -rf /' foo")
        line = format_status_line(
            {"conversation_id": "conv-1234", "cycle_mode": "auto", "sandbox": {"enabled": False}},
            home=self.home,
        )
        self.assertEqual(
            line, f"{WARN_AMBER}aegys ● a:1 d:1 ⚠ native auto mode on: aegys covers it, best off{RESET}"
        )

    def test_file_tool_evasion_is_a_strike(self) -> None:
        def evasion_caller(
            sys_prompt: str,
            msgs: list[dict[str, Any]],
            max_tokens: int,
            tools: list[dict[str, Any]] | None,
        ) -> dict[str, Any]:
            if tools is None:
                return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "1"}]}
            return {
                "stop_reason": "tool_use",
                "content": [
                    {
                        "type": "tool_use",
                        "name": CLASSIFIER_DECISION_TOOL_NAME,
                        "input": {"decision": "block", "tier": "evasion", "reason": "Same goal."},
                    }
                ],
            }

        res = self.evaluate_file(
            "read_file", str(self.home / "notes" / "copy-of-key"), classifier_caller=evasion_caller
        )
        self.assertEqual(res.get("decision"), "deny", res)
        self.assertIn("attempt 1 at a goal aegys already denied", res.get("reason", ""))

    def test_long_repeated_action_is_a_strike(self) -> None:
        long_command = "cat ~/.ssh/id_rsa # " + "x" * 400
        self.assertNotIn("attempt", self.evaluate(long_command).get("reason", ""))
        self.assertIn("attempt 1 at", self.evaluate(long_command).get("reason", ""))

    def test_concurrent_hook_runs_lose_no_counts(self) -> None:
        # agy can run several hook processes at once for one conversation.
        code = (
            "import sys; from pathlib import Path; sys.path.insert(0, sys.argv[2]); "
            "from aegys.guard import record_guard_decision\n"
            "for _ in range(25): record_guard_decision(Path(sys.argv[1]), 'conv-1234', allowed=True)"
        )
        procs = [
            subprocess.Popen([sys.executable, "-c", code, str(self.home), str(PACKAGE_DIR.parent)])
            for _ in range(4)
        ]
        for proc in procs:
            self.assertEqual(proc.wait(timeout=60), 0)
        self.assertEqual(load_guard_state(self.home, "conv-1234")["allowed"], 100)

    def test_statusline_flags_always_proceed(self) -> None:
        self.set_tool_permission("always-proceed")
        line = format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home)
        self.assertTrue(line.startswith(ALERT_RED), line)
        self.assertIn("aegys ✗ toolPermission always-proceed", line)

    def test_cli_switch_argument_explains_instead_of_reading_stdin(self) -> None:
        # Run by hand, the switch has no conversation to act on: say so, do not wait for stdin.
        proc = subprocess.run(
            [sys.executable, "-m", "aegys.guard", "off"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
            env={**os.environ, "HOME": str(self.home)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("type /aegys off", proc.stdout)

    def test_statusline_counts_and_toggle_state(self) -> None:
        def chip(text: str) -> str:
            return f"{DEEP_BLUE}{text}{RESET}"

        # Initial state: 0 allowed, 0 denied, no classifier suffix, full bullet ● while on.
        self.assertEqual(
            format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home),
            chip("aegys ● a:0 d:0"),
        )

        # Fast-allowed command increments `a:` only; `ca:`/`cd:` stay omitted.
        self.evaluate("git status")
        self.evaluate("git log -n 5 | head -n 5")
        self.assertEqual(
            format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home),
            chip("aegys ● a:2 d:0"),
        )

        # Deterministic hard-deny increments `d:` only; `ca:`/`cd:` stay omitted.
        self.evaluate("rg --pre 'rm -rf /' foo")
        self.assertEqual(
            format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home),
            chip("aegys ● a:2 d:1"),
        )

        # Classifier allow increments both `a:` and `ca:`; classifier suffix appears.
        self.evaluate("python3 -c 'print(1)'", classifier_caller=allow_caller)
        self.assertEqual(
            format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home),
            chip("aegys ● a:3 d:1 ca:1 cd:0"),
        )

        # Classifier deny increments both `d:` and `cd:`.
        self.evaluate("rm tracked.py", classifier_caller=soft_deny_caller)
        self.assertEqual(
            format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home),
            chip("aegys ● a:3 d:2 ca:1 cd:1"),
        )
        self.assertEqual(
            load_guard_state(self.home, "conv-1234"),
            {
                "allowed": 3,
                "denied": 2,
                "classifier_allowed": 1,
                "classifier_denied": 1,
            },
        )

        # Switching the guard off turns ● into ○ and keeps the counters.
        self.slash("/aegys off")
        self.assertEqual(
            format_status_line({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}, home=self.home),
            chip("aegys ○ a:3 d:2 ca:1 cd:1"),
        )

        # --statusline CLI mode reads stdin JSON and prints the formatted line.
        proc = subprocess.run(
            [sys.executable, "-m", "aegys.guard", "--statusline"],
            input=json.dumps({"conversation_id": "conv-1234", "cycle_mode": "accept-edits"}),
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "HOME": str(self.home)},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), chip("aegys ○ a:3 d:2 ca:1 cd:1"))


if __name__ == "__main__":
    unittest.main()
