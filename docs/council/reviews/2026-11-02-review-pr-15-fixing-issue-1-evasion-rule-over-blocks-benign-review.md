# Review PR #15 fixing Issue #1: Evasion rule over-blocks benign sub-steps and ... Review

# Review: PR #15 fixing Issue #1 (Round 3 Verification)

## Scope reviewed

The verification review covers commit range `b4c4a71de5bc675bb6ec5ed660b1ee7fe519d918..4517ee364498c57039da2dbe7b116967fbe3062f` against the original Issue #1 requirements, the Round 2 Council findings, and the Google Jules adversarial code review findings.
Files examined in full across all four seats (Chair, Reviewer on Mistral Large 4, Critic on GLM 5.3, and Saboteur on Claude Opus 5.5 High):
- `README.md`
- `aegys/command_checks.py`
- `aegys/guard.py`
- `aegys/shell_words.py`
- `docs/council/reviews/2026-11-02-review-pr-15-fixing-issue-1-evasion-rule-over-blocks-benign-review.md`
- `tests/test_command_checks.py`
- `tests/test_guard.py`
- `tests/test_shell_words.py`

## Strengths

- `aegys/shell_words.py:100-105`: POSIX `for NAME do CMD; done` and `select NAME do CMD; done` loops without `in` or `;` are cleanly unwrapped (`del words[:3]; continue`), while preserving `words[0]` (`"select"`) as the head program name when `in` is present.
- `aegys/command_checks.py:503-547`: `_split_stages_with_ends` and `_scan_substitutions` associate each command substitution with its containing stage via byte offsets, executing substitution recursion with `initial_cwds=stage_cwds` and `initial_known=known` before subsequent `cd` stages alter the directory state.
- `aegys/command_checks.py:288-320` and `533-543`: Heredoc delimiter quoting (`_heredoc_bodies_with_quoting`) correctly discriminates between unquoted delimiters (`<<EOF`), which undergo command substitution walking, and quoted delimiters (`<<'EOF'`, `<<"EOF"`, `<<\EOF`), which remain inert data.
- `aegys/command_checks.py:376-438`: Arithmetic `$((...))` parser extracts inner command substitutions, quote/backtick tracking inside `$(...)` prevents premature closing on inner `)`, and length-preserving underscore masking keeps surrounding words in the same stage during `shlex` splitting.
- `tests/test_guard.py:1623-1708`: State persistence assertions explicitly verify that `state["strikes"] == 0` and `"strike_at"` is cleared after `explicit_intent` authorization, and cross-turn repeat evasions do not trigger auto-strikes.
- Test suite integrity: 151 unit tests run and pass cleanly in 1.3s with zero failures. Targeted fault-injection testing by Saboteur confirmed that all 3 executed mutations on the fixes were caught by the new regression tests.

## Issues

- [minor] `aegys/command_checks.py:42` and `aegys/shell_words.py:67`: `_split_stages_with_ends` in `aegys/command_checks.py:451-486` supersedes `split_stages` for stage tokenization with byte offsets, leaving `split_stages` without production callers outside tests and an unused import in `command_checks.py`. To prevent drift, consolidate both callers onto one offset-returning splitter in `aegys/shell_words.py`.
- [minor] `aegys/command_checks.py:527-529` and `539-541`: Here-strings (`<<<`) are walked for substitutions unconditionally, whereas in bash single-quoted here-strings (`grep x <<< '$(cat ~/.ssh/id_rsa)'`) are literal data. Delimiter quoting should be respected for here-strings or here-strings omitted from heredoc body substitution walks.
- [minor] `aegys/command_checks.py:326-334`: `heredoc_bodies` has no internal callers remaining after `command_stages` switched to `_heredoc_bodies_with_quoting`. The orphaned wrapper function should be deprecated or removed.
- [minor] `aegys/command_checks.py:243-259` and `1507-1533`: Interpreters with option flags taking separate values (e.g. `python3 -W ignore - <<EOF`) can cause the value argument to be interpreted as the script operand, skipping the stdin dash check in deterministic parsing. Known value-taking options should be skipped.
- [minor] `aegys/command_checks.py:429-433` and `531`: Length-preserving underscore masking replaces unquoted backtick spans in outer stage words; at recursion depth >= 3 the substitution walk stops, meaning triply-nested shell strings (`bash -c 'bash -c "eval \"x=\`cat ~/.ssh/id_rsa\`\""'`) rely on classifier inspection rather than deterministic stage checks.

## Recommendations

- Consolidate `split_stages` and `_split_stages_with_ends` into a single canonical stage parser in `aegys/shell_words.py`.
- Remove dead wrapper function `heredoc_bodies` in `aegys/command_checks.py`.
- Add argument parser awareness for separate-value options in `reads_program_from_stdin`.

## Unverified

- None. All 8 files under review were read and hand-traced by Reviewer, Critic, and Chair; Saboteur ran baseline and targeted mutation testing in a throwaway worktree; the full test suite (151 unit tests) was executed and confirmed passing.

## Assessment

Ready to merge: yes. All critical and important findings from Council Round 2 and the Google Jules adversarial review are completely resolved. The implementation adheres strictly to fail-closed security invariants, closes all identified command substitution bypass vectors, correctly bounds user authorization and strike resets, and includes comprehensive regression tests. The 5 remaining findings are minor refactoring and edge-case enhancements that do not block merging.
