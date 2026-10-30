"""Tests for aegys/vibe_worktree_guard.py: feed it JSON, read its answer.

Nothing here touches a repository or the network; the worktree is a temporary
directory created per test.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


from aegys import vibe_worktree_guard as guard

SCRIPT = Path(__file__).resolve().parents[1] / "aegys" / "vibe_worktree_guard.py"


class WorktreeGuardCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve() / "wt"
        self.root.mkdir()
        self.env = {guard.GUARD_ENV: str(self.root)}

    def tearDown(self):
        self.tmp.cleanup()

    def bash(self, command, env=None):
        payload = {"tool_name": "bash", "tool_input": {"command": command}, "cwd": str(self.root)}
        return guard.decide(payload, self.env if env is None else env)[0]

    def edit(self, path, tool="edit"):
        payload = {"tool_name": tool, "tool_input": {"file_path": path}, "cwd": str(self.root)}
        return guard.decide(payload, self.env)[0]


class TestInactive(WorktreeGuardCase):
    def test_without_the_env_var_everything_passes(self):
        self.assertEqual(self.bash("git push origin main", env={}), "pass")
        payload = {"tool_name": "write_file", "tool_input": {"file_path": "/etc/hosts"}, "cwd": "/"}
        self.assertEqual(guard.decide(payload, {})[0], "pass")


class TestFileTools(WorktreeGuardCase):
    def test_inside_passes(self):
        for path in ("src/a.ts", str(self.root / "e2e" / "x.ts"), "./tmp/scratch.md"):
            self.assertEqual(self.edit(path), "pass", path)

    def test_outside_is_denied(self):
        for path in ("../other/a.ts", "/etc/hosts", str(Path.home() / ".zshrc")):
            for tool in ("edit", "write_file", "search_replace"):
                self.assertEqual(self.edit(path, tool), "deny", (tool, path))

    def test_symlink_out_of_the_worktree_is_denied(self):
        outside = Path(self.tmp.name).resolve() / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        self.assertEqual(self.edit("link/file.txt"), "deny")

    def test_the_git_pointer_file_is_denied(self):
        """Rewriting <worktree>/.git would point every later git command at another repository."""
        for path in (".git", str(self.root / ".git"), ".git/config"):
            self.assertEqual(self.edit(path, "write_file"), "deny", path)


class TestBash(WorktreeGuardCase):
    def test_ordinary_work_passes(self):
        for command in (
            "npm run --silent typecheck",
            "bash scripts/test.sh 2>&1 | tail -20",
            "git add -A && git commit -qm 'M1: thing'",
            "git status --short; git diff --stat",
            "git config --get user.name",
            "mkdir -p tmp/scratch && cp src/a.ts tmp/scratch/",
            "rm -f tmp/probe.mts e2e/debug.e2e.ts",
            "npx playwright test -c e2e/playwright.config.ts --grep 'saves'",
            "ls /tmp/pal-x /private/var/folders/ab/T/y",
            "cat %s/src/a.ts" % self.root,
            "sed -n '1,20p' src/a.ts",
        ):
            self.assertEqual(self.bash(command), "pass", command)

    def test_shared_git_state_is_denied(self):
        for command in (
            "git config user.email t@t.test",
            "git -C . config --local user.name T",
            "git init -q",
            "cd tmp && git init",
            "git push origin HEAD",
            "git remote add x https://example.com/x.git",
            "git reset --hard HEAD~1",
            "git clean -fdx",
            "git worktree add ../x",
            "git stash drop",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_network_and_system_commands_are_denied(self):
        for command in ("curl https://example.com", "wget x", "ssh host ls", "sudo ls",
                        "brew install jq", "npm install -g tsx", "pip install requests",
                        "osascript -e 'beep'", "defaults write com.x y 1", "echo a | nc h 1"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_commands_that_print_the_environment_are_denied(self):
        for command in ("env", "env | head -3", "printenv", "printenv HOME", "env -i",
                        "env FOO=1", "echo a && env", "/usr/bin/env", "(printenv)",
                        "git status; env | sort", "env -0"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_env_that_runs_a_command_is_not_a_dump(self):
        for command in ("env FOO=1 git status", "env -u HOME ls", "echo env", "rg env src",
                        "git log --grep=printenv", "env -S 'ls -la'"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_paths_outside_are_denied(self):
        for command in ("cat /etc/passwd", "cp src/a.ts /usr/someone/else.ts",
                        "ls ~/Library", "rm -rf ../other", "rm -f *", "rm -rf $HOME/x",
                        "cat /tmp/../etc/passwd", "cat /usr/x/../../etc/hosts"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_relative_paths_and_regexes_are_not_paths(self):
        for command in ("grep -rn 'a/b' src/main", "sed -n 's/a/b/p' src/x.ts",
                        "node --import tsx --test src/**/*.test.ts",
                        "rg -n \"@/lib/utils\" src", "rg 'from \"@/components' src",
                        "grep -rn '/api/users' src", "npx playwright test --grep '/api/'",
                        "npm run build -- --base=/app/",
                        "cat /usr/share/dict/words", "ls /opt/homebrew/lib", "cat /dev/stdin"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_words_in_messages_and_paths_are_not_git_subcommands(self):
        for command in (
            "git commit -m \"load config from env\"", "git diff src/config.ts",
            "git add config.toml", "git add src/init.ts", "git commit -m \"init the parser\"",
            "git commit -m \"push notifications\"", "git commit -m \"add worktree docs\"",
            "git commit -m \"remote add-on\"", "git commit -m \"clean up -f flag handling\"",
            "git log --oneline -- init/", "git config user.name",
            "git commit -m 'see https://github.com/x/y/issues/1'",
            "git commit -m 'fix /etc/hosts parsing'",
        ):
            self.assertEqual(self.bash(command), "pass", command)

    def test_rm_inside_the_worktree_passes(self):
        for command in ("rm -rf tmp/*", "rm -f *.log", "rm -rf tmp/scratch dist"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_rm_of_the_whole_worktree_or_its_git_pointer_is_denied(self):
        for command in ("rm -rf .", "rm -rf ./*", "rm .git", "cp x .git", "mv a %s/.git" % self.root):
            self.assertEqual(self.bash(command), "deny", command)

    def test_relative_writes_outside_are_denied(self):
        for command in ("cp src/a.ts ../other/", "mv x ../../y", "touch ../x", "mkdir -p ../new",
                        "ln -s src ../link"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_symlinks_are_resolved_before_the_allowed_prefixes(self):
        """The temporary directory is an allowed prefix; a link in it to $HOME is not."""
        link = Path(self.tmp.name).resolve() / "escape"
        link.symlink_to(Path.home())
        self.assertEqual(self.bash("cat %s/.zshrc" % link), "deny")

    def test_an_unparsable_command_is_denied(self):
        self.assertEqual(self.bash("echo \"unbalanced"), "deny")


class TestSharedRefs(WorktreeGuardCase):
    def test_ref_rewrites_are_denied(self):
        for command in (
            "git branch -D doomed", "git branch -f probe HEAD", "git branch -m a b",
            "git branch -M a b", "git branch --delete x", "git branch -dr origin/x",
            "git branch --set-upstream-to=origin/main", "git tag -d v1.0", "git tag -f v1 HEAD",
            "git symbolic-ref HEAD refs/heads/main", "git gc --prune=now",
            "git reflog expire --expire=now --all", "git notes add -m x",
            "git checkout -B main", "git switch -C main", "git update-ref -d refs/heads/x",
            "git fetch origin", "git pull", "git clone https://example.com/x.git",
            "git -c core.hooksPath=/tmp/h commit -m x", "git -C ../other status",
            "git --git-dir=/Users/x/repo/.git log",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_ref_reads_pass(self):
        for command in ("git branch --show-current", "git branch --list", "git branch -vv",
                        "git symbolic-ref HEAD", "git tag --list", "git notes show HEAD",
                        "git reflog", "git checkout -b feature", "git switch -c feature",
                        "git -C tmp/x status"):
            self.assertEqual(self.bash(command), "pass", command)


class TestInlineCode(WorktreeGuardCase):
    def test_inline_code_is_denied(self):
        for command in (
            "npx tsx -e \"console.log(1)\"", "npx --yes tsx -e x", "npx -y tsx --eval x",
            "node --import tsx -e \"require('child_process').execSync('git push')\"",
            "node -p 1", "node --eval=1", "tsx -e x", "npx tsx@4 -e x", "python3 -c 'print(1)'",
            "perl -e 1", "npx -c 'git push'", "npm exec -- tsx -e x",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_scripts_and_test_runners_pass(self):
        for command in ("npx tsx scripts/gen.ts", "node --import tsx --test src/a.test.ts",
                        "python3 -m unittest -v", "npx playwright test -c e2e/x.ts",
                        "node scripts/build.mjs --prod"):
            self.assertEqual(self.bash(command), "pass", command)


class TestWrappers(WorktreeGuardCase):
    def test_wrapped_and_nested_commands_are_checked(self):
        for command in (
            "bash -c \"git push\"", "sh -lc 'curl https://x.test'", "find . -exec git push \\;",
            "env git push", "env X=1 git push", "command git push", "xargs -I {} git push",
            "timeout 5 git push", "echo `git push`", "echo \"$(git push)\"", "eval git push",
            "/usr/bin/git push", "GIT_DIR=/Users/x/.git git log",
        ):
            self.assertEqual(self.bash(command), "deny", command)


class TestExtraDirectories(WorktreeGuardCase):
    def test_extra_directory_counts_as_inside(self):
        exchange = Path(self.tmp.name).resolve() / "exchange"
        exchange.mkdir()
        env = {**self.env, guard.EXTRA_ENV: str(exchange)}
        payload = {"tool_name": "write_file", "tool_input": {"file_path": str(exchange / "report.md")},
                   "cwd": str(self.root)}
        self.assertEqual(guard.decide(payload, env)[0], "pass")
        self.assertEqual(guard.decide(payload, self.env)[0], "deny")


class TestUnifiedHarnessNames(WorktreeGuardCase):
    def test_dotted_tool_names_get_the_same_rules(self):
        """The unified harness sends `file_system.bash` / `file_system.search_replace`."""
        bash = {"tool_name": "file_system.bash", "tool_input": {"command": "git push"},
                "cwd": str(self.root)}
        self.assertEqual(guard.decide(bash, self.env)[0], "deny")
        edit = {"tool_name": "file_system.write_file", "tool_input": {"file_path": "/etc/x"},
                "cwd": str(self.root)}
        self.assertEqual(guard.decide(edit, self.env)[0], "deny")


class TestOptionValuesAndGitPointer(WorktreeGuardCase):
    """A path can hide in an option value, attached (`--output=../x`) or separate."""

    def test_option_values_leaving_the_worktree_are_denied(self):
        for command in (
            "git show -s --output=../body.txt HEAD",
            "git show -s --output=../../../../etc/hosts HEAD",
            "git show --output ../body.txt HEAD",
            "git log --output=/etc/hosts", "git log --output=~/f", "git log --output=$HOME/f",
            "cp --target-directory=../out src/a.ts",
            "git commit -F ../msg", "git commit -t ../tmpl",
            "git add --pathspec-from-file=../list", "cat ../secret",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_option_values_inside_the_worktree_pass(self):
        for command in (
            "git show -s --format=%B --output=tmp/body.txt HEAD",
            "git log --pretty=format:%s --since=2.days.ago -- src/a.ts",
            "git diff --stat main...feature", "rg --glob=src/**/*.ts foo",
            "git commit -F tmp/msg.txt", "git add .gitignore", "cat .gitignore", "ls .github",
        ):
            self.assertEqual(self.bash(command), "pass", command)

    def test_no_command_may_name_the_git_pointer(self):
        """`git show --output=.git` rewrites the pointer file and retargets the worktree."""
        for command in (
            "git show -s --output=.git HEAD", "git show --output .git HEAD",
            "git show --output=%s/.git HEAD" % self.root, "tee .git", "cp tmp/p .git",
            "echo 'gitdir: /x' > .git", "echo x >> ./.git", "git log -- .git",
            "git show --output=.GIT HEAD", "cp tmp/p .Git", "echo x > .GIT",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_the_git_pointer_in_any_letter_case_is_denied_for_file_tools(self):
        for path in (".GIT", ".Git/config", str(self.root / ".GIT")):
            self.assertEqual(self.edit(path, "write_file"), "deny", path)

    def test_reading_or_excluding_the_git_pointer_passes(self):
        for command in (
            "find . -path ./.git -prune -o -type f -print", "find . -not -path './.git/*' -name '*.ts'",
            "grep -rn --exclude-dir=.git foo .", "fd -E .git ts", "tree -a -I .git", "du -sh .git",
            "ls -a .git", "git check-ignore -v .git", "cat .git", "rg --glob '!.git' foo",
        ):
            self.assertEqual(self.bash(command), "pass", command)
        for command in ("find .git -delete", "find . -fprint .git", "find .git -exec rm {} +"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_globs_that_expand_to_dotdot_or_the_git_pointer_are_denied(self):
        """The shell expands `.?` to `..` and `.gi?` to `.git` after the guard has looked."""
        for command in (
            "cp src/a.ts .?/x", "mv src/a.ts .?/x", "touch .?/x", "mkdir .?/d", "cp -R src .?/",
            "rm -rf .?/*", "cp src/a.ts .[.]/x", "cp src/a.ts .*/x", "ln -s .? up",
            "cp tmp/p .gi?", "cp tmp/p .gi[t]", "cp tmp/p .g*", "cp tmp/p .G?T",
            "git show -s --output .gi? HEAD", "git show --output=.g* HEAD", "git show --output .?/y HEAD", "git show --output={..,.}/x HEAD",
            "cp src/a.ts {.,x}./y", "echo x > .?/y", "echo x > {.,.}./y",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_globs_that_stay_inside_pass(self):
        for command in ("rm -f *.log", "rm -rf tmp/*", "cp src/*.ts tmp/", "rm -f .*.swp",
                        "cp src/a.ts {tmp,dist}/", "echo x > tmp/*.txt", "sed 's/.*//' src/a.ts",
                        "cp tmp/p src/.g*"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_patterns_that_look_like_relative_paths_pass(self):
        for command in ("rg -F '../lib' src", "grep -rn '../utils' src", "cat src/a.ts | grep -c '../'",
                        "git log --grep='..' --oneline", "git log --grep '..' --oneline",
                        "git log -S '../lib' --oneline", "git grep '../lib' -- src",
                        "rg -e '.git' src", "grep -rn .git README.md"):
            self.assertEqual(self.bash(command), "pass", command)
        self.assertEqual(self.bash("git log --output ../x"), "deny")

    def test_search_programs_may_read_relative_paths_outside(self):
        for command in ("rg foo ../lib", "grep -rn foo ../lib"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_redirect_targets_are_resolved_through_symlinks(self):
        outside = Path(self.tmp.name).resolve() / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        for command in ("echo x > link/f", "echo x >> link/f", "echo x 2>link/f"):
            self.assertEqual(self.bash(command), "deny", command)
        self.assertEqual(self.bash("echo x > tmp/f"), "pass")

    def test_git_dirs_are_resolved_through_symlinks(self):
        outside = Path(self.tmp.name).resolve() / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        for command in ("git -C link status", "git --git-dir link log", "git --git-dir=link log",
                        "git --work-tree link status", "git --work-tree=link status"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_paths_that_cannot_be_resolved_are_denied_with_a_reason(self):
        for command in ('cat "/tmp/\x00x"', "ls ~nosuchuser/x", "rm -rf ~nosuchuser",
                        "cat --file=~nosuchuser/x"):
            payload = {"tool_name": "bash", "tool_input": {"command": command}, "cwd": str(self.root)}
            decision, reason = guard.decide(payload, self.env)
            self.assertEqual(decision, "deny", command)
            self.assertIn("cannot", reason, command)


class TestSymlinksAndSpellings(WorktreeGuardCase):
    def setUp(self):
        super().setUp()
        self.outside = Path(self.tmp.name).resolve() / "outside"
        self.outside.mkdir()
        (self.root / "link").symlink_to(self.outside)

    def test_a_writer_operand_through_a_symlink_is_denied(self):
        self.assertEqual(self.bash("cp src/a.ts link/f"), "deny")

    def test_reading_through_a_symlink_passes(self):
        """pnpm and npm link into directories outside the worktree; only writes are held."""
        self.assertEqual(self.bash("cat link/f"), "pass")
        self.assertEqual(self.bash("cat -n link/f"), "pass")

    def test_only_the_redirect_target_is_checked_after_a_redirect(self):
        self.assertEqual(self.bash("echo x > tmp/f link/g"), "pass")

    def test_home_variable_spellings_are_denied(self):
        for command in ("rm -rf ${HOME}/x", "rm -rf $HOME/x", "cp a ${HOME}"):
            self.assertEqual(self.bash(command, env={**self.env, "HOME": "/etc"}), "deny", command)

    def test_an_equals_sign_inside_an_option_value_is_not_a_split_point(self):
        self.assertEqual(self.bash("git log --pretty=format:x=../y"), "pass")

    def test_file_tools_deny_unresolvable_paths_with_a_reason(self):
        for path in ("a\x00", "~nosuch/x"):
            payload = {"tool_name": "write_file", "tool_input": {"path": path}, "cwd": str(self.root)}
            decision, reason = guard.decide(payload, self.env)
            self.assertEqual(decision, "deny", path)
            self.assertIn("cannot", reason)


class TestOtherWriters(WorktreeGuardCase):
    """Writers beyond cp/mv/rm: dd, archivers, sort -o, sed -i, and the program word itself."""

    def test_dd_reads_its_of_operand_as_a_path(self):
        for command in ("dd of=/etc/hosts", "dd of=~/.zshrc", "dd of=../x", "dd of=.git",
                        "dd of=.GIT", "dd if=src/a.ts of=.?/x", "dd of=$HOME/x"):
            self.assertEqual(self.bash(command), "deny", command)
        self.assertEqual(self.bash("dd if=src/a.ts of=tmp/copy bs=1k"), "pass")

    def test_archivers_and_output_options_are_held_to_the_worktree(self):
        for command in ("tar cf .?/x .", "tar cf ../x.tar .", "zip .?/x src", "gzip .?/x",
                        "sort -o .?/x data", "sort --output .?/x data", "sort -o ../x data", "sort --output=../x data",
                        "xz .?/x", "tar xf a.tar -C ../out"):
            self.assertEqual(self.bash(command), "deny", command)
        for command in ("tar czf tmp/x.tgz src", "zip -r tmp/x.zip src", "sort -o tmp/x data",
                        "sort -k 2 -t , data.csv", "gzip -k tmp/x"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_every_added_writer_holds_its_operands(self):
        outside = Path(self.tmp.name).resolve() / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        for command in ("bzip2 link/x", "gunzip link/x.gz", "split -b 1k src/a.ts link/p",
                        "ditto src link/d", "unzip a.zip -d link", "xz link/x", "dd if=../x of=tmp/y",
                        "dd if=link/x of=tmp/y"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_every_writer_holds_its_operand_through_a_symlink(self):
        """Through a symlink no `..` shows, so only the writer rule can stop it."""
        outside = Path(self.tmp.name).resolve() / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)
        for program in ("rm", "rmdir", "unlink", "mv", "cp", "ln", "mkdir", "touch", "chmod", "tee",
                        "truncate", "install", "patch", "dd", "tar", "zip", "unzip", "gzip", "gunzip",
                        "bzip2", "xz", "split", "ditto"):
            self.assertEqual(self.bash("%s link/x" % program), "deny", program)

    def test_a_slash_as_an_option_value_is_a_path_except_as_a_sort_delimiter(self):
        for command in ("tar xf a.tar -C /", "tar xf a.tar --directory /", "tar -C / -xf a.tar",
                        "unzip a.zip -d /", "cp -t / src/a.ts", "mv -t / src/a.ts",
                        "install -t / src/a.ts", "sort -o / data"):
            self.assertEqual(self.bash(command), "deny", command)
        self.assertEqual(self.bash("sort -t / data"), "pass")
        self.assertEqual(self.bash("sort -T / data"), "deny")

    def test_search_options_that_name_files_are_paths(self):
        for command in ("rg --files /etc", "rg --files /etc/passwd", "rg -f /etc/passwd",
                        "grep -f /etc/passwd src/a.ts", "git grep -e x /etc/hosts", "git grep -f /etc/passwd x", "grep --file /etc/passwd src/a.ts"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_the_word_grep_elsewhere_in_a_git_command_exempts_nothing(self):
        for command in ("git log --author grep /etc/hosts", "git commit -m grep /etc/hosts",
                        "git commit -m grep ../x", "git log --author grep ../x"):
            self.assertEqual(self.bash(command), "deny", command)
        self.assertEqual(self.bash("git -C tmp grep '/etc/hosts'"), "pass")

    def test_a_git_message_is_not_a_path(self):
        for command in ("git commit -m '/etc/hosts'", "git commit --message '/etc/hosts'",
                        "git commit --message=/etc/hosts"):
            self.assertEqual(self.bash(command), "pass", command)
        self.assertEqual(self.bash("zip -m ../x src"), "deny")

    def test_dd_scratch_copies_from_the_device_files_pass(self):
        for command in ("dd if=/dev/zero of=tmp/x bs=1 count=1", "dd if=/dev/urandom of=tmp/x bs=100 count=1",
                        "dd if=/dev/random of=tmp/x bs=1 count=1"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_archives_may_exclude_the_git_pointer(self):
        for command in ("tar czf tmp/x.tgz . --exclude ./.git", "tar cf tmp/x . --exclude=.git",
                        "zip -r tmp/x.zip . -x ./.git"):
            self.assertEqual(self.bash(command), "pass", command)
        self.assertEqual(self.bash("tar czf tmp/x.tgz .git"), "deny")

    def test_sort_delimiters_are_not_paths(self):
        for command in ("sort -t / data", "sort -k 2 -t , data.csv", "sort -t: -k2 data"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_a_search_pattern_that_names_a_system_path_passes(self):
        for command in ("rg '/etc/hosts' src", "grep -rn '/var/log/system.log' src",
                        "git log -S '/etc/hosts' --oneline", "git grep '/etc/hosts'",
                        "rg -e '/etc/hosts' src"):
            self.assertEqual(self.bash(command), "pass", command)
        for command in ("rg foo /etc/hosts", "grep -rn foo /etc"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_sed_in_place_is_denied(self):
        for command in ("sed -i s/a/b/ src/a.ts", "sed -i.bak s/a/b/ src/a.ts", "sed -ni p src/a.ts",
                        "sed --in-place s/a/b/ src/a.ts", "sed -i s/a/b/ .?/x",
                        "sed -E -i s/a/b/ src/a.ts", "sed -n -i p src/a.ts"):
            self.assertEqual(self.bash(command), "deny", command)
        self.assertEqual(self.bash("sed -n 1,5p src/a.ts"), "pass")
        self.assertEqual(self.bash("sed -E 's/a/b/' src/a.ts"), "pass")

    def test_the_program_word_is_a_path_too(self):
        for command in ("../x", "../scripts/build.sh --prod", "~/x.sh", "$HOME/x.sh", "/etc/x.sh",
                        "~root/x.sh"):
            self.assertEqual(self.bash(command), "deny", command)
        for command in ("./node_modules/.bin/tsc --noEmit", "/usr/bin/git status", "bash scripts/test.sh"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_the_clobber_redirect_is_a_redirect(self):
        for command in ("echo x >| .?/y", "echo x >| ../y", "echo x &> ../y", "echo x >| .git"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_echo_and_printf_print_their_words(self):
        for command in ("echo $HOME", "echo ${HOME}", "echo /etc/passwd", "printf '%s' ../x"):
            self.assertEqual(self.bash(command), "pass", command)
        for command in ("echo $HOME > /etc/x", "printf x > ../x"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_globs_and_braces_are_resolved_only_where_a_write_can_follow(self):
        """Pins the gate: a non-writer's word is not expanded, so a read may name them."""
        self.assertEqual(self.bash("cat {.,x}./y"), "pass")
        self.assertEqual(self.bash("cat src/../.?/x"), "pass")
        self.assertEqual(self.bash("cp src/../.?/x tmp/"), "deny")


class TestCompoundCommands(WorktreeGuardCase):
    """`{ git push; }` and loop bodies run their words; the keyword is not the program."""

    def setUp(self):
        super().setUp()
        outside = Path(self.tmp.name).resolve() / "outside"
        outside.mkdir()
        (self.root / "link").symlink_to(outside)

    def test_the_command_after_a_compound_keyword_is_checked(self):
        for command in (
            "{ git push; }", "{ curl https://example.com; }", "{ git config user.email t@t.test; }",
            "{ pip install requests; }", "{ sudo ls; }", "{ python3 -c 'print(1)'; }",
            "{ sed -i s/a/b/ src/a.ts; }", "{ dd of=.git if=src/a.ts; }",
            "if true; then git push; fi", "if git push; then :; fi", "until git push; do :; done",
            "while true; do git push; done", "for i in 1; do git push; done",
            "true && { git push; }", "! git push", "if true; then :; else git push; fi",
            "if false; then :; elif git push; then :; fi", "{ cp src/a.ts .?/x; }",
            "{ cp src/a.ts link/f; }", "case x in x) git push;; esac",
            "for f in a; do git push; done", "while git push; do :; done",
            "coproc git push", "coproc { git push; }", "coproc P { git push; }",
            "function p { git push; }; p", "function p { git push; }",
            "cat <(git push)", "cat < <(git push)", "diff <(git push) <(git log)",
            "while read l; do echo $l; done < <(git push)", "tee >(git push)",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_compound_commands_of_allowed_words_pass(self):
        for command in ("cat <(git log --oneline)", "diff <(git show a:f) <(git show b:f)",
                        "{ git status; git diff --stat; }", "if test -f src/a.ts; then cat src/a.ts; fi",
                        "for f in src/*.ts; do wc -l $f; done", "while read l; do echo $l; done < tmp/x",
                        "! git diff --quiet"):
            self.assertEqual(self.bash(command), "pass", command)


class TestModuleLoaders(WorktreeGuardCase):
    def test_modules_from_data_and_http_urls_are_denied(self):
        for command in (
            "node --import 'data:text/javascript,console.log(1)' m.mjs",
            "node --test --import 'data:text/javascript,1' m.mjs",
            "node --import=data:text/javascript,1 m.mjs",
            "node --import tsx --import \"data:text/javascript,1\" src/a.ts",
            "node --require data:text/javascript,1 m.js", "node -r data:text/javascript,1 m.js",
            "node --experimental-loader https://example.com/l.mjs m.mjs",
            "node --loader=http://example.com/l.mjs m.mjs",
            "npx tsx --import data:text/javascript,1 a.ts", "node --import=DATA:text/javascript,1 m.mjs",
            "node --test --test-reporter=data:text/javascript,1 m.mjs",
            "node --test --test-reporter https://example.com/r.mjs m.mjs",
        ):
            self.assertEqual(self.bash(command), "deny", command)

    def test_combined_eval_flags_are_denied(self):
        for command in ("node -pe 1", "node -ep 1", "node --import tsx -pe 1", "npx tsx -pe 1"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_module_loaders_naming_packages_and_files_pass(self):
        for command in ("node --import tsx --test src/a.test.ts", "node -r ./tmp/setup.cjs m.js",
                        "node --loader ts-node/esm m.ts", "node --import=tsx m.ts"):
            self.assertEqual(self.bash(command), "pass", command)


class TestRuleCoverage(WorktreeGuardCase):
    """One case per rule, so deleting the rule fails a test."""

    def test_every_denied_git_subcommand(self):
        for sub in ("init", "push", "fetch", "pull", "clone", "ls-remote", "send-email", "worktree",
                    "update-ref", "filter-branch", "filter-repo", "replace", "gc", "prune",
                    "fast-import"):
            self.assertEqual(self.bash("git %s x" % sub), "deny", sub)

    def test_every_remote_change(self):
        for sub in ("add", "set-url", "remove", "rm", "rename", "set-head", "set-branches",
                    "prune", "update"):
            self.assertEqual(self.bash("git remote %s origin" % sub), "deny", sub)
        self.assertEqual(self.bash("git remote -v"), "pass")

    def test_git_config_write_flags(self):
        for command in ("git config --unset user.name", "git config --unset-all user.name",
                        "git config --edit", "git config -e", "git config --remove-section x",
                        "git config --rename-section a b", "git config --add a b",
                        "git config --replace-all a b"):
            self.assertEqual(self.bash(command), "deny", command)
        for command in ("git config --list", "git config -l", "git config --get-regexp user"):
            self.assertEqual(self.bash(command), "pass", command)

    def test_node_options_cannot_smuggle_code(self):
        for command in ("npx --node-options=--eval=1 tsx a.ts", "npx --node-options '--eval 1' tsx a.ts",
                        "npm exec --node-options=--eval=1 -- tsx a.ts",
                        "NODE_OPTIONS=--import=x node a.js", "env NODE_OPTIONS=--import=x node a.js"):
            self.assertEqual(self.bash(command), "deny", command)

    def test_npx_options_that_take_a_value_are_skipped(self):
        for command in ("npx -p typescript tsx -e x", "npx --package typescript tsx -e x",
                        "npx --package=typescript tsx -e x"):
            self.assertEqual(self.bash(command), "deny", command)
        self.assertEqual(self.bash("npx -p typescript tsx a.ts"), "pass")


class TestProtocol(WorktreeGuardCase):
    def run_script(self, payload, env):
        proc = subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(payload),
                              capture_output=True, text=True, env={**os.environ, **env})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return proc.stdout

    def test_deny_prints_json_with_a_reason(self):
        out = self.run_script({"tool_name": "bash", "tool_input": {"command": "git push"},
                               "cwd": str(self.root)}, self.env)
        answer = json.loads(out)
        self.assertEqual(answer["decision"], "deny")
        self.assertTrue(answer["reason"])

    def test_pass_prints_nothing(self):
        env = {k: v for k, v in os.environ.items() if k != guard.GUARD_ENV}
        proc = subprocess.run([sys.executable, str(SCRIPT)],
                              input=json.dumps({"tool_name": "bash", "tool_input": {"command": "ls"}}),
                              capture_output=True, text=True, env=env)
        self.assertEqual((proc.returncode, proc.stdout), (0, ""))


if __name__ == "__main__":
    unittest.main()
