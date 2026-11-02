<p align="center">
  <img src="assets/logo.svg" alt="aegys logo" width="160">
</p>

<h1 align="center">aegys</h1>

<p align="center">
  <strong>
    Tired of <em>agy</em> asking you for permission on every small thing?<br>
    Longing for the smooth ride of Claude Code's auto mode?<br>
    You've come to the right place.
  </strong>
</p>

---

***aegys*** is a hook for the Antigravity CLI (*agy*). It **looks at each shell command, file read or write, and file search before it runs and decides: let it through, block it, or ask you**. Safe, boring commands run at once. Commands on the deny list never run. Everything in between goes to a small language model, which judges whether the action fits what you asked for.

*aegys* replaces *agy*'s own auto mode, which works only with *agy*'s terminal sandbox switched on. Like Claude Code's auto mode, ***aegys* needs no sandbox**, so **run *agy* in default mode with the sandbox off**. If you leave it on, *aegys* runs the commands it allows outside the sandbox anyway.

## Disclaimer

*aegys* is vibe coded. It guards your machine against one AI agent, and a different AI agent wrote it. **Use it at your own risk.**

## What it does

- Runs commands on a shipped allow list (`git status`, `cat`, `rg`, …) without asking.
- Blocks recursive deletes of critical paths, reads of credential files, and writes to *agy*'s and git's control files and to *aegys* itself.
- Blocks URLs on a deny list and private or cloud-metadata addresses.
- Asks you before `sudo`, `doas`, and commands on your own ask list.
- Sends the rest to a classifier model of your choice, which allows or denies. When the agent retries a denied goal by another route, *aegys* denies again and tells it to change course.
- Allows file reads and writes inside your workspace, except config files such as `.git` or `.bashrc`; checks the rest the same way as commands.
- `/aegys off` hands decisions back to you for one conversation: hard blocks stay, and most commands ask first. `/aegys on` switches the guard back.
- Reads your own allow/ask/deny lists and settings from `~/.gemini/aegys/config.json` on top of the shipped defaults.
- Asks you instead of guessing when its config is broken or the classifier is unreachable.

You choose the classifier model and give *aegys* its API key. The default model is Claude Haiku 5.5 Low.

> **Note:** for now *aegys* speaks only Anthropic's API, so the model must be a Claude model or sit behind an Anthropic-compatible endpoint, and the key goes in `ANTHROPIC_API_KEY`. Support for other providers is tracked in [#13](https://github.com/maxsroda/aegys/issues/13).

## Trust, but verify

Don't take this README's word for it. **Read the code**, starting with the docstring of `aegys/guard.py`, to see exactly what gets allowed. Or ask a coding agent you trust to read it for you.

## License

MIT
