# AI coding agents

AI coding agents (Claude Code, Codex, Gemini CLI, …) run commands on your machine and read
their output. sealctl lets them **use** your secrets without **seeing** them:

```sh
sealctl ai install      # every agent found on this machine
sealctl ai status
sealctl ai uninstall    # removes exactly what install added
```

Then, in any agent: copy an API key and say *"store it as myapp/openai"*. The agent runs
`sealctl secret set myapp/openai --from-clipboard`, and later `sealctl run -- <command>` so the
program gets the key while the agent sees only `****`.

## Three layers

1. **sealctl itself** — works with every agent, no setup:
   * `sealctl run` replaces secret values with `****` in everything the program prints, whenever
     it runs inside an agent or its output isn't a terminal.
   * `secret get`, `recover`, `seal`, `unseal`, `buy`, `unpair`, `project trust`, `scan` and `migrate` refuse
     inside an agent (exit 8; detected by the environment variables agents set: `CLAUDECODE`,
     `CODEX_THREAD_ID`, `GEMINI_CLI`, `QWEN_CODE`, `COPILOT_AGENT_SESSION_ID`, `OPENCODE`,
     `AI_AGENT`, …; force with `SEALCTL_AGENT=1`). `SEALCTL_AGENT=0` turns detection off,
     also when those variables are set; it is for you, not the agent (the hooks deny an agent
     setting it), and sealctl then says on stderr, once per command, that detection is off
     although an agent is running.
   * The credential helpers (`sealctl git credential`, `sealctl aws credentials`) answer inside
     an agent only when git or the AWS CLI itself started them: sealctl looks at the executables
     of its parent processes (git's transports such as `git-remote-https`, or `git-lfs`,
     through at most one `sh -c`; the `aws` program). The `git` program itself only passes the
     answer on, so a git alias, pager or hook that runs a helper is refused too. The agent
     calling a helper from its shell, through `sh -c`, or with `git credential fill` gets
     exit 8, whether its output is a pipe or a terminal. Inside an agent, a helper also
     recognises the agent's own program among its parents, so removing the variables does not
     get around it. `git push` and `aws s3 ls` run by an agent work as
     before; a program that uses an AWS SDK directly does not (run it yourself).
   * An agent's first use of a secret in a repository during a session asks the phone (the
     card shows the agent, the repository, the command and the secret names); the phone can
     remember the answer. A person is never asked inside an Open session.
   * When a command prints `Waiting for your phone`, the skill tells the agent to tell you and
     wait, not retry; a decline (exit 4) means stop and ask you.
   * Where the agent cannot see that line either (a signed `git commit`, `git push` through the
     credential helper), a desktop notification says what waits, with the repository and the
     agent: `Approve on your phone: Sign a git commit · sealctl/app · Claude Code`.
   * Nothing secret is printed to a terminal unless asked (`--show`).
2. **Hooks** — checks the agent runs every time:
   * a prompt containing something that looks like a key is **blocked before the model sees it**;
   * shell commands that would reveal secrets (`cat .env`, `printenv`, `echo $API_KEY`,
     `pbpaste`, `sealctl secret get`, `git credential fill`, …) are denied with a hint;
   * sealctl commands are matched by their subcommand, after sealctl's global options and
     through `env`, `command`, `sudo`, `sh -c`, `$(…)` and any path to the binary, so
     `sealctl run -e KEY=shop/buy -- …` is allowed and `env /usr/local/bin/sealctl secret get`
     is not;
   * setting or removing the agent variables (`SEALCTL_AGENT=0 …`, `unset CLAUDECODE`) is
     denied: only you switch detection off;
   * reading `.env` files or private keys, and writing key-like literals into files, is denied;
   * reading `*.sealed`, `machine.json` or sealctl's state folder is denied;
   * each session starts with one line: `sealctl: secrets are available by name through
     sealctl run (names: …). Values are never shown.`
3. **Skill and deny rules** — the `sealctl-secrets` skill (open SKILL.md format) explains the
   workflow; deny rules block the dangerous sealctl commands where the agent supports them
   (`secret get`, `recover`, `seal`, `unseal`, `buy`, `unpair`, `project trust`, `aws credentials`,
   `git credential`, and `git credential fill`). In Claude Code and Qwen Code they also cover
   reading `.env`, `.env.local`, `.env.production` and the like, which keeps those files out of
   a folder-wide search as well. The skill never mentions the price.

What needs which layer: the refusals in layer 1 hold with no setup, in every agent. Everything
in layers 2 and 3 — `.env` reads, environment dumps, `echo $KEY`, clipboard reads,
`git credential fill`, changing the agent variables — holds only where `sealctl ai install` set
up hooks or deny rules, and only as far as the agent runs them (see Limits).

## Support

| Agent | Skill | Hooks | Deny rules | Notes |
|---|---|---|---|---|
| Claude Code | `~/.claude/skills` | `~/.claude/settings.json` | `permissions.deny` | |
| Codex | `~/.agents/skills` | `~/.codex/hooks.json` | `~/.codex/rules/sealctl.rules` | run `/hooks` once to trust new hooks |
| Gemini CLI | `~/.agents/skills` | `~/.gemini/settings.json` | `~/.gemini/policies/sealctl.toml` | |
| Qwen Code | `~/.agents/skills` | `~/.qwen/settings.json` | `permissions.deny` | |
| GitHub Copilot CLI | `~/.agents/skills` | `~/.copilot/hooks/sealctl.json` | — | prompt blocking depends on version; a crashing hook blocks tools (fail closed) |
| Cursor | `~/.agents/skills` | `~/.cursor/hooks.json` | — | the CLI doesn't fire every hook yet |
| OpenCode, Amp, Goose | `~/.agents/skills` | — | — | skill only (their hooks are JS plugins) |
| Antigravity CLI | `~/.gemini/config/skills` | — | — | |
| Kiro | `~/.kiro/skills` | — | — | |

Files sealctl changes are backed up once as `<file>.before-sealctl`.

## Limits — read these

* **Don't paste keys into an agent.** A blocked prompt never reaches the model, but your AI
  tool may still keep it in its local history. If you pasted a real key, rotate it.
* Hooks **fail open** in most agents (if sealctl is missing or crashes, the action proceeds),
  and deny rules match command text, not programs. They stop accidents, not a determined
  attacker. A program you run with `sealctl run` can always read its own secrets.
* The credential helpers' check of who started them reads executable names on the process
  tree. It stops an agent calling them directly, not code running as you that sets out to get
  around it (a copy of a shell named `git-remote-https`, git's trace output with redaction
  off). `git push` run by an agent uses the token, as intended, and the phone logs the use.
* Detection of keys is by pattern (known token formats plus random-looking `key = value`). A
  false alarm can be overridden by starting the prompt with `#nosecret`.
* After `brew upgrade` nothing needs reinstalling: hooks call `/opt/homebrew/bin/sealctl`.
