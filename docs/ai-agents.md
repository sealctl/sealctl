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
   * `secret get`, `recover`, `seal`, `unseal`, `buy`, `unpair` and the credential helpers
     refuse inside an agent (detected by the environment variables agents set: `CLAUDECODE`,
     `CODEX_THREAD_ID`, `GEMINI_CLI`, `QWEN_CODE`, `COPILOT_AGENT_SESSION_ID`, `OPENCODE`,
     `AI_AGENT`, …; force with `SEALCTL_AGENT=1`).
   * An agent's first use of a secret in a repository during a session asks the phone (the
     card shows the agent, the repository, the command and the secret names); the phone can
     remember the answer. A person is never asked inside an Open session.
   * When a command prints `Waiting for your phone`, the skill tells the agent to tell you and
     wait, not retry; a decline (exit 4) means stop and ask you.
   * Nothing secret is printed to a terminal unless asked (`--show`).
2. **Hooks** — checks the agent runs every time:
   * a prompt containing something that looks like a key is **blocked before the model sees it**;
   * shell commands that would reveal secrets (`cat .env`, `printenv`, `echo $API_KEY`,
     `pbpaste`, `sealctl secret get`, …) are denied with a hint;
   * reading `.env` files or private keys, and writing key-like literals into files, is denied;
   * reading `*.sealed`, `machine.json` or sealctl's state folder is denied;
   * each session starts with one line: `sealctl: secrets are available by name through
     sealctl run (names: …). Values are never shown.`
3. **Skill and deny rules** — the `sealctl-secrets` skill (open SKILL.md format) explains the
   workflow; deny rules block the dangerous sealctl commands where the agent supports them
   (`secret get`, `recover`, `seal`, `unseal`, `buy`, `unpair`, `aws credentials`,
   `git credential`). The skill never mentions the price.

## Support

| Agent | Skill | Hooks | Deny rules | Notes |
|---|---|---|---|---|
| Claude Code | `~/.claude/skills` | `~/.claude/settings.json` | `permissions.deny` | |
| Codex | `~/.agents/skills` | `~/.codex/hooks.json` | `~/.codex/rules/sealctl.rules` | run `/hooks` once to trust new hooks |
| Gemini CLI | `~/.agents/skills` | `~/.gemini/settings.json` | `~/.gemini/policies/sealctl.toml` | |
| Qwen Code | `~/.agents/skills` | `~/.qwen/settings.json` | `permissions.deny` | |
| GitHub Copilot CLI | `~/.agents/skills` | `~/.copilot/hooks/sealctl.json` | — | prompt blocking depends on version; a crashing hook blocks tools (fail closed) |
| Cursor | `~/.agents/skills` | `~/.cursor/hooks.json` | — | the CLI doesn't fire every hook yet |
| OpenCode, Amp, Goose | `~/.agents/skills` | — | — | hooks need JS plugins; planned |
| Antigravity CLI | `~/.gemini/config/skills` | — | — | |
| Kiro | `~/.kiro/skills` | — | — | |

Files sealctl changes are backed up once as `<file>.before-sealctl`.

## Limits — read these

* **Don't paste keys into an agent.** A blocked prompt never reaches the model, but your AI
  tool may still keep it in its local history. If you pasted a real key, rotate it.
* Hooks **fail open** in most agents (if sealctl is missing or crashes, the action proceeds),
  and deny rules match command text, not programs. They stop accidents, not a determined
  attacker. A program you run with `sealctl run` can always read its own secrets.
* Detection of keys is by pattern (known token formats plus random-looking `key = value`). A
  false alarm can be overridden by starting the prompt with `#nosecret`.
* After `brew upgrade` nothing needs reinstalling: hooks call `/opt/homebrew/bin/sealctl`.
