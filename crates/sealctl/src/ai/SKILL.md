---
name: sealctl-secrets
description: Store and use API keys, tokens and other credentials with sealctl (approved on the user's phone) without ever seeing their values. Use whenever a task needs a credential — running a command or tests that need an API key, a .env file, "store this key", "which keys do I have", or when the user is about to paste a secret.
---

# Secrets with sealctl

This machine keeps API keys and other credentials in **sealctl**: sealed with keys that the
user's phone hands out, opened only into the environment of the program that needs them.
Your job is to let programs **use** secrets while you never **see** them. Values are never
needed: use `sealctl run`.

## Rules

1. Never ask the user to paste a secret into the chat, and never print, echo, log, `cat` or
   read a secret value — not from `.env` files, the environment, the clipboard or sealctl.
   If a user is about to paste one, stop them: a pasted secret stays in the transcript.
2. Never write a secret value into a file (code, config, `.env`, tests, docs). Reference it by
   environment variable name instead.
3. When a sealctl command prints `Waiting for your phone`, tell the user to approve on their
   phone and wait. Do not retry or loop.
4. A declined request (exit code 4) means stop and ask the user what they want.

## Store a secret

Ask the user to **copy** the key (from the provider's website or their password manager),
then run:

```sh
sealctl secret set <project>/<name> --from-clipboard     # e.g. myapp/openai-api-key
```

It reads the clipboard, stores the value sealed and clears the clipboard. Names are paths:
`<project>/<what>`, lowercase with dashes. Add `--force` to replace an existing secret.

To move an existing `.env` file into sealctl, tell the user to run (you don't need to read it):

```sh
sealctl seal env .env --prefix <project> --delete
```

This stores every variable and writes `.sealctl.toml` (variable → secret name), which is safe
to commit.

## Use secrets

```sh
sealctl run -- <command>                       # uses .sealctl.toml in the current directory
sealctl run -e OPENAI_API_KEY=myapp/openai-api-key -- <command>
```

The program gets the real values in its environment. Its output reaches you with every
secret value replaced by `****`, so test output and errors are safe to read. Prefer adding a
mapping to `.sealctl.toml` over ad-hoc `-e`:

```toml
[env]
OPENAI_API_KEY = "myapp/openai-api-key"
```

sealctl trusts a `.sealctl.toml` on first use: after you add or change one, the user's own next
`sealctl run` there asks them to trust it. That is expected; never run `sealctl project trust`.

## Look around (safe)

```sh
sealctl secret ls          # names only
sealctl status             # session, volumes, this machine — no secrets
```

## Never run

`sealctl secret get`, `sealctl recover`, `sealctl seal`, `sealctl unseal`, `sealctl unpair`,
`sealctl project trust`, the credential helpers (`sealctl git credential`, `sealctl aws credentials`), `printenv`/`env`
dumps, `echo $SOME_KEY`, `cat .env`, `pbpaste`, `git credential fill`. sealctl itself refuses
the sealctl ones inside an AI agent (the credential helpers answer only git and the AWS CLI
themselves, so `git push` and `aws …` work); the installed hooks deny the others. If the user
needs a value themselves, they run `sealctl secret get <name> --clip` in their own terminal.
