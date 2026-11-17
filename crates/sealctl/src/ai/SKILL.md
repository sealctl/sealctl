---
name: sealctl-secrets
description: Store and use API keys, tokens and other credentials with sealctl (encrypted with the user's Ledger) without ever seeing their values. Use whenever a task needs a credential — running a command or tests that need an API key, a .env file, "store this key", "which keys do I have", or when the user is about to paste a secret.
---

# Secrets with sealctl

This machine keeps API keys and other credentials in **sealctl**: encrypted with the user's
Ledger hardware wallet, decrypted only into the environment of the program that needs them.
Your job is to let programs **use** secrets while you never **see** them.

## Rules

1. Never ask the user to paste a secret into the chat, and never print, echo, log, `cat` or
   read a secret value — not from `.env` files, the environment, the clipboard or sealctl.
   If a user is about to paste one, stop them: a pasted secret stays in the transcript.
2. Never write a secret value into a file (code, config, `.env`, tests, docs). Reference it by
   environment variable name instead.
3. If a sealctl command is waiting for the Ledger, tell the user what to do on the device
   (turn on / unlock it, open the OpenPGP app, enter the PIN) — sealctl also shows a desktop
   notification. Don't retry in a loop; wait for the user.

## Store a secret

Ask the user to **copy** the key (from the provider's website or their password manager),
then run:

```sh
sealctl secret set <project>/<name> --from-clipboard     # e.g. myapp/openai-api-key
```

It reads the clipboard, stores the value encrypted and clears the clipboard. Names are paths:
`<project>/<what>`, lowercase with dashes. Add `--force` to replace an existing secret.

To move an existing `.env` file into sealctl (you don't need to read it):

```sh
sealctl secret import-env .env --prefix <project> --delete
```

This stores every variable and writes `.sealctl.toml` (variable → secret name), which is safe
to commit.

## Use secrets

```sh
sealctl run -- <command>                       # uses .sealctl.toml in the current directory
sealctl run --env OPENAI_API_KEY=myapp/openai-api-key -- <command>
```

The program gets the real values in its environment. Its output reaches you with every
secret value replaced by `****`, so test output and errors are safe to read. Prefer adding a
mapping to `.sealctl.toml` over ad-hoc `--env`:

```toml
[env]
OPENAI_API_KEY = "myapp/openai-api-key"
```

## Look around (safe)

```sh
sealctl secret ls          # names only
sealctl status             # Ledger, volumes, agent session — no secrets
```

## Never run

`sealctl secret get`, `sealctl ssh passphrase`, `sealctl recover`, `printenv`/`env` dumps,
`echo $SOME_KEY`, `cat .env`, `pbpaste`. sealctl refuses most of these inside an AI agent
anyway; if the user needs a value themselves, they run `sealctl secret get <name> --clip` in
their own terminal.
