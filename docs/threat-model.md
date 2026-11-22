# Threat model

sealctl 0.7: keys derived from 24 words held by the phone app, handed to a paired machine
when the phone approves. Wire formats and keys: [protocol.md](protocol.md).

## Protected against

- **Stolen or lost disk, backup or cloud bucket.** Volumes (APFS, LUKS2, sparse bundles),
  restic repositories and the secret store are encrypted with keys that are never written to
  disk on the machine.
- **A stolen laptop that is Locked or off.** The machine holds only its pairing key; object
  keys come from the phone, which shows the request with the machine's name and asks.
- **The relay.** Requests are sealed to the phone's box key and signed with the pairing key;
  replies are sealed to a one-time key of that request and signed by the phone. The relay sees
  ids, sizes and timing, never a key or a secret name. A recorded reply cannot be opened later:
  the one-time key lives only in memory until the reply arrives.
- **AI agents reading secrets by mistake.** Agents get values only inside the environment of a
  program run with `sealctl run`, whose output is masked; `secret get`, the credential
  helpers, `seal`, `unseal`, `recover` and `buy` refuse inside agents; hooks and deny rules
  stop the common ways of printing secrets. See [ai-agents.md](ai-agents.md).
- **A reflexive tap on a sensitive request.** Handing objects back (`unseal`) and taking over
  existing ones (`seal`) are level 2 (biometrics on the phone, proximity or the number shown at
  the terminal); `unseal --all` is level 3: the number match, a signed plan the CLI cannot leave,
  and a two-hour delay away from a trusted place, announced on every paired machine and
  cancellable from any of them.
- **Losing the phone or the machine.** The 24 words open every object (`sealctl recover`), and
  a phone restored from the same words has the same keys and pairings.

## Not protected against

- **A compromised machine while the session is Open.** The daemon holds the keys in memory and
  answers any process of the same user on its socket (peer uid checked). Mounted volumes are
  plain to anything running as you. Lock (`sealctl lock`, or from the phone) when you step
  away; the idle allowance does it for you.
- **Malware that pretends to be you, not an agent.** Agent detection uses the environment
  variables agents set; it guards against mistakes, not against code that hides them.
- **Programs run with `sealctl run`.** They get the values they are given, by design.
- **A malicious relay holding back or delaying messages.** It cannot forge a reply or release a
  delayed one early (the machine checks the signed not-before time), but it can drop notes and
  messages.
- **Loss of the 24 words.** Unrecoverable by design.

## Assumptions

- The phone's platform keychain and biometrics behave as documented.
- The crates behind sealctl-core (HKDF, HPKE, Ed25519, X25519, ChaCha20-Poly1305, BIP39) and the
  OS tools (APFS, LUKS2, hdiutil, restic) are correct.
- The words are kept on paper, offline, and typed only into the phone app or `sealctl recover`
  and `--words`.
