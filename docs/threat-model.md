# Threat model

## Protected against

- **Stolen or lost disk / backup / cloud bucket** — data is encrypted (APFS/LUKS2, restic), and
  the keys that unlock it never leave the Ledger.
- **Stolen laptop while powered off or locked volumes** — volumes stay locked without the Ledger
  and its PIN.
- **Malware reading files at rest** — passphrase files are OpenPGP-encrypted to the card.
- **Bluetooth / USB eavesdropping** — key-derivation requests are blinded (docs/derived-keys.md),
  so the link only carries random-looking points; the BLE link is additionally encrypted after
  pairing (verify the pairing code on the device the first time). File decryption
  (`sealctl decrypt`) uses the standard OpenPGP card path, which is not blinded — prefer
  `-t usb` for it.
- **Losing the device or the computer** — all keys are derived from the seed; nothing else
  needs to survive (see docs/derived-keys.md).

## Not protected against

- **A compromised computer while a volume is unlocked** — plaintext is accessible to anything
  running as you. Hardware keys protect keys, not unlocked data.
- **Malware asking for keys while a session is open** — the OpenPGP app keeps the PIN verified
  until the app closes or the device locks, and the sealctl agent keeps derived keys (the SSH
  agent: decrypted SSH keys) in memory for up to 1 hour idle / 24 hours total. Anything running
  as you can query the agent sockets (0600) or the card during that window. Run `sealctl lock` (stops the agent) when you step
  away, keep a short auto-lock on the Ledger, and treat "agent running" like "logged in".
- **A weakness in the key derivation** — sealctl's one custom construction (2HashDH over
  X25519, docs/derived-keys.md). It follows a well-studied pattern, but it has not been
  independently reviewed.
- **Backup credentials while a volume is unlocked** — the restic password and cloud
  credentials sit inside the unlocked volume (by design, so scheduled backups need no Ledger).
  They are as exposed as the volume's own data, no more. Use bucket credentials scoped to the
  backup bucket and enable object lock / versioning against ransomware.
- **Loss of the 24 words** — unrecoverable by design; there is no other copy of any key.
- **A malicious OpenPGP app build** — when sideloading the Bluetooth build, build it yourself
  from source and compare the hash (see docs/bluetooth-app.md).

## Assumptions

- The Ledger firmware and OpenPGP app behave as specified.
- rPGP, openpgp-card, APFS, LUKS2 and restic are correct.
- The seed is stored offline and never typed into a computer.
