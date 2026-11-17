# Seed-derived keys (specification)

sealctl stores **no key files**. Volume passphrases, restic repository passwords and the secret
store key are derived on demand from the Ledger's OpenPGP decryption key — which the OpenPGP app
derives from the device's 24-word recovery phrase in *seed mode* — and a public identifier.
With the 24 words alone, every sealctl-protected volume, backup and secret can be opened again.

This is sealctl's **one custom construction**. Everything else is standard (OpenPGP, APFS,
LUKS2, restic). It is written down here so that it can be reimplemented independently.

## Construction (version 1)

Inputs:

* `k` — the X25519 private key in the OpenPGP app's **decryption** slot (slot 1, generated in
  seed mode, Curve25519). It never leaves the device.
* `purpose` — ASCII: `volume`, `restic`, `secrets`, `ssh` or `check` (device identity only).
* `id` — UTF-8: the volume UUID (lowercase, hyphenated), the restic repository URL, or the
  literal `store`.

```
LABEL = "sealctl/derive/v1"
p     = 2^255 - 19,  A = 486662

H1(purpose, id):                                  # hash onto Curve25519, no known discrete log
  for i = 0, 1, 2, …:
    h = SHA-512(LABEL ‖ 0x00 ‖ purpose ‖ 0x00 ‖ id ‖ 0x00 ‖ i as u32 big-endian)
    u = (h as little-endian integer) mod p
    if u ≠ 0 and w = u³ + A·u² + u (mod p) is a non-zero square (Euler: w^((p−1)/2) = 1):
      return u                                    # x-coordinate of a point on the curve

u   = H1(purpose, id)
S   = X25519(k, u)                                # on the Ledger: PSO:DECIPHER (ECDH)
      reject S = 0^32
key = HKDF-SHA256(salt = LABEL,
                  ikm  = S,
                  info = purpose ‖ 0x00 ‖ id ‖ 0x00 ‖ u (32 bytes, little-endian),
                  L    = 32)
passphrase = lowercase hex(key)                   # 64 characters, handed to the OS tool
```

On the card, the point is sent as the 32-byte little-endian external public key in a
PSO:DECIPHER `A6 { 7F49 { 86 · } }` template; the app returns the result little-endian.

### Blinding (transport protection)

The device is never asked for `X25519(k, u)` directly (RFC 9497 *Blind* / *Finalize*):

```
s  = fresh random scalar mod ℓ (from 64 random bytes)
B  = 8·(s·u)                 → sent to the device      (torsion-free, random-looking)
R  = X25519(k, B)            ← returned by the device   (must be torsion-free, not identity)
S  = (8s)⁻¹·R  = k·u         computed on the host
```

The factor 8 removes the small-order part of `u` from the request (otherwise its torsion class
would leak which id is derived). The clamped `k` is a multiple of 8, so `k·u` has no torsion
part either, and `(8s)⁻¹` cancels `8s`: `S` is bit-for-bit the unblinded result (tested for all
purposes). A reply that is not a torsion-free, non-identity point is rejected.

### Device identity

On each new connection sealctl derives `key_check(derive("check", "device"))` and compares it
with the value recorded the first time (`~/.config/sealctl/device-check-<fingerprint>`). The
request is blinded like every other, so a device that is not the user's Ledger cannot answer
it correctly — and nothing derived over that connection is used. USB and
Bluetooth therefore never carry `S`, and an eavesdropper cannot tell which id is derived.

## Why this shape

* It is the **2HashDH** PRF, the structure used for OPRF evaluation in RFC 9497:
  `F(k, x) = H₂(x, k·H₁(x))`. Its output is pseudorandom to anyone without `k` under the
  (gap) Diffie–Hellman assumption with `H₁` modelled as a random oracle.
* `H₁` must map **directly onto the curve**. Deriving the point as `h·G` from the id would let
  anyone compute `k·h·G = h·(k·G)` from the *public* key — that construction is insecure.
* The on-curve check runs on the host, so the device never decides which candidate is used:
  a firmware change cannot silently change the keys.
* X25519 is deterministic by definition (unlike some signature implementations, which may add
  randomness for fault resistance), so the same seed always yields the same keys.
* Small-order components are irrelevant: X25519 scalars are multiples of 8.

## Ids

| purpose | id | where the id comes from |
|---|---|---|
| `volume` | volume UUID | APFS volume UUID (`diskutil info`, readable while locked); LUKS UUID (`cryptsetup luksUUID`, chosen by sealctl); sparse bundle: `sealctl.id` file inside the bundle (chosen by sealctl) |
| `restic` | key id: the volume name (default), or `--key-id`; repositories from 0.2.0 used the URL | you |
| `secrets` | `store` | constant |
| `ssh` | `SHA256:…` fingerprint of the key's public key, as OpenSSH prints it | the encrypted key file (its public part is not encrypted) |

The ids are not secret. The volume id travels with the disk, so a disk can be unlocked on any
machine with the seed: `sealctl volume import` + `sealctl unlock`.

## Consequences

* **Recovery needs only the 24 words**: restore them on a Ledger, install the OpenPGP app,
  `sealctl setup --force` (regenerates the identical seed-derived key).
* Keys cannot be rotated per volume; to change a volume's key, copy the data to a new volume
  (new UUID ⇒ new key).
* A restic repository's password depends on its key id (the volume name by default), not on
  where it is stored: it can be copied to another bucket or provider.
* While the OpenPGP app is open with the PIN verified (and while the sealctl agent session
  lives), local processes running as you can request derivations. See the threat model.

## Recovery without a Ledger

`k` itself is reproducible from the 24 words in software (`sealctl recover`), following the
OpenPGP app's seed mode "v2" (`app-openpgp/src/gpg_gen.c`):

```
seed = BIP39(words, passphrase)
Sn   = BIP32-secp256k1(seed, m/0x80475047'/(slot+1)')            # private key, 32 bytes
h    = SHA-256("kdf2" ‖ Sn ‖ "dec " ‖ 00 01 ‖ len(A) ‖ A)          # A = 12 2B060104019755010501
d    = SHAKE-256(h, 64) mod ℓ (big-endian), clamped; k = d little-endian
```

The result is accepted only if `X25519(k, 9)` equals the certificate's decryption subkey.
`scripts/speculos-recover-check.sh` proves the equivalence against the real app in Ledger's
emulator. Typing the phrase into a computer exposes it: recovery only, ideally offline.

## Test vectors

Software key `k = [7; 32]` (32 bytes of `0x07`), reproduced in
`crates/sealctl/tests/derive_vectors.rs`; `check` is the first 4 bytes of
`SHA-256("sealctl/key-check\0" ‖ key)`:

| purpose | id | `u` (hex, little-endian) | check |
|---|---|---|---|
| volume | `fa5a93d5-28d9-4c08-b608-c2b6f344b4d8` | `df3fe7a5f660f84b811e53a804d0270453ab18f89f512466db4846358890dc06` | `840133ef` |
| restic | `s3:https://example.r2.cloudflarestorage.com/bucket/work` | `06be1a8c0a465da2dbf4f3559149b702926206c13071ee51eccbc39ec46e9c3e` | `6f29c744` |
| secrets | `store` | `807428635dc3a48b7ef6fa7bb41136002507d60b5f626cfdfe031de277eb936f` | `cd3b8e29` |

These vectors must never change; a change would make existing data unreadable.
