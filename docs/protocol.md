# sealctl protocol

This is the wire-level spec for the phone-approved sealctl, version 1. It says exactly how keys are derived, what is stored, and what goes over the wire. The CLI, the phone apps (through the shared Rust core) and the relay implement it. Every byte layout here has a test vector in [Appendix A](#appendix-a-test-vectors), computed by the script in [Appendix B](#appendix-b-how-the-vectors-were-computed).

These values must never change for version 1. A change would make existing data unreadable.

## Conventions

| Notation | Meaning |
| --- | --- |
| `"text"` | The UTF-8 bytes of the text, without a terminator |
| `0x00` | One zero byte |
| `a ‖ b` | Concatenation of byte strings |
| `b64u(x)` | Base64url of `x` without padding (RFC 4648 §5). 16 bytes give 22 characters, 32 bytes give 43 |
| `hex(x)` | Lowercase hexadecimal |
| `HKDF(ikm, info, L)` | HKDF-SHA256 (RFC 5869) with an empty salt, input key material `ikm`, `info`, output length `L` bytes |
| `HMAC(k, m)` | HMAC-SHA256 |
| `SHA256(m)` | SHA-256 |
| `Ed25519` | RFC 8032 Ed25519 (pure, no context). A private key is a 32-byte seed |
| `X25519` | RFC 7748. A private key is 32 bytes, clamped when used |
| `AEAD` | ChaCha20-Poly1305 (RFC 8439): 32-byte key, 12-byte nonce, 16-byte tag appended to the ciphertext |
| `HPKE` | RFC 9180 base mode, single-shot, suite DHKEM(X25519, HKDF-SHA256) `0x0020`, HKDF-SHA256 `0x0001`, ChaCha20Poly1305 `0x0003` |
| UUID | A version 4 UUID in lower case with hyphens, 36 characters |
| Times | Unix milliseconds in JSON bodies, as in the Relay API |

JSON bodies are UTF-8. Signatures cover the exact bytes sent, so no canonical JSON is needed. Readers ignore unknown fields.

**Versions.** This is protocol version 1 (`protocol_version()` in the core returns `"1"`). Every QR code and body carries `v`, the major version. A reader refuses a higher `v` with "This machine runs a newer sealctl. Update the app." (or the reverse on the machine). Additions within version 1 are new optional fields only.

## Keys at a glance

Every key in sealctl, where it comes from and where it lives. The sections below define each one.

| Key | Made how | Size | Lives where | Used for |
| --- | --- | --- | --- | --- |
| Words | 24 BIP39 English words, 256 bits of entropy | 24 words | Paper card | Everything; typed only on the phone or into `sealctl recover` |
| Seed | BIP39 from the words, empty passphrase | 64 bytes | Nowhere: computed, then wiped | Input to the root |
| Root | `HKDF(seed, "sealctl/v1/root", 32)` | 32 bytes | Phone keychain, readable while the phone is unlocked; a synced backup item | Input to every key below |
| Words fingerprint | 4 characters from `derive(root, "fingerprint", 8)` | 4 characters | Card, `.id` files, `sealctl status` | Says which words sealed an object |
| Phone identity | `derive(root, "phone:identity", 32)`, an Ed25519 seed | 32 bytes | Phone (stored apart from the root, readable after first unlock) | Signs relay calls, replies and machine messages; its public key is the phone's id |
| Phone box key | `derive(root, "phone:box", 32)`, an X25519 private key | 32 bytes | Phone, with the identity | Machines encrypt requests and status to its public key |
| State key | `derive(root, "state", 32)` | 32 bytes | Phone | Encrypts the phone's state blob on the relay |
| Pairing key | Random Ed25519 seed made on the machine | 32 bytes | Machine, 0600 file | Signs the machine's relay calls, requests and status; its public key is the machine's id |
| Machine box key | Random X25519 private key made on the machine | 32 bytes | Machine, 0600 file | The phone encrypts machine messages (lock, answers) to its public key |
| Pairing code | Random, made on the machine | 16 bytes | Machine until paired, and the QR code | The phone proves it scanned the QR code |
| One-time key | Random X25519 key per request | 32 bytes | Machine memory until the reply arrives | The reply is sealed to it |
| Store key | `derive(root, "secrets:<store-id>", 16)` | 16 bytes | Machine memory for the session | Opens the secret store |
| File key | `HKDF(store key, "sealctl/v1/file:<file-id>", 32)` | 32 bytes | Machine memory, per operation | Encrypts one `.sealed` file |
| Own-approval key | `derive(root, "secret:<file-id>", 16)` | 16 bytes | Machine memory for one command | Opens one `--own-approval` secret |
| Volume key | `derive(root, "volume:<volume-id>", 16)` | 16 bytes | Machine memory while the volume is mounted | The volume passphrase |
| Backup key | `derive(root, "backup:<repository-id>", 16)` | 16 bytes | Machine memory while the session is Open | The restic password |
| Key check | `HKDF(key, "sealctl/v1/check", 8)` | 8 bytes | `.id` files | Shows a key is the right one without revealing it |

Keys that leave the phone are 16 bytes (128 bits), so that each one can be typed as 22 characters in the air-gapped variant. Keys that never leave the phone are 32 bytes.

## Derivation and test vectors

### From the words to the root

1. The words are 24 words from the BIP39 English list. The last word carries the BIP39 checksum; a phrase whose checksum fails is refused. The first four letters identify each word.
2. `mnemonic` = the 24 words in lower case, NFKD-normalised, joined with one space (`0x20`).
3. `seed` = PBKDF2-HMAC-SHA512(password = `mnemonic`, salt = `"mnemonic"`, iterations = 2048, length = 64). This is BIP39 with an empty passphrase. sealctl never uses a BIP39 passphrase.
4. `root` = `HKDF(seed, "sealctl/v1/root", 32)`.

The seed is wiped as soon as the root exists. The root is the only stored secret.

### derive

```text
derive(root, label, L) = HKDF(ikm = root, info = "sealctl/v1/" ‖ label, L)
label                  = purpose                 for keys with no object
                       = purpose ‖ ":" ‖ id      for keys that open an object
```

| Purpose | Id | L | Output | Handed to a machine |
| --- | --- | --- | --- | --- |
| `fingerprint` | none | 8 | Words fingerprint, encoded below | No |
| `phone:identity` | none | 32 | Ed25519 seed of the phone identity | No |
| `phone:box` | none | 32 | X25519 private key of the phone box key | No |
| `state` | none | 32 | AEAD key of the state blob | No |
| `secrets` | store id | 16 | Store key | Yes |
| `secret` | file id | 16 | Own-approval key of one secret | Yes |
| `volume` | volume id | 16 | Volume key | Yes |
| `backup` | repository id | 16 | Backup key | Yes |

The id is the object's id exactly as its `.id` file writes it (see [Ids and .id files](#ids-and-id-files)). On the wire a key is named by its purpose `p` and id `i` separately. The phone hands out only the four purposes marked Yes, with an id matching `^[A-Za-z0-9._-]{1,64}$`. Anything else is refused with `bad_label`.

### Words fingerprint

```text
n  = derive(root, "fingerprint", 8), read as an unsigned 64-bit big-endian integer
n  = n mod 58^4
fp = n as 4 base58 digits, most significant first, padded with "1" (the zero digit)
     alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
```

The fingerprint is case-sensitive. It names a set of words. It is not secret and does not check any key.

### Key check

```text
check(key) = b64u(HKDF(ikm = key, info = "sealctl/v1/check", 8))      # 11 characters
```

`.id` files carry the check of the key that opens the object. A machine compares the check of every key it receives with the one on file before using the key. A mismatch is the error `wrong_key`.

### Keys as text

| Use | Form |
| --- | --- |
| Passphrase given to `diskutil`, `hdiutil`, `cryptsetup` and restic | `hex(key)`: 32 characters, through stdin or a file descriptor, never an argument or an environment variable |
| Key in a reply body, or typed in the air-gapped variant | `b64u(key)`: 22 characters |

### Machine tag and hardware hint

```text
tag  = first 20 bits of SHA256("sealctl/v1/tag" ‖ 0x00 ‖ M), as 4 characters of
       Crockford base32 in lower case, alphabet 0123456789abcdefghjkmnpqrstvwxyz
       (M = the machine's 32-byte pairing public key)
hint = b64u(first 16 bytes of SHA256("sealctl/v1/hint" ‖ 0x00 ‖ raw))          # 22 characters
       raw on macOS: IOPlatformUUID as ioreg prints it (upper case, with hyphens)
       raw on Linux: the contents of /etc/machine-id without the newline
```

The tag tells apart two paired machines with the same name: `dev@mbp.example.com #k7m2`. The hint lets the phone recognise the same hardware when a machine pairs again. A machine with neither source sends no hint.

## Ids and .id files

Every object carries its own id, generated when the object is made and readable from the object without any key.

| Object | Id | Where the id is read | Where the words fingerprint and key check are read |
| --- | --- | --- | --- |
| Secret store | Generated UUID | Its folder name, and `<store-id>.id` inside it | `<store-id>.id` |
| Own-approval secret | Generated UUID (its file id) | The `.sealed` header | Words in the `.sealed` header; check in `<store-id>.id` under `own` |
| APFS volume | The volume UUID from its header, in lower case | `diskutil info` (works while locked) | `<mount>/.sealctl/volume.id` once mounted; the APFS passphrase hint `sealctl <fp>` while locked |
| Sparse bundle | Generated UUID | `<bundle>/sealctl.id` | `<bundle>/sealctl.id` |
| LUKS2 volume | The LUKS UUID, chosen by sealctl when formatting | `cryptsetup luksUUID` | A LUKS2 token of type `sealctl` in the header, readable while locked; `<mount>/.sealctl/volume.id` |
| Restic repository | Its folder name: a generated UUID, or for a repository taken over with `sealctl seal` the last path segment of its URL (`[A-Za-z0-9._-]{1,64}`) | The repository URL | The host field `sealctl-<fp>` of its restic key (the `keys/` files are readable without the password); the machine's backup config |

### .id file format

An `.id` file is a JSON object. It is public: it holds no key.

```json
{
  "sealctl": 1,
  "kind": "store",
  "id": "0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f",
  "words": "qHWf",
  "check": "Je_Q_YPg3B0",
  "created": "2026-11-21T09:00:00Z",
  "format": "sealed-v1"
}
```

| Field | Value |
| --- | --- |
| `sealctl` | `1` |
| `kind` | `store`, `volume` or `backup`; it fixes the purpose (`secrets`, `volume`, `backup`) |
| `id` | The object id |
| `words` | Words fingerprint of the words that sealed the object |
| `check` | `check(key)` of the object's key |
| `created` | RFC 3339 time in UTC |
| `format` | Stores only: `sealed-v1` |
| `own` | Stores only, optional: `{"<file-id>": "<check of its own-approval key>"}` |
| `volume` | Volumes only: `"apfs"`, `"sparsebundle"` or `"luks"` |

The LUKS2 token is the same object with the two fields cryptsetup requires: `"type": "sealctl"` and `"keyslots": []`.

## Store format

A secret store is a folder named by its store id. It holds one public `.id` file and one `.sealed` file per secret. Nothing else is needed to read it besides the words.

```text
<store-root>/0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f/
  0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f.id
  shop/openai-api-key.sealed
  shop/stripe-test.sealed
  ssh/ed25519.sealed
```

Files a reader does not know (a `.git` folder, a README) are ignored, so the folder can live in a git repository or a synced folder as it is.

### Secret names

A name is a path of segments separated by `/`. Each segment is 1 to 64 characters of `A-Z a-z 0-9 - _ . @ +` and does not start with `.`. A name is at most 128 characters. Its file is `<name>.sealed`. sealctl itself uses the prefixes `ssh/` (SSH keys), `aws/` (AWS profiles), `git/` (git hosts) and `backup/` (backup storage credentials).

### .sealed file

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 4 | Magic `"SCS1"` (`53 43 53 31`) |
| 4 | 1 | Mode: `0x01` store key, `0x02` own-approval key |
| 5 | 4 | Words fingerprint, 4 ASCII characters |
| 9 | 16 | File id: the 16 bytes of the UUID |
| 25 | 12 | Nonce, random for every write |
| 37 | n + 16 | AEAD ciphertext of the value, with its tag |

The first 37 bytes are the header.

```text
mode 1:  file key = HKDF(ikm = store key,        info = "sealctl/v1/file:" ‖ file-id, 32)
mode 2:  file key = HKDF(ikm = own-approval key, info = "sealctl/v1/file:" ‖ file-id, 32)
         own-approval key = derive(root, "secret:" ‖ file-id, 16)
aad      = header (37 bytes) ‖ store-id ‖ 0x00 ‖ name
sealed   = header ‖ AEAD-Seal(file key, nonce, aad, value)
```

`file-id` and `store-id` here are the 36-character UUID strings; `name` is the secret name without `.sealed`. The value is 1 to 65,536 bytes, stored as given. The AAD binds the header, the store id and the name: a file copied to another name or another store does not open.

Rules for writers:

- A new secret gets a new random file id. Replacing a value keeps the file id, and so the file key, and writes a new random nonce: every write draws its own nonce, never one taken from an earlier file or header. In sealctl-core, `sealed::seal` takes the mode, fingerprint and file id (`sealed::Label`) and draws the nonce itself; there is no way to pass one in outside the test vectors.
- Renaming a secret re-encrypts it under the new name.
- Write `<name>.sealed.tmp-<random>` in the same folder, `fsync`, then rename it over the old file. Files 0600, folders 0700.
- The store's `.id` file is written last when a store is made, and replaced atomically when the words change.

## Pairing QR code and proof

### The QR code

`sealctl pair` shows a QR code (byte mode, error correction M) that holds one link, and prints the same link as text for a phone that cannot scan it:

```text
https://sealctl.com/p#v=1&m=<machine>&x=<machine box>&s=<code>&n=<name>&o=<os>&d=<model>&h=<hint>&e=<expiry>[&r=<relay>]
```

| Parameter | Value |
| --- | --- |
| `v` | `1` |
| `m` | `b64u(M)`: the machine pairing public key, 43 characters |
| `x` | `b64u(MX)`: the machine box public key (X25519), 43 characters |
| `s` | `b64u(pairing code)`: 16 random bytes made for this pairing, 22 characters |
| `n` | Name, `user@full-hostname`, 1 to 200 characters |
| `o` | OS, e.g. `macOS 15.2` or `Ubuntu 24.04`, up to 200 characters; a reader takes a missing `o` as empty |
| `d` | Model, e.g. `Mac15,3`, up to 200 characters; omitted when unknown |
| `h` | Hardware hint, 22 characters; omitted when unknown |
| `e` | Expiry, Unix seconds: 10 minutes after the code was made. The phone refuses an expired code |
| `r` | Relay origin, e.g. `https://relay-staging.sealctl.com`; omitted for `https://relay.sealctl.com`. An `https://` origin with no path, or `http://` only to `localhost`, `127.0.0.1` or `[::1]` (test relays) |

Values are percent-encoded (RFC 3986; unreserved characters stay as they are), in the order above. The core's parser also accepts the part after `#` on its own, so the text can be typed or pasted. Parameters it does not know are ignored; a known parameter given twice, a field over its length, or a control character in `n`, `o` or `d` refuses the code. The parser checks `v` first, so a newer code is refused as newer rather than as malformed, and refuses an expired code. The pairing code `s` stays inside the core: the app gets the other fields, and `pairing_proof` uses the code. The data sits in the fragment, so a browser that opens the link sends none of it to sealctl.com. The phone app claims the link as a universal link (iOS) and an app link (Android); the web page at `/p` only says to scan the code with the sealctl app.

### The proof

The phone registers the machine with `POST /v1/phones/{phone}/machines` (Relay API) and sends `proof`:

```text
P      = phone identity public key (32 bytes)
X      = phone box public key: the X25519 public key of derive(root, "phone:box", 32)
M      = machine pairing public key (32 bytes)
c      = pairing code from the QR code (16 bytes)
mac    = HMAC(c, "sealctl/v1/pair" ‖ 0x00 ‖ P ‖ X ‖ M)
proof  = b64u(X ‖ mac)                                   # 64 bytes, 86 characters
```

The machine polls `GET /v1/machines/{M}` every 2 seconds for up to 10 minutes. On `200 {"phone", "proof"}` it:

1. decodes `proof` and refuses any length other than 64 bytes;
2. computes `mac` with its own `c` and the returned `phone` as `P`, and compares in constant time;
3. on a match, stores `P` and `X` as its phone and deletes `c`.

A wrong proof means someone else registered this machine key. The machine says "This pairing did not come from your phone. Run sealctl pair again." and deletes its pairing key.

### Phone key change (new words)

When the words change, the phone identity and box keys change. The phone moves each machine to its new identity by registering the machine under the new phone key, with a move proof signed by the old identity:

```text
P_old  = old phone identity public key (the machine already trusts it)
P_new  = new phone identity public key
X_new  = new phone box public key
sig    = Ed25519-Sign(old phone identity, "sealctl/v1/move" ‖ 0x00 ‖ P_new ‖ X_new ‖ M)
proof  = b64u(X_new ‖ sig)                               # 96 bytes, 128 characters
```

The relay then drops the old pairing, so the machine's next signed call under the old phone answers `403 forbidden`, and its open wait closes with `unpaired` (planned: `moved`). The machine calls `GET /v1/machines/{M}`. If `phone` differs from `P_old` and `proof` decodes to 96 bytes, it verifies `sig` with `P_old`. On success it stores `P_new` and `X_new`, keeps `P_old` until its objects are rewrapped, and carries on. Any other answer means the machine was unpaired.

A phone restored from the same words has the same identity and box keys, so it keeps its pairings with no step on the machines.

## Request and reply encryption

A machine asks its phone for keys or decisions with one sealed request. The phone answers with one sealed reply. The relay sees only the sealed strings, the request id, the machine id and timing.

### Request

```text
id        = b64u(16 random bytes)                         # 22 characters, the relay request id
ot_sk     = a fresh random X25519 private key: the one-time key; ot_pk is its public key
body      = the request JSON, UTF-8, at most 2,960 bytes; it holds "ot": b64u(ot_pk)
sig       = Ed25519-Sign(pairing key, "sealctl/v1/request" ‖ 0x00 ‖ id ‖ 0x00 ‖ P ‖ body)
aad       = id ‖ 0x00 ‖ M
enc, ct   = HPKE-Seal(pkR = X, info = "sealctl/v1/request", aad, pt = sig ‖ body)
sealed    = b64u(enc ‖ ct)                                # at most 4,096 characters
```

For a request with `match`, both sides also export the [number match](#number-match) from this HPKE context; single-shot sealing is then done as `SetupBaseS`, `Seal`, `Export` on one context. The machine sends `{"type": "request", "id", "sealed", "ttl"}` on the wait socket (Relay API). 2,960 bytes is the largest body that fits: 4,096 characters are 3,072 bytes, less 32 for `enc`, 16 for the tag and 64 for `sig`.

The phone gets `id`, `machine` (= `M`) and `sealed` from the relay. It:

1. refuses a machine that is not in its list of pairings;
2. opens the HPKE ciphertext with its box private key, with `info` and `aad` as above;
3. splits the plaintext into `sig` (64 bytes) and `body`, and verifies `sig` with `M`;
4. refuses a body whose `t` is more than 10 minutes from its own clock, or an `id` it has already answered.

In the core, `open_request` does steps 2 to 4 except the `id` check (`Expired` for `t`; a body whose `v` is higher is `NewerVersion`); the app keeps the ids it answered (Pending, app spec 9.1). A `Request` object can be answered once; a second reply from it is the error `Replay`.

### Reply

```text
rq        = b64u(SHA256(request body))                    # ties the reply to the request
body      = the reply JSON, UTF-8, holding "rq"
sig       = Ed25519-Sign(phone identity, "sealctl/v1/reply" ‖ 0x00 ‖ id ‖ 0x00 ‖ M ‖ body)
aad       = id ‖ 0x00 ‖ M
enc, ct   = HPKE-Seal(pkR = ot_pk, info = "sealctl/v1/reply", aad, pt = sig ‖ body)
sealed    = b64u(enc ‖ ct)                                # at most 4,096 characters
```

The phone posts `{"sealed"}` to `POST /v1/phones/{phone}/requests/{id}/reply`. The machine opens it with `ot_sk`, verifies `sig` with `P`, checks `rq`, and wipes `ot_sk`. Because `ot_sk` lives only in memory until then, a machine stolen later cannot open a reply someone recorded.

A reply that fails any check is dropped and the request fails with `bad_reply`; the machine never uses keys from it.

### Request body

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | number | `1` |
| `t` | number | When the request was made |
| `why` | string | The request kind (below) |
| `ot` | string | `b64u(ot_pk)` |
| `ctx` | object | Who asks and why (below) |
| `keys` | array | Keys asked for (below) |
| `uses` | array | Agent uses to decide: `[{"a": agent, "r": repository id, "n": [secret names]}]` |
| `work` | number | Minutes worked today on this machine |
| `old` | string | `old_words` only: the retired words fingerprint the listed objects are sealed with |
| `seq`, `state`, `log`, `inv`, `migrate` | | `report` only: the fields of a [status message](#machine-status-and-messages) |
| `lvl` | number | The [confirmation level](#confirmation-levels) the machine asks for: `1`, `2` or `3`; `1` when absent. The phone never applies a lower level than its own |
| `match` | bool | `true` when a person at this machine's terminal is shown the [number match](#number-match) for this request |
| `plan` | object | `unseal` only: the [plan](#plan-and-plan-signature) `{"all", "h", "items", "n", "i"}` |
| `handback` | object | `report` only: what a finished `unseal` handed back and where (below) |

`ctx`:

| Field | Meaning |
| --- | --- |
| `agent` | Agent name, e.g. `Claude Code`; `null` for a person |
| `repo` | `{"id", "name"}` or `null`. `id` is stable and used for answers: the git remote `origin` normalised to `host/owner/name` (scheme, user, port and `.git` dropped, lower case host), or the absolute path of the repository root when it has no remote. `name` is for display: `owner/name`, or the folder name |
| `cmd` | The command, at most 120 characters, key-like substrings replaced by `****` |
| `cwd` | Working directory, `~` for the home folder, at most 120 characters |
| `user` | `user@full-hostname` of the requesting user |
| `subject` | What triggered the request: `{"k": "secret" \| "volume" \| "backup" \| "ssh" \| "machine", "n": <name>}` |
| `n` | Secret names involved, at most 10 |

Each item of `keys`:

| Field | Meaning |
| --- | --- |
| `p` | Purpose: `secrets`, `secret`, `volume` or `backup` |
| `i` | Object id |
| `w` | Words fingerprint from the object's `.id` file; absent for a new object |
| `c` | Key check from the object's `.id` file; absent for a new object |
| `o` | Inventory facts: `{"k": "store" \| "secret" \| "volume" \| "backup", "p": <path or URL>, "s": <size in bytes>}` |

Request kinds (`why`):

| `why` | Sent when | Level of asking | Confirmation level |
| --- | --- | --- | --- |
| `open` | The session is Locked and something needs a key, or `sealctl open` | Automatic or One tap, by the levels of asking | 1 |
| `keys` | The session is Open and needs a key it does not hold: a new object, a volume opened later | Automatic while the phone is unlocked and this machine's session is Open by its last status; otherwise One tap | 1; 2 with `ctx.subject` `{"k": "machine", "n": "seal"}` (`sealctl seal` taking over an object the user already has) |
| `agent` | The session is Open and an agent uses a secret for the first time in a repository | Automatic when the answer is remembered; otherwise One tap | 1 |
| `own` | An `--own-approval` secret is used | One tap, every time | 1 |
| `rewrap` | The phone key changed: the machine asks for old and new keys of everything it holds | In the app, one machine at a time | 2 |
| `old_words` | An object is sealed with retired words | In the app: the user types those words | 2 (`level()` in the core); the typed words are the confirmation |
| `unseal` | `sealctl unseal` hands objects back under the user's own passwords | In the app | 2; 3 with `plan.all`, or a plan that holds a `pairing` item |
| `report` | No machine channel on the relay yet (below), or `sealctl migrate`, or a finished `unseal` | Never shown | |

A request may carry `keys` and `uses` together, so one tap covers opening the session, an agent's first use and an `--own-approval` secret. An app that gets an unknown `why` shows it with Deny only.

`sealctl unseal` asks with `unseal`, never with `keys`. The phone never answers it automatically.

The machine says nothing about where it is. For the Automatic level the phone uses the relay's `near` flag on the request (planned, see Relay API) and its own place.

### Reply body

| Field | Type | Meaning |
| --- | --- | --- |
| `v` | number | `1` |
| `rq` | string | `b64u(SHA256(request body))` |
| `ok` | bool | `false` when denied or failed |
| `err` | string | When `ok` is `false`: `declined`, `bad_label`, `wrong_key`, `retired_words`, `unsupported`, `phone_locked`; for levels 2 and 3 also `no_match` (the wrong number was picked), `not_near` (no proximity, below), `no_biometrics` (biometrics unavailable or locked out), `held` (this machine picked a wrong number within the last hour), `outside_plan` (a key not in the approved plan), `plan_expired` |
| `lvl` | number | The confirmation level the phone applied; absent for level 1, as in the request |
| `w` | string | The phone's current words fingerprint; absent in a reply sealed without the root (a denial, or agent uses without keys while the phone is locked) |
| `grant` | string | `once`: the keys and uses are for the command that asked, then wiped; `session`: kept until the session locks; `plan`: for the approved `unseal` plan only |
| `plan` | object | `unseal` only: `{"h", "nb", "sig"}`, the [plan signature](#plan-and-plan-signature) |
| `part` | number | `unseal` plan sent in parts: the part acknowledged, for every part but the last |
| `more` | bool | `unseal`: `true` when keys of the plan remain to be asked for: the keys this request asked for did not all fit in one reply, and the machine asks for the rest. Only `plan` grants split keys; any other approval that does not fit is not sent |
| `remember` | bool | The phone stored the answer for the agent uses in the request |
| `place` | string | `trusted`, `other` or `none` (no location permission) |
| `cap`, `base`, `rate` | numbers | Allowance: cap in seconds, base in seconds, seconds added per minute worked |
| `keys` | array | `[{"p", "i", "k": b64u(key), "old": b64u(previous key)}]`; `old` only for `rewrap` and `old_words`. An item the phone cannot answer has `err` instead of `k`: `retired_words` with `retired` (`YYYY-MM-DD`, when those words were retired), or `wrong_key` |
| `ack` | number | `report` only: the `seq` the phone stored |
| `msgs` | array | `report` only: [machine message](#machine-status-and-messages) bodies waiting for this machine |

A `plan` grant carries no `cap`, `base` and `rate` (no allowance at levels 2 and 3). For `once` and `session` the core fills `cap`, `base` and `rate` from the place: `trusted` 14,400 / 1,800 / 120, `other` 600 / 600 / 0, `none` 3,600 / 1,800 / 120. The machine computes its idle allowance as `min(cap, base + rate × minutes worked today)` and does not hard-code these numbers. The machine computes the hard stop itself: 02:00 local time, or 14 hours after the first `open` granted today, whichever comes first.

### Confirmation levels

Every approval has a confirmation level. The level of asking (Automatic, One tap, In the app) says when the phone is asked; the confirmation level says how hard the approval is.

| Level | Operations | On the phone |
| --- | --- | --- |
| 1 Routine | `open`, `keys`, `agent`, `own`: `sealctl run` with a secret, SSH signing, opening a volume | One tap; Face ID by policy; the trusted-place allowance applies |
| 2 Sensitive | Pairing a machine, `unseal <object>`, `sealctl seal` of an existing object, `rewrap` | Biometrics every time, no passcode fallback, no allowance; the exact objects listed; proximity (below) |
| 3 Leaving | `unseal --all`, Leave sealctl, showing the 24 words, deleting the phone's relay data | Level 2, plus: number match, plan signature, delay away from trusted places, the card check (Leave sealctl), a report |

Rules:

- **The phone decides.** It computes the level from `why`, `ctx.subject` and `plan` as in the kinds table and applies `max(that, lvl)`. A machine can raise the level of its own request, never lower it. A request the phone cannot classify is level 3.
- **Levels do not change which keys a machine can get.** `open` can ask for any object key at level 1. Levels make deliberate the steps that remove sealctl's protection or are hard to undo: handing objects back under plain passwords, unpairing, showing or erasing the words.
- **Proximity** (level 2 and above) means the person approving can see the machine. It holds when either: the relay's `near` flag is true and the phone is on Wi-Fi or Ethernet; or the request has `match` and the number match passes. For pairing, scanning the QR code with the app's own camera counts as proximity. A level 2 request with neither is answered `not_near`; the CLI then says to run the command at the machine's terminal.
- **Level 3 from a machine** always needs `match`. A level 3 request without it is answered `no_match`.
- **Biometrics.** Levels 2 and 3 need a fresh biometric match: iOS `LAPolicy.deviceOwnerAuthenticationWithBiometrics`, Android `BIOMETRIC_STRONG` without device credential. When biometrics are unavailable or locked out, level 3 is refused (`no_biometrics`) until they work again; the 24 words on the CLI (`--words`) still work. The app spec says how level 2 falls back.
- **The 24 words** typed into the CLI (`recover`, `seal` and `unseal` with `--words`) need no phone and no level: the card is the stronger proof.

### Number match

The terminal shows a two-digit number. The phone offers three numbers; only someone looking at the terminal knows which is right. Picking a wrong one rejects the request.

```text
x       = HPKE-Export(request context, exporter_context = "sealctl/v1/match", L = 4), read as an unsigned 32-bit big-endian integer
N       = 10 + (x mod 90)                                  # 10 to 99
```

The request context is the HPKE context of that one sealed request (RFC 9180 section 5.3): the machine exports from its sender context when it seals, the phone from its receiver context when it opens. Both get the same `N`; no byte string carries it, so it is in no request body, log, notification or stored request. A machine sets `match: true` in the body only when a person at its terminal is shown `N`: `On your phone, pick 47.`

On the phone:

1. The core keeps `N` inside the `Request` object and never hands it to Swift or Kotlin. It offers `N` and two other numbers from 10 to 99, distinct, drawn by the phone at random, in random order, and checks the pick. Only a number it offered can be right, and the first wrong pick is final for that request. The core answers any approval of a level 3 request without a right pick with `no_match`.
2. The number screen comes before anything the machine wrote: it shows only the machine's name from the phone's own pairing record and the three numbers. Command, paths and plan item names, all written by the machine, appear only after a right pick, so a machine cannot spell out the answer.
3. A wrong pick answers `no_match`. For one hour after it, every level 2 or 3 request from that machine is answered `held` without being shown.

**What it guards against.** The request is already sealed to the phone, so the relay never sees `N` either way. Number match is not about the relay. It addresses approval fatigue and requests triggered from afar: malware on a paired machine, or a copied pairing key, sending `unseal` while the owner is elsewhere, hoping for a reflexive tap. Without the terminal in sight the chance of a right pick is one in three, and a wrong pick holds that machine for an hour.

### Plan and plan signature

`unseal` sends the plan the user confirmed at the terminal. The phone shows it, signs its hash, and hands out keys only for objects in it. The CLI refuses to act on any object outside it.

```text
plan text = "sealctl-plan-v1\n" ‖ b64u(M) ‖ "\n" ‖ one line per item, in plan order
line      = k ‖ "\t" ‖ n ‖ "\t" ‖ p ‖ "\t" ‖ i ‖ "\n"        # p and i empty for a step with no key
ph        = SHA256(plan text)                               # "h" = b64u(ph)
psig      = Ed25519-Sign(phone identity, "sealctl/v1/plan" ‖ 0x00 ‖ id ‖ 0x00 ‖ M ‖ ph ‖ nb)
            id = the request id that carried the last part; nb = not-before time, Unix ms, unsigned 64-bit big-endian
```

`plan` in the request:

| Field | Meaning |
| --- | --- |
| `all` | `true` for `unseal --all` |
| `h` | `b64u(ph)` over the whole plan |
| `items` | `[{"k", "n", "p"?, "i"?}]`: kind (`secrets`, `secret`, `volume`, `backup`, `ssh`, `git`, `ai`, `services`, `local`, `pairing`), name as the terminal shows it, and the purpose and id of the key that step needs. Several items may name the same key (an SSH key needs the store key). Fields are at most 200 characters with no control characters; the phone refuses a plan that breaks this |
| `n`, `i` | A plan that does not fit in one body is sent in `n` parts, `i` from 1. Every part carries `h`; the phone answers each part but the last at once with `{"ok": true, "part": i}`, rebuilds the plan text and checks `h` when the last part arrives. Only the last part carries `match` |

The phone answers the last part, after the number match, the plan view and the biometric match, with `grant: "plan"`, `plan: {"h", "nb", "sig"}`, and keys for as many plan items as fit; `more: true` says keys remain. The machine asks for the rest with further `unseal` requests holding `plan: {"h"}` and `keys`, without `match`; the phone answers them without showing anything while the approval is valid: same machine, same `h`, from `nb` to `nb` + 30 minutes, every key named by a plan item (`outside_plan` otherwise, `plan_expired` after).

The machine checks `sig` with `P` against its own `ph`, the request id and `nb`, refuses to start before `nb` by its own clock, and writes `h`, `nb` and `sig` into the run's `plan.json`. `nb` is the approval time, or two hours later when the phone is away from a trusted place (below).

### Delayed approvals

A level 3 approval away from a trusted place takes effect two hours later. At a trusted place there is no delay.

- **From a machine (`unseal --all`).** The phone seals the reply as usual, with `nb` = now + 2 hours, and posts it with `"delay": 7200`. The relay holds it and tells the machine `{"type": "delayed", "id", "releaseAt"}`. The machine keeps its one-time key in memory, shows the time left, and fetches the reply once `releaseAt` passes. If the CLI stops during the two hours, the approval is lost; running it again starts a new one.
- **On the phone (Leave sealctl, showing the words, deleting the relay data).** The phone registers a delayed action with the relay and finishes it after `releaseAt`, only when the relay confirms it was not cancelled. Finishing asks for biometrics again.
- **Announced** on every install of the phone (push) and on every paired machine: the relay's own `delayed` note, so an offline phone cannot hide it, and the phone's sealed `notice` message saying what and where.
- **Cancellable** from the phone or any paired machine until it finishes (`sealctl cancel`). A cancelled `unseal --all` ends with `Cancelled from <where>.`; nothing was handed back.
- A malicious relay could release a held reply early; the machine still refuses to act before `nb`, which the phone signed.

The relay endpoints are in [Delayed approvals (planned)](#delayed-approvals-planned).

### Hand-back report

After `unseal`, before its pairing step, the machine sends a `report` with `handback`:

| Field | Meaning |
| --- | --- |
| `h` | The plan hash it ran |
| `items` | `[{"k", "n", "to", "s"}]`: the plan item, where its password or value went (`~/sealctl-unsealed-2026-11-21/passwords.txt (volume safe)`, `macOS Keychain, service sealctl-unsealed`, `1Password vault Private`, `~/.ssh/ed25519`, `shown once`), and `s` = `done`, `failed` or `skipped` |
| `run` | The run folder, `~/sealctl-unsealed-2026-11-21` |

The phone shows it and sends every other paired machine a `notice` with the counts and the stores. A report that does not fit is split as status reports are.

### Air-gapped variant (reserved)

Not built in version 1; reserved so that no key format changes later:

- The machine shows the sealed request as a QR code `sealctl:r1:<id>:<sealed>`, with `ot` absent from the body.
- The phone shows each 16-byte key as `b64u(key)`, 22 characters, which the user types on the machine.
- The machine accepts a typed key only if `check(key)` equals the check on the object's `.id` file.

## Machine status and messages

An Open machine tells the phone its state and the uses inside the session; the phone tells the machine to lock and which answers it holds. Both are sealed and signed like requests, without a request id.

```text
status   (machine to phone)
  body   = status JSON
  sig    = Ed25519-Sign(pairing key, "sealctl/v1/status" ‖ 0x00 ‖ P ‖ body)
  enc, ct = HPKE-Seal(pkR = X, info = "sealctl/v1/status", aad = M, pt = sig ‖ body)
  sealed = b64u(enc ‖ ct)                                 # at most 8,192 characters

message  (phone to machine)
  body   = message JSON
  sig    = Ed25519-Sign(phone identity, "sealctl/v1/message" ‖ 0x00 ‖ M ‖ body)
  enc, ct = HPKE-Seal(pkR = MX, info = "sealctl/v1/message", aad = M, pt = sig ‖ body)
  sealed = b64u(enc ‖ ct)                                 # at most 4,096 characters
```

Status body:

| Field | Meaning |
| --- | --- |
| `v`, `t` | Version, time |
| `seq` | Increases by one with every status from this machine; the phone ignores a `seq` it has seen |
| `state` | `{"s": "locked" \| "open" \| "waiting", "left": <idle seconds left>, "stop": <hard stop time>, "place": <place from the last open>, "busy": [<volumes still mounted after a lock, with the process holding them>]}`; each `busy` item is `{"n": <volume name>, "p": <process name>, "pid"?: <process id>}` |
| `log` | Uses since the last acknowledged status, at most 50: `[{"t", "a", "r", "c", "n": [names], "own": bool}]` |
| `inv` | Objects on this machine, when changed: `[{"p", "i", "w", "c", "o"}]` as in request `keys` |
| `migrate` | Re-encryption: `{"items": [{"p", "i", "path", "s", "rw": <seconds>, "re": [<min s>, <max s>], "free": <bytes>, "done": <0 to 1>, "paused": <reason or null>}]}` |

The machine sends a status when its state changes, when it holds unsent log entries (at most every 60 seconds), and at least every 15 minutes while Open.

Message body:

| Field | Meaning |
| --- | --- |
| `v`, `t` | Version, time |
| `seq` | Increases by one with every message to this machine; the machine ignores a `seq` it has seen |
| `type` | `lock`, `answers`, `ack` or `notice` |
| `reason` | `lock`: `phone` (Lock tapped), `place` (the phone left the place), `words` (the words changed) |
| `answers` | `answers`: this machine's remembered answers, at most 40 per message, `[{"a", "r", "n", "last"}]`; `"more": true` when another `answers` message follows. The machine replaces its list when the last part arrives |
| `ack` | `ack`: the status `seq` the phone stored |
| `notice` | `notice`: a level 3 action, for the machine to show: `{"what": "unseal_all" \| "leave" \| "words" \| "delete", "state": "pending" \| "cancelled" \| "done", "machine": <name of the machine it concerns, or null>, "delay": <delayed id, or null>, "at": <releaseAt, or null>, "report": {"done", "failed", "skipped", "to": [<stores>]} or null}` |

A machine ignores a `lock` whose `t` is earlier than the start of its current session (the time it sent the `open` request) by more than 60 seconds, so a lock held for an offline machine does not close tomorrow's session, while a lock made just after the approval still applies when the phone's clock is a little behind the machine's.

**Transport.** The relay transport for both is planned (see Relay API, Machine channel). Until it ships, an Open machine keeps one `report` request waiting on the relay, renewed when it expires (`ttl` 300). The report carries the status fields, split over several reports when they do not fit in 2,960 bytes; the phone's reply carries `ack` and the waiting messages in `msgs`. A machine opens at most one `report` per 60 seconds, so a quiet Open machine makes at most 288 of these calls a day.

## Phone storage formats

The phone keeps its secrets in the platform keychain; these byte formats let both apps and the core agree.

| Item | Bytes |
| --- | --- |
| Root | The 32-byte root |
| Phone keys | Phone identity seed (32) ‖ phone box private key (32): 64 bytes |
| Words backup item (iCloud Keychain, Block Store) | `0x01` ‖ words entropy (32) ‖ words fingerprint (4 ASCII) ‖ created, Unix milliseconds as unsigned 64-bit big-endian (8): 45 bytes |

## State blob

The phone keeps its pairings, places, answers and inventory on the relay as one blob (`PUT /v1/phones/{phone}/state`):

```text
nonce = 12 random bytes, new for every upload
aad   = "sealctl/v1/state" ‖ 0x00 ‖ P
blob  = 0x01 ‖ nonce ‖ AEAD-Seal(state key, nonce, aad, plaintext)
```

The first byte is the blob format version. The plaintext format belongs to the phone app.

## Relay API

The relay carries sealed requests from a machine to its phone and sealed replies back, keeps the phone's encrypted state, counts days with use, and holds the licence. It runs on Cloudflare Workers with one Durable Object per phone. The code is in the private `sealctl/relay` repository; this section is the contract it implements.

Items marked **(planned)** are agreed and specified but not yet shipped; everything else matches the shipped relay.

### Identities

- A **phone** is identified by its identity public key: the Ed25519 key derived from the root with `phone:identity`.
- A **machine** is identified by its pairing public key: a random Ed25519 key made on the machine.
- Both are written as unpadded base64url of the 32-byte key: 43 characters. That string is the id used in paths.

### Signing

Every call except the health check and Paddle's webhook is signed. The signer puts three headers on the request:

| Header | Value |
| --- | --- |
| `Sealctl-Key` | The signer's public key, 43 base64url characters |
| `Sealctl-Time` | Unix time in seconds |
| `Sealctl-Signature` | Ed25519 signature, 64 bytes as base64url |

The signature covers these five lines, joined with `\n` and no trailing newline:

```text
sealctl-relay-v1
<METHOD in upper case>
<path and query, e.g. /v1/phones/<id>/licence>
<the Sealctl-Time value>
<base64url of SHA-256 of the raw body; the hash of an empty body for GET>
```

Signing test vectors for both roles are in `docs/vectors/relay-signing.json`.

The relay refuses a call whose time is more than 300 seconds away from its own clock. A replay inside that window can only repeat the same call; calls that change things are safe to repeat or are guarded (state uses compare-and-swap, purchases are deduplicated).

Signature errors are `401` with one of: `unsigned`, `bad_key`, `bad_time`, `clock_skew`, `bad_signature`. Other request errors: `413 too_large` for a body over 1,500,000 bytes, `400 bad_json` for a body that is not JSON.

- **(planned)** `401 clock_skew` carries the relay's clock: `{"error": "clock_skew", "time": <unix seconds>}`, so a client can tell the user how far off its clock is.
- **(planned)** The body limit is 16,384 bytes on every route except `PUT /v1/phones/{phone}/state`, which keeps 1,500,000 bytes. Larger bodies get `413 too_large`.
- **(planned)** An unexpected failure answers `500 {"error": "internal"}`.

### Roles and the abuse limit

On every path under `/v1/phones/{phone}`, the signer is either:

- **the phone**, when the signer key is `{phone}`;
- **a machine**, when the signer key is paired with that phone;
- anyone else, who gets `403 forbidden`.

Each endpoint below lists the roles it accepts.

Every authorised call to a phone counts towards its abuse limit, WebSocket upgrades included: `ABUSE_LIMIT_PER_DAY` calls (5,000 by default) per UTC day, the same for paid and unpaid phones. Over the limit the relay answers `429 rate_limited` with `{"retryAfter": <seconds>}` and a `Retry-After` header that both point at the next UTC midnight. **(planned)** The body also says which limit was hit: `{"error": "rate_limited", "retryAfter": <seconds>, "scope": "phone" | "network" | "key"}`; `phone` is the daily limit above, `network` and `key` are short-term limits per network address and per signing key, with their own `retryAfter`. Calls refused with `403` do not count, so a stranger cannot use up someone else's limit. The counter is kept in memory and can reset if the phone's object is evicted while idle.

Errors always have the shape `{"error": "<code>", ...}`.

### Endpoints

| Method and path | Who | Body | Success |
| --- | --- | --- | --- |
| `GET /v1/health` | Anyone, unsigned | | `200 {"ok": true}`; **(planned)** `{"ok": true, "env", "version", "time"}`, with `Access-Control-Allow-Origin: https://sealctl.com` for the status page |
| `GET /v1/health/deep` **(planned)** | Anyone, unsigned | | `200 {"ok": true, "objects": true}`, or `503 objects_unavailable` |
| `GET /v1/machines/{machine}` | That machine | | `200 {"phone", "proof"}` |
| `POST /v1/phones/{phone}/machines` | Phone | `{"machine", "name", "os"?, "model"?, "hint"?, "proof"?}` | `201` new or `200` known: `{"machine", "machines": <count>}` |
| `GET /v1/phones/{phone}/machines` | Phone | | `200 {"machines": [{"machine", "name", "os"?, "model"?, "hint"?, "pairedAt"}]}` |
| `DELETE /v1/phones/{phone}/machines/{machine}` | Phone, or that machine | | `200 {"machines": <count>}` |
| `GET /v1/phones/{phone}/wait` | Machine, WebSocket | | `101`, see below |
| `GET /v1/phones/{phone}/socket` | Phone, WebSocket | | `101`, see below |
| `GET /v1/phones/{phone}/requests` | Phone | | `200 {"requests": [{"id", "machine", "sealed", "created", "expires"}]}` |
| `POST /v1/phones/{phone}/requests/{id}/reply` | Phone | `{"sealed"}` | `200 {"delivered": true}` |
| `GET /v1/phones/{phone}/state` | Phone | | `200 {"rev", "blob"}`, `{"rev": 0, "blob": null}` at first |
| `PUT /v1/phones/{phone}/state` | Phone | `{"rev", "blob"}` | `200 {"rev": <rev + 1>}` |
| `GET /v1/phones/{phone}/licence` | Phone or machine | | `200`, see Licence |
| `POST /v1/phones/{phone}/checkout` | Phone or machine | `{"seats"?}` | `200 {"url", "seats"}` |
| `POST /v1/phones/{phone}/claim` | Phone or machine | `{"code"}` | `200 {"licence": "paid", "left"}` |
| `POST /v1/phones/{phone}/licence/move` | Phone | `{"to"}` | `200 {"movedTo"}` |
| `POST /v1/paddle/webhook` | Paddle, `Paddle-Signature` | Paddle's event | `200`, see Paddle |
| `PUT /v1/phones/{phone}/push/{device}` **(planned)** | Phone | `{"platform": "apns", "token", "sandbox"?}` or `{"platform": "fcm", "token"}` | `200 {"devices": <count>}` |
| `GET /v1/phones/{phone}/push` **(planned)** | Phone | | `200 {"devices": [{"device", "platform", "sandbox", "updated"}]}` |
| `DELETE /v1/phones/{phone}/push/{device}` **(planned)** | Phone | | `200 {"devices": <count>}` |
| `POST /v1/phones/{phone}/push/{device}/test` **(planned)** | Phone | | `200 {"ok": true}` |
| `DELETE /v1/phones/{phone}` **(planned)** | Phone | | `200 {"deleted": true, "machines": <count>}` |
| `PUT /v1/phones/{phone}/machines/{machine}/status` **(planned)** | That machine | `{"sealed"}` | `200 {}` |
| `GET /v1/phones/{phone}/status` **(planned)** | Phone | | `200 {"status": [{"machine", "sealed", "updated"}]}` |
| `POST /v1/phones/{phone}/machines/{machine}/messages` **(planned)** | Phone | `{"sealed"}` | `200 {"delivered": <bool>}` |
| `GET /v1/phones/{phone}/machines/{machine}/socket` **(planned)** | That machine, WebSocket | | `101`, see Machine channel |
| `POST /v1/phones/{phone}/delayed` **(planned)** | Phone | `{"id", "delay"}` | `201 {"id", "releaseAt", "expires"}`, see Delayed approvals |
| `GET /v1/phones/{phone}/delayed` **(planned)** | Phone or machine | | `200 {"delayed": [...]}` |
| `GET /v1/phones/{phone}/delayed/{id}` **(planned)** | Phone or machine | | `200`, see Delayed approvals |
| `POST /v1/phones/{phone}/delayed/{id}/cancel` **(planned)** | Phone or machine | | `200 {"cancelled": true}` |
| `POST /v1/phones/{phone}/delayed/{id}/finish` **(planned)** | Phone | | `200 {"finished": true}` |

Times (`created`, `expires`, `pairedAt`, `since`, `updated`) are Unix milliseconds.

**Pairing.** The phone registers a machine it scanned. `machine` is the machine's key; `name` is 1 to 200 characters; `os`, `model` and `hint` are up to 200 characters; `proof` is up to 128 base64url characters. Registering a known machine again updates its record and answers `200`. If the machine was paired with another phone, that phone forgets it. The machine polls `GET /v1/machines/{machine}` until it gets `200`, then checks `proof`.

- Errors: `400 bad_machine` (not a key, or the phone's own key), `bad_name`, `bad_os`, `bad_model`, `bad_hint`, `bad_proof`; `409 too_many_machines` past 100 machines; `402 licence_required` with `{"machines", "free"}` when the machine gate is on (below).
- `GET /v1/machines/{machine}`: `404 not_paired` until the phone registers it or after unpairing; `400 bad_machine`; `403 forbidden` for any other signer.
- Unpairing answers `404 not_paired` for an unknown machine, and closes that machine's open waits with the error `unpaired`.
- **(planned)** The relay no longer stores `hint`: it is accepted and dropped, and `GET /v1/phones/{phone}/machines` no longer returns it. The phone keeps the hint from the QR code in its own encrypted state.
- What `proof` holds and how the machine checks it is defined in [Pairing QR code and proof](#pairing-qr-code-and-proof).
- **(planned)** `GET /v1/phones/{phone}/machines` gains `lastSeen` per machine: the last time that machine made a signed call, Unix milliseconds, updated at most once an hour.
- **(planned)** When a machine is registered under another phone key, its open waits and machine socket on the old phone close with the error `moved` (close code 1008) instead of `unpaired`, so the machine looks itself up and checks the move proof.

**Machine gate.** Off when `MACHINE_GATE` is 0, which is the default. When it is N, registering a new machine on an unpaid phone that already has N machines answers `402 licence_required`. Re-registering a known machine is never refused.

### Requests and replies

A machine asks for one approval per WebSocket:

1. It opens `GET /v1/phones/{phone}/wait`, signed, with `Upgrade: websocket`.
2. It sends one message: `{"type": "request", "id", "sealed", "ttl"?}`.
   - `id`: 16 random bytes as base64url, 22 characters.
   - `sealed`: the sealed request, base64url, at most 4,096 characters.
   - `ttl`: seconds from 1 to 300; 300 when absent.
3. The relay answers `{"type": "queued", "id", "expires"}` and tells the phone.
4. When the phone replies, the machine gets `{"type": "reply", "id", "sealed"}` and the socket closes normally.

Other messages to the machine, each followed by the socket closing:

| Message | When |
| --- | --- |
| `{"type": "expired", "id"}` | The request passed its `expires` time |
| `{"type": "delayed", "id", "releaseAt"}` **(planned)** | The phone approved with a delay; the machine fetches the reply from `GET .../delayed/{id}` after `releaseAt` (closes normally) |
| `{"type": "error", "error": "bad_json"}` | The message was not JSON (close code 1007) |
| `{"type": "error", "error": "bad_request"}` | Wrong type, id or sealed (1008) |
| `{"type": "error", "error": "duplicate_id"}` | Another pending request has this id (1008) |
| `{"type": "error", "error": "unpaired"}` | The machine is no longer paired (1008) |
| `{"type": "error", "error": "one_request_per_socket"}` | A second request on the same socket (1008) |

Before the upgrade, the relay can refuse with `426 websocket_required`, `403 forbidden`, `429 rate_limited`, or `429 too_many_pending` when 32 waits are already open for that phone.

**(planned)** On the wait socket and the phone socket, the client sends the text message `ping` every 30 seconds and the relay answers `pong`. A message over 8,192 bytes closes the socket with `{"type": "error", "error": "too_large"}` and close code 1009.

The relay has no timer for expiry. It notices an expired request when the phone next lists requests or replies, so the machine should keep its own timer and stop waiting at `expires`.

The phone learns about requests in two ways:

- `GET /v1/phones/{phone}/socket`, signed, with `Upgrade: websocket`: the relay sends `{"type": "request", "id", "machine", "sealed", "created", "expires"}` for each new request. The phone sends nothing on this socket.
- `GET /v1/phones/{phone}/requests` lists the pending ones.
- **(planned)** A push notification through APNs or FCM to each registered device (see Push).

**(planned)** Requests on the phone socket and in `GET /v1/phones/{phone}/requests` gain `"near": <bool>`: `true` when the machine's wait and the phone's latest signed call came from the same network address. The relay compares keyed hashes of the addresses in memory and stores no address. The phone trusts `near` only while it is on Wi-Fi or Ethernet.

The phone replies with `POST /v1/phones/{phone}/requests/{id}/reply` and `{"sealed"}` (at most 4,096 characters). Errors: `400 bad_id`, `400 bad_sealed`, `404 gone` when the request expired, was answered, or its machine disconnected. A delivered reply counts the current UTC day as a day with use.

**(planned)** The body may add `"delay": <seconds, 1 to 7,200>` for a level 3 approval away from a trusted place. The relay then stores the sealed reply as a delayed approval (below), sends the machine `{"type": "delayed", "id", "releaseAt"}` instead of the reply, closes its socket normally, and answers `200 {"delivered": true, "releaseAt"}`. Errors add `400 bad_delay` and `429 too_many_delayed`.

The approval path writes nothing to storage: a pending request lives in its WebSocket's attachment, which Cloudflare keeps through hibernation up to 16,384 bytes. The 4,096-character cap keeps it well inside that. If the machine disconnects, its request is gone and it asks again. The one exception is a delayed approval, which must outlive any socket for up to two hours.

### Encrypted state

The phone keeps its pairings, places, answers and inventory on the relay as one blob encrypted with its state key.

- `GET` returns `{"rev", "blob"}`.
- `PUT` takes `{"rev", "blob"}`, where `rev` must equal the stored rev, and stores the blob as `rev + 1`.
- `blob` is base64url of at most 1 MiB (1,048,576 bytes) once decoded.
- Errors: `409 conflict` with the stored `{"rev"}`, `400 bad_rev`, `400 bad_blob`, `413 too_large`.

Compare-and-swap means a replayed or stale upload cannot roll the state back.

### Licence

`GET /v1/phones/{phone}/licence` answers:

| Field | Meaning |
| --- | --- |
| `licence` | `"paid"` or `"unpaid"` |
| `source` | `"purchase"`, `"seat"`, `"moved"`, or `null` |
| `since` | When it was paid, or `null` |
| `movedTo` | The phone key this licence was moved to, or `null` |
| `daysUsed` | UTC days with at least one delivered reply |
| `ask` | `true` when unpaid and `daysUsed` is at least `ASK_AFTER_DAYS` (30) |
| `machines` | Paired machines |
| `machineGate` | N when the machine gate is on, else `null` |
| `codes` | Seat codes this phone bought: `[{"code", "seats", "claimed"}]` |
| `revoked` **(planned)** | `"refund"`, `"chargeback"`, or `null`: why a paid licence was taken back |

The relay only says whether to ask. When and where to print the request to pay (stderr, after a command a person typed, at most once a week) is the CLI's job.

**Checkout.** `POST /v1/phones/{phone}/checkout` with `{"seats"}` (an integer from 1 to 1,000; 1 when absent) asks Paddle for a transaction and returns Paddle's checkout link. The relay sends Paddle:

```json
{ "items": [{ "price_id": "<PADDLE_PRICE_ID>", "quantity": <seats> }], "custom_data": { "phone": "<phone>", "seats": <seats> } }
```

- Errors: `400 bad_seats`; `409 already_paid` for one seat on a paid phone; `503 payments_not_configured` without the Paddle settings; `502 payments_unavailable` when Paddle fails.
- More seats can be bought on a paid phone, for a team.

**Paddle webhook.** `POST /v1/paddle/webhook` checks `Paddle-Signature: ts=<unix>;h1=<hex>`. `h1` is HMAC-SHA256 with the webhook secret over `<ts>:<raw body>`; any one of several `h1` values may match. `ts` must be within 5 seconds, as in Paddle's SDKs.

- Errors: `401 bad_signature`, `400 bad_json`.
- Only `transaction.completed` events with a 32-byte `custom_data.phone` and positive item quantities are used. Anything else answers `200 {"ignored": true}`.
- The result is `200 {"granted": true, "code": <code or null>}`, or `200 {"duplicate": true}` for a transaction already seen. The last 100 transaction ids are kept per phone.

What a purchase grants:

- **One seat:** the phone is paid, with source `purchase`.
- **Several seats:** the relay creates a seat code with that many seats. The buying phone takes one of them unless it is already paid, and the code appears in its `codes`. The chosen code is noted before the seat pool is created, so a webhook that Paddle retries after a crash reuses it.

**Seat codes.** Eight characters of Crockford base32 without I, L, O and U, written `XXXX-XXXX`: 40 random bits.

- `POST /v1/phones/{phone}/claim` with `{"code"}` takes a seat. The code is matched case-insensitively, ignoring spaces and dashes, with I and L read as 1 and O as 0.
- A claimed seat stays with that phone. Claiming again from a paid phone answers `409 already_paid` and takes no second seat.
- Errors: `400 bad_code`, `409 already_paid`, `404 unknown_code`, `409 no_seats_left`.

**Moving the licence.** When the words change, the old phone key moves its licence to the new one with `POST /v1/phones/{old}/licence/move` and `{"to": "<new phone key>"}`, signed by the old key. The new phone becomes paid with source `moved`, unless it already was. The old one becomes unpaid with `movedTo` set. Errors: `400 bad_target`, `409 not_paid`.

**(planned)** The body becomes `{"to", "proof"}`, where `proof` is the new key's Ed25519 signature, base64url, over the text `sealctl-licence-move-v1\n<old phone key>\n<new phone key>` (no trailing newline). The answer is `200 {"movedTo", "licence", "daysUsed"}`. Unpaid phones may move too, and days used carry over, so `409 not_paid` goes away. A proof that does not verify answers `400 bad_proof`. A vector is in `docs/vectors/relay-signing.json` (`licenceMove`).

### Push (planned)

- A device id is 22 random base64url characters, made once per app install. A phone has at most 4 devices.
- `PUT /v1/phones/{phone}/push/{device}` registers or updates a token: `{"platform": "apns", "token": <hex>, "sandbox"?: <bool>}` or `{"platform": "fcm", "token": <string>}`. Errors: `400 bad_device`, `400 bad_platform`, `400 bad_token`.
- `DELETE /v1/phones/{phone}/push/{device}` answers `404 unknown_device` for a device it does not know.
- `POST /v1/phones/{phone}/push/{device}/test` sends a test push. Errors: `502 push_failed` with `{"reason", "removed"}` (`removed` is true when the provider said the token is dead and the relay dropped it), `503 push_not_configured`.
- A push carries only the type, the request id and its expiry. The app fetches and opens the sealed request itself. Types: `request`, `test`, and `delayed` and `cancelled` for [delayed approvals](#delayed-approvals-planned), where the id is the delayed id and the expiry is `releaseAt`.

### Machine channel (planned)

Proposed by the phone app and needed for Open time left, the usage log and locking when the phone leaves a place. The sealed formats are in [Machine status and messages](#machine-status-and-messages); the relay sees only sealed strings. Until it ships, machines use a `report` request as described there.

- `PUT /v1/phones/{phone}/machines/{machine}/status` with `{"sealed"}` (at most 8,192 characters) replaces that machine's latest status. The relay keeps one status per machine.
- `GET /v1/phones/{phone}/status` lists the latest status of every machine.
- `POST /v1/phones/{phone}/machines/{machine}/messages` with `{"sealed"}` (at most 4,096 characters) queues a message for that machine; at most 16 are held per machine, oldest dropped first, each for at most 24 hours. `delivered` is true when the machine's socket was open and took it.
- The machine opens `GET /v1/phones/{phone}/machines/{machine}/socket` while its session is Open. The relay sends each held message as `{"type": "message", "sealed", "created"}`, then each new one as it arrives, and drops it once sent. The machine sends nothing but `ping`. The socket hibernates while idle. An unpaired or moved machine's socket closes with `unpaired` or `moved`.
- A status update also wakes the phone's socket with `{"type": "status", "machine"}`; no push is sent for status.

### Delayed approvals (planned)

A level 3 approval away from a trusted place waits two hours (see [Delayed approvals](#delayed-approvals)). The relay holds it, announces it and lets anyone paired cancel it.

**Why storage.** Normal approvals live only in a socket's attachment. A delayed one cannot: the machine's socket would have to survive two hours of sleep and network changes, a delay on the phone alone has no machine socket, and a cancel must work while the machine that asked is offline. So the Phone object stores one record per delayed approval, `delayed:<id>`, and deletes it when it is fetched, finished, cancelled-and-expired, or expired. The record holds `{machine or null, sealed or null, created, releaseAt, expires, cancelled?: {by, at}}`. `sealed` is the reply sealed to the machine's one-time key, which the relay cannot open. These are rare: a few in a person's use of sealctl.

| Call | Who | Does |
| --- | --- | --- |
| Reply with `delay` | Phone | Creates the record with the request's `id` and `machine` and the sealed reply |
| `POST .../delayed` with `{"id", "delay"}` | Phone | Creates a record with no machine and no sealed reply, for an action on the phone. `id` is 22 base64url characters made by the phone (`400 bad_id`, `409 duplicate_id`). `201 {"id", "releaseAt", "expires"}`; `400 bad_delay`, `429 too_many_delayed` |
| `GET .../delayed` | Phone or any paired machine | `200 {"delayed": [{"id", "machine", "created", "releaseAt", "expires", "state"}]}`, `state` `waiting`, `released` or `cancelled` |
| `GET .../delayed/{id}` | Phone or any paired machine | The same fields for one record. For the machine that asked, once `releaseAt` has passed and it is not cancelled, also `"sealed"`, and the record is then deleted. `404 gone` when there is no such record |
| `POST .../delayed/{id}/cancel` | Phone or any paired machine | Drops `sealed`, sets `cancelled` `{by: "phone" or the machine key, at}`; the record stays as a tombstone until `expires`, so the machine that asked learns why. `200 {"cancelled": true}`, also when already cancelled; `404 gone` when fetched, finished or expired |
| `POST .../delayed/{id}/finish` | Phone | For a record with no machine: once `releaseAt` has passed and it is not cancelled, deletes it and answers `200 {"finished": true}`. `425 too_early` with `{"releaseAt"}`; `409 cancelled` with `{"by"}`; `400 bad_id` for a record that has a machine; `404 gone` |

- `delay` is 1 to 7,200 seconds; `releaseAt` = now + `delay`; `expires` = `releaseAt` + 900 seconds. A record past `expires` is deleted and answers `404 gone`.
- At most 4 records per phone; a fifth answers `429 too_many_delayed`.
- **Notes.** On create, the relay sends `{"type": "delayed", "id", "machine", "releaseAt"}` on every open phone socket and machine socket, and pushes `{"type": "delayed", "id", "expires": <releaseAt>}` to every push device. On cancel, `{"type": "cancelled", "id", "by"}` on the same sockets and a push with `"type": "cancelled"`. A machine socket that opens while records are pending gets one `delayed` note per record. The phone also sends each paired machine a sealed `notice` message.
- Deleting the phone deletes its records.

### Deleting a phone (planned)

- `DELETE /v1/phones/{phone}`, signed by the phone, deletes its machines, state, push devices, machine status and held messages, delayed approvals, and pending requests, and answers `{"deleted": true, "machines": <count>}`. A licence record that is paid, moved or refunded stays (licence, Paddle transaction ids, seat codes), so a later restore from the words is still paid and a refund still finds the licence. Nothing else stays.
- A phone with no signed call for 730 days has its data deleted the same way.

### Changing words on the relay (planned)

The phone runs these steps in order, while it still holds the old root:

1. The new key uploads its state: `PUT /v1/phones/{new}/state` with `rev` 0.
2. The old key moves the licence to the new key (above).
3. The new key registers each machine again with `POST /v1/phones/{new}/machines`. Its `proof` is the 96-byte move proof from [Phone key change](#phone-key-change-new-words), which the machine checks with the old key it already trusts.
4. The new key registers its push devices.
5. The old key deletes itself with `DELETE /v1/phones/{old}`.

### Limits

| Limit | Value |
| --- | --- |
| Signature time window | 300 seconds |
| Request body | 1,500,000 bytes |
| Calls per phone per UTC day | `ABUSE_LIMIT_PER_DAY`, 5,000 |
| Sealed request or reply | 4,096 base64url characters |
| Request lifetime | 1 to 300 seconds, default 300 |
| Open waits per phone | 32 |
| Machines per phone | 100 |
| State blob | 1 MiB |
| Seats per checkout | 1,000 |
| Paddle webhook clock tolerance | 5 seconds |
| Request body, other than `PUT state` **(planned)** | 16,384 bytes |
| WebSocket message **(planned)** | 8,192 bytes |
| WebSocket keep-alive **(planned)** | `ping` every 30 seconds |
| Push devices per phone **(planned)** | 4 |
| Data kept without a signed call from the phone **(planned)** | 730 days |
| Sealed status, sealed machine message **(planned)** | 8,192 and 4,096 characters |
| Machine messages held per machine **(planned)** | 16, for at most 24 hours |
| Delayed approvals per phone **(planned)** | 4; delay 1 to 7,200 seconds; kept 900 seconds after `releaseAt` |

## Appendix A: test vectors

All values were computed by the script in Appendix B. Hex is lowercase. The script also writes them all to `docs/vectors/v1.json`, and the relay signing vectors to `docs/vectors/relay-signing.json`. The Rust core, both apps and the relay tests check them.

### Words and roots

| | Words A | Words B |
| --- | --- | --- |
| Entropy | 32 zero bytes | `SHA256("sealctl test vector B")` = `1e184193586466f416402377363e28d4a528487350d1765f1bc6338ccd2a939c` |
| Mnemonic | `abandon` × 23, then `art` | `bulk search gospel radio edit key flip afford jaguar rapid mechanic power family category snap boss iron web various grow smoke next example lounge` |
| Seed | `408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840` | `7502614a61d8af5a8f0ee5ca79d5c6ffa0283859f7c67ddcb0b9d5050a3dbea0038db02787a913afeb2ca19ca9b6ef4ab262ebb60b6ef819d9e8684f33088abd` |
| Root | `c84ec5e5a42bb700ac138f9fcf479c119281813b2b58d57d1ce867cd125bc387` | `c5bc09a521badc47362bde04e971bef78ae8affae6efc8cbfc0732e3d614c0b5` |
| `derive(root, "fingerprint", 8)` | `754d1b90b1e5e357` | `dea749f9a2cc7038` |
| Words fingerprint | `hYNi` | `qHWf` |
| Phone identity seed | `da11aecf08f293cc3b477215bf611239942b322944328a2ba8a7e9b1d50d9198` | `3c3bee53d281b885c38f4630822bec3610231d463687584f68ff8c1251efb8bc` |
| Phone identity public key `P` | `4Zkfuuv3Jt7aychw6n9UcFN8xz5RMHzxogXuGEG_-8Y` | `6jOhto9rTH8m9Up6iegjDiB66iuP5cbQcp5Jsw0S-Vk` |
| Phone box private key | `cfc44443ca8710d225b15176cd657ff5e4d06bdf39dda7d242e694287aa2b4a0` | `b42cade7b7c57cd0cb3253f1eea6f128a7b3be7fced8065132555982228300a7` |
| Phone box public key `X` | `BqbhR1uHQPxCAQQyqMJPLPKTKTzq9Yy89rdkdeSXHXQ` | `EJ4y1Oe4rkm4dufqP-AHPtR5WIsso3php0rQmPs65AQ` |
| State key | `7c261415db10d3bd7d181ef42a640843e8d198d03867de7981aa08879f519f84` | `581bbb4357daa1fbbf97c496e79a34fc1f09a910798be4fd232263b0b83f1349` |

Seed A is the published BIP39 vector for this mnemonic with an empty passphrase. With the passphrase `TREZOR` the same code gives BIP39's own vector `bda85446…92fcc8`.

### Object keys (words B)

| Purpose | Id | Key (hex) | Key as `b64u` | Check |
| --- | --- | --- | --- | --- |
| `secrets` | `0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f` | `5677fb191b04d79e01050b92bd729019` | `Vnf7GRsE154BBQuSvXKQGQ` | `Je_Q_YPg3B0` |
| `secret` | `3d7e1b9a-2c4f-4a8e-b6d1-5f0e9c2a7b34` | `bc5e20d3004ebb9fcbc70716675a60f4` | `vF4g0wBOu5_LxwcWZ1pg9A` | `65tvJfDbPUw` |
| `volume` | `fa5a93d5-28d9-4c08-b608-c2b6f344b4d8` | `1e5df55d6efd8fc9ae89ee1434bd9bfa` | `Hl31XW79j8muie4UNL2b-g` | `4lcdvKgJcu4` |
| `backup` | `6c1f0b2e-8d3a-4f7b-a9e4-2b5c7d8e9f01` | `86e9a954ddf9eb7a827d4f95b8538b1a` | `humpVN3563qCfU-VuFOLGg` | `WI2ym_Ma7M8` |

The volume passphrase given to `diskutil` is `hex(key)`: `1e5df55d6efd8fc9ae89ee1434bd9bfa`.

### Sealed files (words B)

Store id `0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f`, file id `3d7e1b9a-2c4f-4a8e-b6d1-5f0e9c2a7b34`, name `shop/openai-api-key`, value `test-value-not-a-real-key` (25 bytes).

| | Mode 1 (store key) | Mode 2 (own-approval key) |
| --- | --- | --- |
| Nonce | `000102030405060708090a0b` | `0c0d0e0f1011121314151617` |
| File key | `6dff6bde9cc76ddd950ec941785f313e2963cb69c482120783a94d35e856a8e3` | `6b2bf49df137be922adffb79217fc146f666aab32962626578163d4c5e361111` |

Mode 1 file, hex:

```text
5343533101714857663d7e1b9a2c4f4a8eb6d15f0e9c2a7b34000102030405060708090a0b0ecd1cceef004d909df5e2b4128e7398cfb332ca3df24f496f18f4280438c8a4353dace2e61bc27022
```

Mode 2 file, hex:

```text
5343533102714857663d7e1b9a2c4f4a8eb6d15f0e9c2a7b340c0d0e0f10111213141516171b3be8a37ddb80ac9c97032f5fd474e074651e27cf18e928cd1f89ab64763b616dbe9fa2d4aadd711a
```

### State blob and storage formats (words B)

State blob, nonce `18191a1b1c1d1e1f20212223`, plaintext `{"v":1}`:

```text
ARgZGhscHR4fICEiI-CQ_7xceVbKZkJ1FfSlhWXk0KoPpJ6z
```

Words backup item, created 2026-11-21T09:00:00Z, hex:

```text
011e184193586466f416402377363e28d4a528487350d1765f1bc6338ccd2a939c71485766000001a1fd557a80
```

### Machine and pairing

| | Value |
| --- | --- |
| Machine pairing seed | `SHA256("sealctl test machine")` = `0989ff28e15082da9bb580b18e7ce58d8c666779a43656a9896312ab698d1540` |
| Machine public key `M` | `0F1KEPyKdmRmXeKvFt-eqoWgd_KglZaTGvTE2uYiKJ8` |
| Machine box private key | `SHA256("sealctl test machine box")` = `4795c65ec37844793bd167f8d937c3bc306204ff90e7f549c9bccc03caad6945` |
| Machine box public key `MX` | `4jROv9hrxxgxPnthhEjuVMcIKPKlN0g8pJe8D7GS4nE` |
| Tag | `7k2g` |
| Hint, for `/etc/machine-id` = `0123456789abcdef0123456789abcdef` | `LpZG-TSgDnt6i1pN_Q2CKA` |
| Pairing code `c` | `000102030405060708090a0b0c0d0e0f` |
| `mac` with phone B | `e14918889a9ffb8a5785761ccf0ee1b6db3d94762108145c5f51c89c047a4f8a` |
| Pairing proof (64 bytes) | `EJ4y1Oe4rkm4dufqP-AHPtR5WIsso3php0rQmPs65AThSRiImp_7ileFdhzPDuG22z2UdiEIFFxfUcicBHpPig` |
| Move signature, old words A to new words B | `db31b0c6a037667fe05107ac69b146a8484f6ea0327567bb122cf967f19d5c5360d8cb846d4d76f7e89a3ed68a267b50f2984ccfe4aec45b41cabe67cd6da405` |
| Move proof (96 bytes, 128 characters) | `EJ4y1Oe4rkm4dufqP-AHPtR5WIsso3php0rQmPs65ATbMbDGoDdmf-BRB6xpsUaoSE9uoDJ1Z7sSLPln8Z1cU2DYy4RtTXb36Jo-1oome1DymEzP5K7EW0HKvmfNbaQF` |

QR link for name `dev@mbp.example.com`, OS `macOS 15.2`, model `Mac15,3`, expiry 2026-11-21T09:10:00Z:

```text
https://sealctl.com/p#v=1&m=0F1KEPyKdmRmXeKvFt-eqoWgd_KglZaTGvTE2uYiKJ8&x=4jROv9hrxxgxPnthhEjuVMcIKPKlN0g8pJe8D7GS4nE&s=AAECAwQFBgcICQoLDA0ODw&n=dev%40mbp.example.com&o=macOS%2015.2&d=Mac15%2C3&h=LpZG-TSgDnt6i1pN_Q2CKA&e=1795252200
```

### Request and reply (machine above, phone B)

For the vectors, the one-time key and every HPKE ephemeral key come from HPKE `DeriveKeyPair` with fixed input, as RFC 9180's own vectors do. Real senders use fresh random keys. X25519 private keys are shown as `DeriveKeyPair` gives them, before clamping; a library that keeps keys clamped (x25519-dalek) shows the same key with the low three bits of the first byte cleared and the top bit of the last byte cleared, bit 6 set.

| | Value |
| --- | --- |
| Request id (bytes `30` to `3f`) | `MDEyMzQ1Njc4OTo7PD0-Pw` |
| One-time private key, `DeriveKeyPair(SHA256("sealctl test one-time key"))` | `64a7bf73cb9da8da1be161a8dd8d607156d7158773a9787951b2e168e1a6791f` |
| One-time public key | `5GqC2BI0h8VYrl7inW-V3WdKxNuQrJJp3AEItm0vJ24` |
| Request ephemeral input key material | `SHA256("sealctl test ephemeral request")` |
| Request `enc` | `85d44ac681b1806e375705f6b15b76844a3898b52625b5282b5d8def6f2eda68` |
| Request signature | `409cc9e25dd66dd2110aa39c10b335b281612fb00ef9422b5b197a79197bd8389f8e70622179455ee70c65a5db110d16971db2ee5d898696ab48cd27b3878d0e` |
| Reply ephemeral input key material | `SHA256("sealctl test ephemeral reply")` |
| `rq` | `UIPOtjNiqc6O1JhHzBlATdNrnGkmUspdKaNs6VSBBK4` |
| Reply signature | `abcadfecdac5f8ad588629a71485305574b927239db92df7c032187eac94f8339130ba2ec6861e48237eb1ef63003b46dd6622ed54634a0bc9c8bc527dbcaa0d` |

Request body (exact bytes):

```json
{"v":1,"t":1795251600000,"why":"open","ot":"5GqC2BI0h8VYrl7inW-V3WdKxNuQrJJp3AEItm0vJ24","ctx":{"agent":"Claude Code","repo":{"id":"github.com/acme/shop","name":"acme/shop"},"cmd":"npm test","cwd":"~/src/shop","user":"dev@mbp.example.com","subject":{"k":"secret","n":"shop/openai-api-key"},"n":["shop/openai-api-key"]},"keys":[{"p":"secrets","i":"0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f","w":"qHWf","c":"Je_Q_YPg3B0","o":{"k":"store","p":"~/.local/share/sealctl/store/0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f","s":4096}}],"uses":[{"a":"Claude Code","r":"github.com/acme/shop","n":["shop/openai-api-key"]}],"work":0}
```

Sealed request (960 characters):

```text
hdRKxoGxgG43VwX2sVt2hEo4mLUmJbUoK12N728u2mils1pe7RrLckfSXs36nErQsgB81ptoKH_XpvsisGoR74zMDudcn5x9v8757gSpUWFoEYtiJNJ-w63dIS1j8pctwHqk6biS68DZf3kG84awDc6xLLj6h9-xGPGeiTT6zNj-m-RyyN8-xS-1RuLPTVJgy6L06umNJzl4q6-J35vN7hMzRWTnU4qjAradBwHXjbVribPWcTx8l9HhtbfOCK1G3gkOfosS-ay_GnKQNUt0kjWf6YH1b2ftAuA-IbnhGdnIvZBWDjpY3Szb7yXZnFq-qWGP6CxWJSe0rviw3OcwgkE-UPR7gLHJluuKUxOPzZGebgTdjIAKXwmoorHUFaT_0EQutqrpn1vTgxAdVz6x5VaD5Njw8s3vhs5fmhmiZGkvgHLm5ALuh-pMhj-7urV5QYg9h0IMSoKWGR6AoN6wIBkRJOu6YZpHd8G6eUeAMHRF2ogBz1eVwpQjzY11aj1q67qZd8kzq7h5ddF6GhPpA8IzmvenmLRTbzlf0aLCOswy7fRSGkwW3OPdmRrqvsm7KUIXLCfTlRc331zQg9tH0--k4GgV8RjkycgQEiRIk8RXCLB8zZkRJTUfe9kOYBldMiPNitsGhuddgpXONDmjQ6escwkHM3_LOF-P4KgsnkaPG0uCuPYl2Y_oXDYMkY9K2j9l5A-PA5o2ZttgNJw6lfwNDScyVtYpEn-5yPWiiHLOjeqIscXEhns7B_tfmJ9GCsn4iSaTf9rMO85zhLhRrtzZY97Ew4XwtSVktw6sI6Goe_PwF-Zq0MP4vIdMJyRHg0LZ8gcl5r0xPuIwk9hmI3neljArrFZWp5VJVVsf8BbBUhwmei3slQspaPEav7lF_R_XsPI_b5m0efq5_fwPk5zpQ9OdfF3iR4ChTMXk4v4jn_cI4FVI6QbKGptRTo02
```

Reply body (exact bytes):

```json
{"v":1,"rq":"UIPOtjNiqc6O1JhHzBlATdNrnGkmUspdKaNs6VSBBK4","ok":true,"w":"qHWf","grant":"session","remember":true,"place":"trusted","cap":14400,"base":1800,"rate":120,"keys":[{"p":"secrets","i":"0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f","k":"Vnf7GRsE154BBQuSvXKQGQ"}]}
```

Sealed reply (500 characters):

```text
yDNmrFFqhsR1Sl4EaWphsCfNq4W4i9TiqNszeJU2b23_fhdBzd06Ray1tqKGpjxtFGxPB12iH8RmDxNK9r_Ef26Js-u6l2TQfQng1dEsUnkCEozy_pgK_BJ2oJK8lbHTs6MdZGHCRZr0K2xbmjwZDVDCoFjRqi1aD4zBPVb7kGP5ABwBxfpi6Sg2vn3uaYnVFInAtkhTR4tx8car5lGehKqyF7xXUG3SyOCey-H8_bapRgz-ys1TuYDsrWzHnixl2dombnDcBFqgOyfrrB4XQIOm3n0goBLwG2Cfre5gx4ucfKFx_dElzYf5nxmGHXjIvVuw-ar-mD1EEm4Sk1l2VpRGAW-m0sUADflRl9lZ5yj69d_CDTI0dF1pQTMkAjZIrVaUYR68Y6GiKtwU-aMo_cQKgZ4NnXbP9jDfBcAd3CnxfeO0FXWlMIwT7TFf5f-03Uhzd2ut_Y5_vp1jsXS201oCLreJEKSHlTU7bR_Q5SoIUyuNziLG
```

### Machine status and message

Status ephemeral input key material `SHA256("sealctl test ephemeral status")`; message ephemeral input key material `SHA256("sealctl test ephemeral message")`.

| | Value |
| --- | --- |
| Status signature | `f18abd4aead7213f2d75d2586a69582f3d973b2799fa71142ffbae600acbe6a35b8574ae4edebe5d2e4cdf320e12c957c18994f127211c1927169a250898ca0a` |
| Message signature | `b17341a6688aa1fc9d75dc6565e6d908300d6e53d0e14674ea888f664bd4d3e9f0ca1b2b2b424c5ed84a886215e87cba96438e6d842d9f394bd8a7c8768f6700` |

Status body and sealed status:

```json
{"v":1,"t":1795253400000,"seq":1,"state":{"s":"open","left":13200,"stop":1795309200000,"place":"trusted"},"log":[{"t":1795251660000,"a":"Claude Code","r":"github.com/acme/shop","c":"npm test","n":["shop/openai-api-key"],"own":false}]}
```

```text
Ua-CF1FcHm_EpmUXE9XE9neN3arulA0FkYw8rPGkxRBEjoTrx7rT3FWMwetlcU0OTlxhhYt5l1c5S-yBZA51n_dKXqawpvv1NE-g1WXF_1SY_yhuIMwzPdv4uaonBRSUmvAgx-n_o2jOaLpDBe2__uVPGd7nMAI7CJ6iT20sj3-cm-3v2NP5TacL2A99T4TlfSqiYILCc4dPbglaG1WHkYBcGY8VmK6dM-fJwwFoNTz3Tsu7YQaEiCq3Kls3oqw68MlVu2Lq0jrSltsCxehP-P1wNH47kzi9CehRHqoxm7xs9fhmbs5tMF2GbRs3Ys0WIQT-aTfdfHnetx1ngEylOYD4Z61qdigQZV1PqG3for_TC8bsZCmX0vD4UkMIiZaf5t1HcTK5OYsof7F-MHOAgOl6lboav3cTgcadaalCxGpFdyoqjPKGQU34lNN0X-JH2chmiTLKxGcBPw
```

Message body and sealed message:

```json
{"v":1,"t":1795266000000,"seq":1,"type":"lock","reason":"place"}
```

```text
kSu_90aNYw5cu9GZEPGDWrc_5q3oVLjtofTLbfTN8DGaEIi_AfEwDUCI8zujYABAC_gTsQ8Hh1aI-6g1uEkEdy_khe2CNPX6W-w7_unQVcDu0VX9kJIUcsBWW7WTuQk6bclG0kSahBjH80qYRlz1rriC0P4D631TMgiV-i2HPBAKP7n7NZ-3J0GE4_tdqfA3FzVp64WTtdFim8C8o30P2DNTVNJJ9CJWCev_JA6trlQ
```

### Unseal: number match and plan signature (machine above, phone B)

A level 3 `unseal --all` request with `match`, its number, the plan hash and the plan signature, with a delayed `nb` (here one hour after `t`; the vector checks the signature over `nb`, not the length of the delay). Keys as in Object keys above.

| | Value |
| --- | --- |
| Request id (bytes `40` to `4f`) | `QEFCQ0RFRkdISUpLTE1OTw` |
| One-time public key, `DeriveKeyPair(SHA256("sealctl test one-time key unseal"))` | `1xUvEc4lX4VSHgBQzZD2FNQuU94uqDrjxCTwSfbQ1nY` |
| Request ephemeral input key material | `SHA256("sealctl test ephemeral unseal")` |
| Request `enc` | `f3b45eb260fd1c2e2faa466a97ca1a20e64e56e91b0eb119c4f29b4e3eef445d` |
| Request signature | `4b4c724d4fe34a4c5559fdc573095208e1130b4aecb8f101f7dab49ffc40ed2f7e7f4054b216f542848b14b7704fff035723016053377b610283174a8ef82c09` |
| `HPKE-Export(…, "sealctl/v1/match", 4)` | `63aa18dd` |
| Number `N` | `59` |
| Plan hash `h` | `aQflz4JdVBW_hQrHlC9GlH0JOhJ1PSVy7VSUObEo7dE` |
| `nb` | `1795258800000` (2026-11-21T11:00:00Z) |
| Plan signature (hex) | `b28c6d717b373abc9561966486ee191538751c36b862a96e5a1e2f2849e8a1bc454d4c228a486bef211055bc6c430aabb01c63002f00bbe01513643a37d2c00f` |
| Reply ephemeral input key material | `SHA256("sealctl test ephemeral unseal reply")` |
| Reply signature | `3f3660007e9f2cc448c4cf99a8b33612a00beb326d5ed39ed5022b8e78810fe7ef920b913b752efa2ffdccbe4dd9d0f37705c171e6adba4b5cc27249a55d0405` |

Plan text (exact bytes; `\t` is a tab, `\n` a newline):

```text
sealctl-plan-v1\n0F1KEPyKdmRmXeKvFt-eqoWgd_KglZaTGvTE2uYiKJ8\nsecrets\tstore\tsecrets\t0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f\nvolume\tsafe\tvolume\tfa5a93d5-28d9-4c08-b608-c2b6f344b4d8\nssh\ted25519\tsecrets\t0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f\ngit\tsigning\t\t\nai\tClaude Code\t\t\nservices\tdaemon\t\t\nlocal\t~/.config/sealctl\t\t\npairing\tdev@mbp.example.com\t\t\n
```

Signed plan message, hex (`"sealctl/v1/plan"`, `0x00`, id, `0x00`, `M`, `ph`, `nb`):

```text
7365616c63746c2f76312f706c616e005145464351305246526b64495355704c5445314f547700d05d4a10fc8a7664665de2af16df9eaa85a077f2a09596931af4c4dae622289f6907e5cf825d5415bf850ac7942f46947d093a12753d2572ed549439b128edd1000001a1fdc35780
```

Request body (exact bytes):

```json
{"v":1,"t":1795255200000,"why":"unseal","lvl":3,"ot":"1xUvEc4lX4VSHgBQzZD2FNQuU94uqDrjxCTwSfbQ1nY","match":true,"ctx":{"agent":null,"repo":null,"cmd":"sealctl unseal --all","cwd":"~","user":"dev@mbp.example.com","subject":{"k":"machine","n":"unseal"}},"plan":{"all":true,"h":"aQflz4JdVBW_hQrHlC9GlH0JOhJ1PSVy7VSUObEo7dE","items":[{"k":"secrets","n":"store","p":"secrets","i":"0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f"},{"k":"volume","n":"safe","p":"volume","i":"fa5a93d5-28d9-4c08-b608-c2b6f344b4d8"},{"k":"ssh","n":"ed25519","p":"secrets","i":"0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f"},{"k":"git","n":"signing"},{"k":"ai","n":"Claude Code"},{"k":"services","n":"daemon"},{"k":"local","n":"~/.config/sealctl"},{"k":"pairing","n":"dev@mbp.example.com"}]},"keys":[{"p":"secrets","i":"0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f","w":"qHWf","c":"Je_Q_YPg3B0","o":{"k":"store","p":"~/.local/share/sealctl/store/0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f","s":4096}},{"p":"volume","i":"fa5a93d5-28d9-4c08-b608-c2b6f344b4d8","w":"qHWf","c":"4lcdvKgJcu4","o":{"k":"volume","p":"/Volumes/safe","s":53687091200}}]}
```

Sealed request (1,596 characters):

```text
87ResmD9HC4vqkZql8oaIOZOVukbDrEZxPKbTj7vRF3kaEGSvN_4TMw_Z1hftawnwLsnwFHM40njkwVSEwknqh4gWOyZ2HUU8kWzTYxB8DbUD7Fl1Sk2JLAc-7JXIXMrn2SV30U9VkSxncwjaU4gUqii3tQ3QLSb3n6gzeVPrM7bjVpAXI-pAuCXwLyMAmmmPUtt_AdEyCUrtZP3rnv7_ymsTw2JkqidbyHwQu2H5vPBFHwx8MRzKOqisPssvwZuL2eJmReH_PYEV6t-F_lSJB0Wws6Cwnk502LhNQBpNTSXdTU2lQZBlZZy5V_4RQEgFBIPTybIuJNzvAK6J9WKvmHs5aGGk52zrjrfmWZmuOfKavmbBFggLx5kCcNWNCQcx3GQivlvamQCqHwbabItPbWIg_UxpKHdCBaW1zpsYmcmOmLEOZ6Tc-RobOkgVYMxgkSjsIEQhpZvNf38mtF-cBUGqwDZpx2Nv3j5OAj6U-h_zf1FTTcfIJ85NZfG7t514Wng4vgE5zmpXSCE_l02zYSfAVS56GH2z-jUxNZaChzvwdJNkPpE-AsOIr4zgaOG8NgV_JxNhWN0fsDi8pfSSwDOukG23Ghfv1sgpjVxtqBts3hgRd0C_9so13NOeo5Fef4Ix7BRFBjUtVoXRLNITMPSnTT0pssDhsuq67fCmVGq0hoMEzy0w2rB606v6nz3UTKLVG-mzKCf-59C1hWR1hBslLONrr-Q68wL3ATsH58sJu0Lh2Ro2RjqCoR94aWC1TggVh8BD9bKaRl5ZBTGhmc7hNYdlCsxrP1pPAEkUxbE5mpVmMHirv_BSGsluaE9WMhI5P20r3LNM6043GJMgEW1PX7R4xY00BpFDCzTgY8it90dW1Vki8xaRK2rF9mgrc-PwWUizpGM1lQcZZXgg0a-tBtj7Duk4Dsosg-VJrC4v6YwRuwXTIcte6ZX1KUs5DhEf_rehtdcCHb05hX0tIjVp1qZccC32jqojbB5TBnyqShd5cjOoVenH4ba5kKB1__mca25KRu2P3bJaKzGA4Ifp1T-C_21Y8fPX8r-IJzdde4lQpK7P4A0rbqOCOFQ4WnHdWphQXcebjam6UMFXA3MeU2m-O0X1Lya61lxGZYjbQEIT3aN2qrv5mRdGykTqPQaDSHjeNa3e6JMaVKRNsSmkguJ5x72_Ch07veR1rbmRda9mG7fPQJIfUAtBu4vABu1VvzMNEbO2Sh2_TMeM8HohTUO77od_XrLsKkHpr1DnAcfmqB6GsIRRoNDGJtousLonzkaX0kSwDMw6ya5h6EwyFmQUae1qZ8obAEPqALnmjn-ZE3RROfeAbS_lYqTe_J3CBCd1ESXjXWseJHjPvfhYGq07KbFOIqNSCP_gIV9OrI6FEpgFKV3bxAxoYiRKUBluYQBiVAtPXo5hG5DXr7_0eHmNxi9dibjaf7hXqhdc3AhktAo3zYXZfHFRcrsWf82rQmEKupeiG82kd0z6p04ONa-zT9ek7qAhNOzG9H7nvPjVeDZ6bwxyx0-bHhH7LIqEsjoGLWy3HC1ciCvVHA-StD_uA3-okmu6TY6gbVOc5wRQ8zRhfDTOjfk
```

Reply body (exact bytes):

```json
{"v":1,"rq":"yR1uZeiOV1x-Q9d78x3EG-iSHIYXlaxM095uVX8Onew","ok":true,"lvl":3,"w":"qHWf","grant":"plan","place":"other","plan":{"h":"aQflz4JdVBW_hQrHlC9GlH0JOhJ1PSVy7VSUObEo7dE","nb":1795258800000,"sig":"soxtcXs3OryVYZZkhu4ZFTh1HDa4YqluWh4vKEnoobxFTUwiikhr7yEQVbxsQwqrsBxjAC8Au-AVE2Q6N9LADw"},"keys":[{"p":"secrets","i":"0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f","k":"Vnf7GRsE154BBQuSvXKQGQ"},{"p":"volume","i":"fa5a93d5-28d9-4c08-b608-c2b6f344b4d8","k":"Hl31XW79j8muie4UNL2b-g"}]}
```

Sealed reply (783 characters):

```text
bCPTCAyDny7lBfAus8xBlNL9nP75XyKxaLF6B2ITW0UuXD141Ko5av6SsOwBkFbhwYFsfvS7mOdXAlseoKnyD37RzBQfcwInlJHEveRnkPoyTAQATdd6jOUeLqAn-8q7oEJQ8QojoAxdn-iGgZ_28vhEMB7QwBsfAeH9bqfz1NIdsqw0VK72-2-ZqKow2-84oflZU2Tq2zmT8JwUe_61UOU_ub8rdzgbRnuu50ZMtuSNBNQu253cxtY2CG-xgoe0BkMdrc8uk0cR4Cn4ZCWv3wPql84M6AZLvj9Qu7VE0X3ZS9_0QNrvkPNly2s1Ob8ii_pP5liEM_2eppcOf7gXKSzX_MyiOsdbbVb5vOJg-NUpRhpkC9FXtUyiozt2e-pMO_V1wqZBVhjpnIlvQsf8muJiLwp7QXOSGjwKfj9EjGUyM-xK6Zb_0QNgOy--NC2FK_doySU-_LSZpY5OhVVNTVTV9qeCujKoTNoAlddcqVQsDyanTmO-4CiyqX-h5QyYR40M57GAiz23mFSRPtCTbcxgaNLnUAUcg8TXxupXP30cA77LsSeESX77kJlX-ecdaPq3MRzFh6OjViY3_VhSvVs8umaip7otFYfXjVNi1zxMyOMNXpQjTEzuuRfzSL_Ia4RAI1nz_DpU0t6ntBTQQVXa6uzpgG9sU6klWNd_5jYAmVUTxSvEWPtidPftQdp4ZmRNTixdx51XN231wg3JjnltflkFFXzKxNBiEsBHV-xRBZwSqeQiIy_gERlC-IHpxb2_5-W8LUOZUms
```

## Appendix B: how the vectors were computed

The vectors come from one Node.js script with no dependencies (Node 20 or later; run here with Node 24.22.1). It uses Node's `crypto` for SHA-256, HMAC, PBKDF2, Ed25519, X25519 and ChaCha20-Poly1305, and implements HKDF and HPKE in a few lines on top. Before computing anything it checks its HKDF against Node's `hkdfSync` and its HPKE against RFC 9180 Appendix A.2.1 (the ChaCha20Poly1305 suite, sequence 0, and its exported values, which the number match uses). It checks the word list's SHA-256 against the published BIP39 English list, and every signature it makes is verified again. The relay signing vectors were also checked with WebCrypto (`crypto.subtle.verify` with Ed25519), as the relay verifies them.

Commands used:

```sh
# the BIP39 English list (any copy; this one came from the bip39 crate's source)
grep -o '"[a-z]*"' ~/.cargo/registry/src/*/bip39-2.2.2/src/language/english.rs | tr -d '"' > english.txt
shasum -a 256 english.txt   # 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda
node docs/vectors/generate.mjs english.txt   # prints every value; writes docs/vectors/v1.json and relay-signing.json
```

The script, committed as `docs/vectors/generate.mjs` (it writes `v1.json` next to itself):

```js
// Reproduces every test vector in docs/protocol.md.
// Usage: node vectors.mjs <path to BIP39 english.txt>   (Node 20+, no dependencies)
import crypto from "node:crypto";
import fs from "node:fs";

const H = (b) => Buffer.from(b).toString("hex");
const B = (s) => Buffer.from(s, "hex");
const U = (s) => Buffer.from(s, "utf8");
const b64u = (b) => Buffer.from(b).toString("base64url");
const cat = (...xs) => Buffer.concat(xs.map((x) => Buffer.from(x)));
const sha256 = (b) => crypto.createHash("sha256").update(b).digest();
const Z = Buffer.from([0]);
const out = {};
const put = (k, v) => { out[k] = v; console.log(`${k}: ${v}`); };

// ---------- primitives ----------
const hmac = (key, msg) => crypto.createHmac("sha256", key).update(msg).digest();
const hkdfExtract = (salt, ikm) => hmac(salt.length ? salt : Buffer.alloc(32), ikm);
function hkdfExpand(prk, info, L) {
  let t = Buffer.alloc(0), okm = Buffer.alloc(0);
  for (let i = 1; okm.length < L; i++) { t = hmac(prk, cat(t, info, [i])); okm = cat(okm, t); }
  return okm.subarray(0, L);
}
const hkdf = (ikm, info, L, salt = Buffer.alloc(0)) => hkdfExpand(hkdfExtract(salt, ikm), info, L);
// cross-check the hand-written HKDF against node's own
{
  const a = hkdf(U("ikm"), U("info"), 42), b = Buffer.from(crypto.hkdfSync("sha256", U("ikm"), Buffer.alloc(0), U("info"), 42));
  if (!a.equals(b)) throw new Error("hkdf mismatch");
}
const ED_PKCS8 = B("302e020100300506032b657004220420"), ED_SPKI = B("302a300506032b6570032100");
const X_PKCS8 = B("302e020100300506032b656e04220420"), X_SPKI = B("302a300506032b656e032100");
const edPriv = (seed) => crypto.createPrivateKey({ key: cat(ED_PKCS8, seed), format: "der", type: "pkcs8" });
const edPub = (seed) => Buffer.from(crypto.createPublicKey(edPriv(seed)).export({ format: "jwk" }).x, "base64url");
const edSign = (seed, msg) => crypto.sign(null, msg, edPriv(seed));
const edVerify = (pub, msg, sig) => crypto.verify(null, msg, crypto.createPublicKey({ key: cat(ED_SPKI, pub), format: "der", type: "spki" }), sig);
const xPriv = (sk) => crypto.createPrivateKey({ key: cat(X_PKCS8, sk), format: "der", type: "pkcs8" });
const xPub = (sk) => Buffer.from(crypto.createPublicKey(xPriv(sk)).export({ format: "jwk" }).x, "base64url");
const xDH = (sk, pk) => crypto.diffieHellman({ privateKey: xPriv(sk), publicKey: crypto.createPublicKey({ key: cat(X_SPKI, pk), format: "der", type: "spki" }) });
function chachaSeal(key, nonce, aad, pt) {
  const c = crypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c.setAAD(aad, { plaintextLength: pt.length });
  return cat(c.update(pt), c.final(), c.getAuthTag());
}
function chachaOpen(key, nonce, aad, ct) {
  const d = crypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  d.setAAD(aad, { plaintextLength: ct.length - 16 });
  d.setAuthTag(ct.subarray(ct.length - 16));
  return cat(d.update(ct.subarray(0, ct.length - 16)), d.final());
}

// ---------- HPKE (RFC 9180), base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 ----------
const i2osp = (n, w) => { const b = Buffer.alloc(w); b.writeUIntBE(n, 0, w); return b; };
const KEM_ID = cat(U("KEM"), i2osp(0x20, 2));
const HPKE_ID = cat(U("HPKE"), i2osp(0x20, 2), i2osp(1, 2), i2osp(3, 2));
const lExtract = (sid, salt, label, ikm) => hkdfExtract(salt, cat(U("HPKE-v1"), sid, U(label), ikm));
const lExpand = (sid, prk, label, info, L) => hkdfExpand(prk, cat(i2osp(L, 2), U("HPKE-v1"), sid, U(label), info), L);
const deriveKeyPair = (ikm) => { const sk = lExpand(KEM_ID, lExtract(KEM_ID, Buffer.alloc(0), "dkp_prk", ikm), "sk", Buffer.alloc(0), 32); return { sk, pk: xPub(sk) }; };
const eae = (dh, ctx) => lExpand(KEM_ID, lExtract(KEM_ID, Buffer.alloc(0), "eae_prk", dh), "shared_secret", ctx, 32);
function keySchedule(ss, info) {
  const pskId = lExtract(HPKE_ID, Buffer.alloc(0), "psk_id_hash", Buffer.alloc(0));
  const infoHash = lExtract(HPKE_ID, Buffer.alloc(0), "info_hash", info);
  const ksc = cat([0], pskId, infoHash);
  const secret = lExtract(HPKE_ID, ss, "secret", Buffer.alloc(0));
  return {
    key: lExpand(HPKE_ID, secret, "key", ksc, 32), nonce: lExpand(HPKE_ID, secret, "base_nonce", ksc, 12),
    exp: lExpand(HPKE_ID, secret, "exp", ksc, 32),
  };
}
// RFC 9180 section 5.3, secret export from a context
const hpkeExport = (exp, ctx, L) => lExpand(HPKE_ID, exp, "sec", ctx, L);
function hpkeSeal(pkR, info, aad, pt, ikmE) {
  const e = deriveKeyPair(ikmE); // fixed ephemeral for test vectors only; real senders use GenerateKeyPair
  const ss = eae(xDH(e.sk, pkR), cat(e.pk, pkR));
  const { key, nonce, exp } = keySchedule(ss, info);
  return { enc: e.pk, ct: chachaSeal(key, nonce, aad, pt), ss, exp };
}
function hpkeOpen(skR, info, aad, enc, ct) {
  const ss = eae(xDH(skR, enc), cat(enc, xPub(skR)));
  const { key, nonce } = keySchedule(ss, info);
  return chachaOpen(key, nonce, aad, ct);
}
function hpkeOpenExport(skR, info, enc) {
  return keySchedule(eae(xDH(skR, enc), cat(enc, xPub(skR))), info).exp;
}
// RFC 9180 A.2.1 check
{
  const info = B("4f6465206f6e2061204772656369616e2055726e");
  const r = deriveKeyPair(B("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df"));
  if (H(r.sk) !== "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb") throw new Error("A.2.1 skRm");
  const s = hpkeSeal(r.pk, info, B("436f756e742d30"), B("4265617574792069732074727574682c20747275746820626561757479"),
    B("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"));
  if (H(s.enc) !== "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a") throw new Error("A.2.1 enc");
  if (H(s.ss) !== "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7") throw new Error("A.2.1 shared_secret");
  if (H(s.ct) !== "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28") throw new Error("A.2.1 ct");
  if (H(s.exp) !== "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922") throw new Error("A.2.1 exporter_secret");
  const exported = [["", "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"],
    ["00", "8c1df14732580e5501b00f82b10a1647b40713191b7c1240ac80e2b68808ba69"],
    ["54657374436f6e74657874", "5acb09211139c43b3090489a9da433e8a30ee7188ba8b0a9a1ccf0c229283e53"]];
  for (const [ctx, want] of exported) if (H(hpkeExport(s.exp, B(ctx), 32)) !== want) throw new Error("A.2.1 export " + ctx);
  console.log("RFC 9180 A.2.1 sequence 0 and exported values: OK");
}

// ---------- BIP39 ----------
const WORDS = fs.readFileSync(process.argv[2], "utf8").trim().split("\n");
if (WORDS.length !== 2048 || H(sha256(U(WORDS.join("\n") + "\n"))) !== "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda") throw new Error("wordlist");
function mnemonicFromEntropy(ent) {
  const bits = [...cat(ent, sha256(ent).subarray(0, 1))].map((x) => x.toString(2).padStart(8, "0")).join("");
  const w = [];
  for (let i = 0; i < 24; i++) w.push(WORDS[parseInt(bits.slice(i * 11, i * 11 + 11), 2)]);
  return w.join(" ");
}
const seedOf = (m) => crypto.pbkdf2Sync(U(m.normalize("NFKD")), U("mnemonic"), 2048, 64, "sha512");

// ---------- sealctl derivation ----------
const rootOf = (seed) => hkdf(seed, U("sealctl/v1/root"), 32);
const derive = (root, label, L) => hkdf(root, U("sealctl/v1/" + label), L);
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function fingerprint(root) {
  let n = derive(root, "fingerprint", 8).readBigUInt64BE(0) % (58n ** 4n);
  let s = "";
  for (let i = 0; i < 4; i++) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  return s;
}
const check = (key) => b64u(hkdf(key, U("sealctl/v1/check"), 8));
const CROCK = "0123456789abcdefghjkmnpqrstvwxyz";
function tag(machinePub) {
  const h = sha256(cat(U("sealctl/v1/tag"), Z, machinePub));
  const v = (h[0] << 12) | (h[1] << 4) | (h[2] >> 4); // first 20 bits
  return [15, 10, 5, 0].map((s) => CROCK[(v >> s) & 31]).join("");
}
const uuidBytes = (u) => B(u.replace(/-/g, ""));

function phoneKeys(root) {
  const idSeed = derive(root, "phone:identity", 32);
  const boxSk = derive(root, "phone:box", 32);
  return { idSeed, P: edPub(idSeed), boxSk, BX: xPub(boxSk) };
}

// ---------- vectors ----------
const mA = Array(23).fill("abandon").concat("art").join(" ");
const mB = mnemonicFromEntropy(sha256(U("sealctl test vector B")));
put("A.mnemonic", mA);
put("B.entropy", H(sha256(U("sealctl test vector B"))));
put("B.mnemonic", mB);
const roots = {};
for (const [k, m] of [["A", mA], ["B", mB]]) {
  const seed = seedOf(m), root = rootOf(seed), pk = phoneKeys(root);
  roots[k] = root;
  put(`${k}.seed`, H(seed));
  put(`${k}.root`, H(root));
  put(`${k}.fingerprint`, fingerprint(root));
  put(`${k}.fingerprint_okm`, H(derive(root, "fingerprint", 8)));
  put(`${k}.phone_identity_seed`, H(pk.idSeed));
  put(`${k}.phone_identity_public_b64u`, b64u(pk.P));
  put(`${k}.phone_box_private`, H(pk.boxSk));
  put(`${k}.phone_box_public_b64u`, b64u(pk.BX));
  put(`${k}.state_key`, H(derive(root, "state", 32)));
}
const root = roots.B;
const STORE = "0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f";
const FILE = "3d7e1b9a-2c4f-4a8e-b6d1-5f0e9c2a7b34";
const VOL = "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8";
const REPO = "6c1f0b2e-8d3a-4f7b-a9e4-2b5c7d8e9f01";
const labels = [`secrets:${STORE}`, `secret:${FILE}`, `volume:${VOL}`, `backup:${REPO}`];
const keys = {};
for (const l of labels) {
  const k = derive(root, l, 16);
  keys[l] = k;
  const [pp, ii] = l.split(":");
  put(`B.key ${pp} ${ii}`, H(k));
  put(`B.key_b64u ${pp} ${ii}`, b64u(k));
  put(`B.check ${pp} ${ii}`, check(k));
}

// sealed file (store key, mode 1) and own-approval file (mode 2)
const NAME = "shop/openai-api-key", VALUE = U("test-value-not-a-real-key");
function sealFile(mode, ikmKey, nonce) {
  const fileKey = hkdf(ikmKey, U("sealctl/v1/file:" + FILE), 32);
  const header = cat(U("SCS1"), [mode], U(fingerprint(root)), uuidBytes(FILE), nonce);
  const aad = cat(header, U(STORE), Z, U(NAME));
  const sealed = cat(header, chachaSeal(fileKey, nonce, aad, VALUE));
  if (!chachaOpen(fileKey, nonce, aad, sealed.subarray(37)).equals(VALUE)) throw new Error("sealed roundtrip");
  return { fileKey, sealed };
}
const s1 = sealFile(1, keys[`secrets:${STORE}`], B("000102030405060708090a0b"));
put("B.file_key_mode1", H(s1.fileKey));
put("B.sealed_mode1", H(s1.sealed));
const s2 = sealFile(2, keys[`secret:${FILE}`], B("0c0d0e0f1011121314151617"));
put("B.file_key_mode2", H(s2.fileKey));
put("B.sealed_mode2", H(s2.sealed));

// state blob
{
  const pk = phoneKeys(root);
  const nonce = B("18191a1b1c1d1e1f20212223");
  const pt = U('{"v":1}');
  const aad = cat(U("sealctl/v1/state"), Z, pk.P);
  const blob = cat([1], nonce, chachaSeal(derive(root, "state", 32), nonce, aad, pt));
  put("B.state_blob_b64u", b64u(blob));
}

// machine, pairing link and proof
const mSeed = sha256(U("sealctl test machine"));
const M = edPub(mSeed);
const S = B("000102030405060708090a0b0c0d0e0f");
put("machine.seed", H(mSeed));
put("machine.public_b64u", b64u(M));
put("machine.tag", tag(M));
const MACHINE_ID = "0123456789abcdef0123456789abcdef";
const hint = b64u(sha256(cat(U("sealctl/v1/hint"), Z, U(MACHINE_ID))).subarray(0, 16));
put("machine.hint", hint);
const enc = (s) => encodeURIComponent(s);
const mBoxSk = sha256(U("sealctl test machine box"));
const MX = xPub(mBoxSk);
put("machine.box_private", H(mBoxSk));
put("machine.box_public_b64u", b64u(MX));
const EXPIRES = Date.UTC(2026, 10, 21, 9, 10, 0) / 1000;
const link = `https://sealctl.com/p#v=1&m=${b64u(M)}&x=${b64u(MX)}&s=${b64u(S)}&n=${enc("dev@mbp.example.com")}&o=${enc("macOS 15.2")}&d=${enc("Mac15,3")}&h=${hint}&e=${EXPIRES}`;
put("pair.link", link);
{
  const pk = phoneKeys(root);
  const mac = hmac(S, cat(U("sealctl/v1/pair"), Z, pk.P, pk.BX, M));
  put("pair.hmac", H(mac));
  put("pair.proof", b64u(cat(pk.BX, mac)));
  // move from words A (old) to words B (new)
  const old = phoneKeys(roots.A);
  const msg = cat(U("sealctl/v1/move"), Z, pk.P, pk.BX, M);
  const sig = edSign(old.idSeed, msg);
  if (!edVerify(old.P, msg, sig)) throw new Error("move sig");
  put("move.signature", H(sig));
  put("move.proof", b64u(cat(pk.BX, sig)));
  put("move.proof_length", b64u(cat(pk.BX, sig)).length);
}

// request and reply
{
  const pk = phoneKeys(root);
  const id = b64u(B("303132333435363738393a3b3c3d3e3f"));
  const ot = deriveKeyPair(sha256(U("sealctl test one-time key")));
  const t = Date.UTC(2026, 10, 21, 9, 0, 0);
  put("request.id", id);
  put("request.t", t);
  put("onetime.private", H(ot.sk));
  put("onetime.public_b64u", b64u(ot.pk));
  const body = U(JSON.stringify({
    v: 1, t, why: "open", ot: b64u(ot.pk),
    ctx: {
      agent: "Claude Code", repo: { id: "github.com/acme/shop", name: "acme/shop" }, cmd: "npm test", cwd: "~/src/shop",
      user: "dev@mbp.example.com", subject: { k: "secret", n: NAME }, n: [NAME],
    },
    keys: [{ p: "secrets", i: STORE, w: fingerprint(root), c: check(keys[`secrets:${STORE}`]), o: { k: "store", p: "~/.local/share/sealctl/store/" + STORE, s: 4096 } }],
    uses: [{ a: "Claude Code", r: "github.com/acme/shop", n: [NAME] }],
    work: 0,
  }));
  put("request.body", body.toString("utf8"));
  const reqMsg = cat(U("sealctl/v1/request"), Z, U(id), Z, pk.P, body);
  const reqSig = edSign(mSeed, reqMsg);
  put("request.signature", H(reqSig));
  const aad = cat(U(id), Z, M);
  const r = hpkeSeal(pk.BX, U("sealctl/v1/request"), aad, cat(reqSig, body), sha256(U("sealctl test ephemeral request")));
  const sealedReq = b64u(cat(r.enc, r.ct));
  put("request.enc", H(r.enc));
  put("request.sealed", sealedReq);
  put("request.sealed_length", sealedReq.length);
  // phone side
  const raw = Buffer.from(sealedReq, "base64url");
  const pt = hpkeOpen(pk.boxSk, U("sealctl/v1/request"), aad, raw.subarray(0, 32), raw.subarray(32));
  if (!edVerify(M, cat(U("sealctl/v1/request"), Z, U(id), Z, pk.P, pt.subarray(64)), pt.subarray(0, 64))) throw new Error("req verify");

  const rq = b64u(sha256(body));
  const rbody = U(JSON.stringify({
    v: 1, rq, ok: true, w: fingerprint(root), grant: "session", remember: true,
    place: "trusted", cap: 14400, base: 1800, rate: 120,
    keys: [{ p: "secrets", i: STORE, k: b64u(keys[`secrets:${STORE}`]) }],
  }));
  put("reply.rq", rq);
  put("reply.body", rbody.toString("utf8"));
  const repSig = edSign(pk.idSeed, cat(U("sealctl/v1/reply"), Z, U(id), Z, M, rbody));
  put("reply.signature", H(repSig));
  const rr = hpkeSeal(ot.pk, U("sealctl/v1/reply"), aad, cat(repSig, rbody), sha256(U("sealctl test ephemeral reply")));
  const sealedRep = b64u(cat(rr.enc, rr.ct));
  put("reply.sealed", sealedRep);
  put("reply.sealed_length", sealedRep.length);
  const rraw = Buffer.from(sealedRep, "base64url");
  const rpt = hpkeOpen(ot.sk, U("sealctl/v1/reply"), aad, rraw.subarray(0, 32), rraw.subarray(32));
  if (!edVerify(pk.P, cat(U("sealctl/v1/reply"), Z, U(id), Z, M, rpt.subarray(64)), rpt.subarray(0, 64))) throw new Error("reply verify");
}

// machine status (machine to phone) and machine message (phone to machine)
{
  const pk = phoneKeys(root);
  const t = Date.UTC(2026, 10, 21, 9, 30, 0);
  const sbody = U(JSON.stringify({
    v: 1, t, seq: 1,
    state: { s: "open", left: 13200, stop: Date.UTC(2026, 10, 22, 1, 0, 0), place: "trusted" },
    log: [{ t: Date.UTC(2026, 10, 21, 9, 1, 0), a: "Claude Code", r: "github.com/acme/shop", c: "npm test", n: [NAME], own: false }],
  }));
  put("status.body", sbody.toString("utf8"));
  const ssig = edSign(mSeed, cat(U("sealctl/v1/status"), Z, pk.P, sbody));
  put("status.signature", H(ssig));
  const st = hpkeSeal(pk.BX, U("sealctl/v1/status"), M, cat(ssig, sbody), sha256(U("sealctl test ephemeral status")));
  const sealedSt = b64u(cat(st.enc, st.ct));
  put("status.sealed", sealedSt);
  const sraw = Buffer.from(sealedSt, "base64url");
  const spt = hpkeOpen(pk.boxSk, U("sealctl/v1/status"), M, sraw.subarray(0, 32), sraw.subarray(32));
  if (!edVerify(M, cat(U("sealctl/v1/status"), Z, pk.P, spt.subarray(64)), spt.subarray(0, 64))) throw new Error("status verify");

  const mbody = U(JSON.stringify({ v: 1, t: Date.UTC(2026, 10, 21, 13, 0, 0), seq: 1, type: "lock", reason: "place" }));
  put("message.body", mbody.toString("utf8"));
  const msig = edSign(pk.idSeed, cat(U("sealctl/v1/message"), Z, M, mbody));
  put("message.signature", H(msig));
  const mm = hpkeSeal(MX, U("sealctl/v1/message"), M, cat(msig, mbody), sha256(U("sealctl test ephemeral message")));
  const sealedMsg = b64u(cat(mm.enc, mm.ct));
  put("message.sealed", sealedMsg);
  const mraw = Buffer.from(sealedMsg, "base64url");
  const mpt = hpkeOpen(mBoxSk, U("sealctl/v1/message"), M, mraw.subarray(0, 32), mraw.subarray(32));
  if (!edVerify(pk.P, cat(U("sealctl/v1/message"), Z, M, mpt.subarray(64)), mpt.subarray(0, 64))) throw new Error("message verify");
}

// unseal --all: level 3 request with number match, plan hash, plan signature (machine above, phone B)
{
  const pk = phoneKeys(root);
  const id = b64u(B("404142434445464748494a4b4c4d4e4f"));
  const ot = deriveKeyPair(sha256(U("sealctl test one-time key unseal")));
  const t = Date.UTC(2026, 10, 21, 10, 0, 0);
  put("unseal.request.id", id);
  put("unseal.onetime.public_b64u", b64u(ot.pk));
  const items = [
    { k: "secrets", n: "store", p: "secrets", i: STORE },
    { k: "volume", n: "safe", p: "volume", i: VOL },
    { k: "ssh", n: "ed25519", p: "secrets", i: STORE },
    { k: "git", n: "signing" },
    { k: "ai", n: "Claude Code" },
    { k: "services", n: "daemon" },
    { k: "local", n: "~/.config/sealctl" },
    { k: "pairing", n: "dev@mbp.example.com" },
  ];
  for (const it of items) for (const f of [it.k, it.n, it.p ?? "", it.i ?? ""]) if (/[\x00-\x1f\x7f]/.test(f)) throw new Error("plan field");
  const planText = "sealctl-plan-v1\n" + b64u(M) + "\n" + items.map((it) => `${it.k}\t${it.n}\t${it.p ?? ""}\t${it.i ?? ""}\n`).join("");
  const ph = sha256(U(planText));
  put("plan.text", JSON.stringify(planText));
  put("plan.hash_b64u", b64u(ph));
  const body = U(JSON.stringify({
    v: 1, t, why: "unseal", lvl: 3, ot: b64u(ot.pk), match: true,
    ctx: { agent: null, repo: null, cmd: "sealctl unseal --all", cwd: "~", user: "dev@mbp.example.com", subject: { k: "machine", n: "unseal" } },
    plan: { all: true, h: b64u(ph), items },
    keys: [
      { p: "secrets", i: STORE, w: fingerprint(root), c: check(keys[`secrets:${STORE}`]), o: { k: "store", p: "~/.local/share/sealctl/store/" + STORE, s: 4096 } },
      { p: "volume", i: VOL, w: fingerprint(root), c: check(keys[`volume:${VOL}`]), o: { k: "volume", p: "/Volumes/safe", s: 53687091200 } },
    ],
  }));
  put("unseal.request.body", body.toString("utf8"));
  const reqSig = edSign(mSeed, cat(U("sealctl/v1/request"), Z, U(id), Z, pk.P, body));
  put("unseal.request.signature", H(reqSig));
  const aad = cat(U(id), Z, M);
  const r = hpkeSeal(pk.BX, U("sealctl/v1/request"), aad, cat(reqSig, body), sha256(U("sealctl test ephemeral unseal")));
  const sealedReq = b64u(cat(r.enc, r.ct));
  put("unseal.request.enc", H(r.enc));
  put("unseal.request.sealed", sealedReq);
  put("unseal.request.sealed_length", sealedReq.length);
  // number match: both ends export the same 4 bytes from the request's HPKE context
  const x = hpkeExport(r.exp, U("sealctl/v1/match"), 4);
  if (!hpkeExport(hpkeOpenExport(pk.boxSk, U("sealctl/v1/request"), r.enc), U("sealctl/v1/match"), 4).equals(x)) throw new Error("match export");
  put("match.export", H(x));
  put("match.number", 10 + (x.readUInt32BE(0) % 90));
  // plan signature: approved away from a trusted place, so not before t + 1 h
  const nb = t + 3600000;
  const nbBytes = Buffer.alloc(8); nbBytes.writeBigUInt64BE(BigInt(nb));
  const planMsg = cat(U("sealctl/v1/plan"), Z, U(id), Z, M, ph, nbBytes);
  const psig = edSign(pk.idSeed, planMsg);
  if (!edVerify(pk.P, planMsg, psig)) throw new Error("plan sig");
  put("plan.not_before", nb);
  put("plan.message_hex", H(planMsg));
  put("plan.signature", H(psig));
  const rbody = U(JSON.stringify({
    v: 1, rq: b64u(sha256(body)), ok: true, lvl: 3, w: fingerprint(root), grant: "plan", place: "other",
    plan: { h: b64u(ph), nb, sig: b64u(psig) },
    keys: [{ p: "secrets", i: STORE, k: b64u(keys[`secrets:${STORE}`]) }, { p: "volume", i: VOL, k: b64u(keys[`volume:${VOL}`]) }],
  }));
  put("unseal.reply.body", rbody.toString("utf8"));
  const repSig = edSign(pk.idSeed, cat(U("sealctl/v1/reply"), Z, U(id), Z, M, rbody));
  put("unseal.reply.signature", H(repSig));
  const rr = hpkeSeal(ot.pk, U("sealctl/v1/reply"), aad, cat(repSig, rbody), sha256(U("sealctl test ephemeral unseal reply")));
  const sealedRep = b64u(cat(rr.enc, rr.ct));
  put("unseal.reply.sealed", sealedRep);
  put("unseal.reply.sealed_length", sealedRep.length);
  const rraw = Buffer.from(sealedRep, "base64url");
  const rpt = hpkeOpen(ot.sk, U("sealctl/v1/reply"), aad, rraw.subarray(0, 32), rraw.subarray(32));
  if (!edVerify(pk.P, cat(U("sealctl/v1/reply"), Z, U(id), Z, M, rpt.subarray(64)), rpt.subarray(0, 64))) throw new Error("unseal reply verify");
}

// root backup item (iCloud Keychain / Block Store), words B
{
  const ent = sha256(U("sealctl test vector B"));
  const created = Buffer.alloc(8); created.writeBigUInt64BE(BigInt(Date.UTC(2026, 10, 21, 9, 0, 0)));
  put("backup_item", H(cat([1], ent, U(fingerprint(root)), created)));
}

// relay signature (existing Relay API scheme), machine signing a licence read
{
  const pk = phoneKeys(root);
  const time = String(Date.UTC(2026, 10, 21, 9, 0, 0) / 1000);
  const canonical = `sealctl-relay-v1\nGET\n/v1/phones/${b64u(pk.P)}/licence\n${time}\n${b64u(sha256(Buffer.alloc(0)))}`;
  put("relay.canonical", JSON.stringify(canonical));
  put("relay.signature", b64u(edSign(mSeed, U(canonical))));
}

// relay-signing.json: request signing for the Relay API (shared with the relay's tests)
{
  const phone = phoneKeys(root), oldPhone = phoneKeys(roots.A);
  const P = b64u(phone.P), Mid = b64u(M), time = "1795251600";
  const sign = (seed, method, path, body) => {
    const bodyHash = b64u(sha256(U(body)));
    const canonical = `sealctl-relay-v1\n${method}\n${path}\n${time}\n${bodyHash}`;
    return { method, path, time, body, bodyHash, canonical, key: b64u(edPub(seed)), signature: b64u(edSign(seed, U(canonical))) };
  };
  const pairBody = JSON.stringify({ machine: Mid, name: "dev@mbp.example.com", os: "macOS 15.2", model: "Mac15,3", proof: out["pair.proof"] });
  const moveMsg = `sealctl-licence-move-v1\n${b64u(oldPhone.P)}\n${P}`;
  const relay = {
    scheme: "sealctl-relay-v1",
    note: "Ed25519 seeds are test keys derived from the test words in docs/protocol.md Appendix A. Signatures are deterministic (RFC 8032).",
    keys: {
      machine: { seed: H(mSeed), public: Mid },
      phone: { seed: H(phone.idSeed), public: P, words: "B" },
      oldPhone: { seed: H(oldPhone.idSeed), public: b64u(oldPhone.P), words: "A" },
    },
    vectors: [
      { name: "machine reads the licence", signer: "machine", ...sign(mSeed, "GET", `/v1/phones/${P}/licence`, "") },
      { name: "machine opens a wait socket", signer: "machine", ...sign(mSeed, "GET", `/v1/phones/${P}/wait`, "") },
      { name: "machine looks itself up", signer: "machine", ...sign(mSeed, "GET", `/v1/machines/${Mid}`, "") },
      { name: "phone registers a machine", signer: "phone", ...sign(phone.idSeed, "POST", `/v1/phones/${P}/machines`, pairBody) },
      { name: "phone lists requests with a query", signer: "phone", ...sign(phone.idSeed, "GET", `/v1/phones/${P}/requests?limit=10`, "") },
      { name: "machine unpairs itself", signer: "machine", ...sign(mSeed, "DELETE", `/v1/phones/${P}/machines/${Mid}`, "") },
    ],
    licenceMove: { old: b64u(oldPhone.P), new: P, message: moveMsg, proof: b64u(edSign(phone.idSeed, U(moveMsg))) },
  };
  for (const v of relay.vectors) if (!edVerify(Buffer.from(v.key, "base64url"), U(v.canonical), Buffer.from(v.signature, "base64url"))) throw new Error("relay vector");
  fs.writeFileSync(new URL("./relay-signing.json", import.meta.url), JSON.stringify(relay, null, 2) + "\n");
}

fs.writeFileSync(new URL("./v1.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
```
