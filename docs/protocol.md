# sealctl protocol

This is the wire-level spec for the phone-approved sealctl. The product design lives in the design doc; this file says exactly what goes over the wire and what is stored. Only the relay API is written so far.

## Derivation and test vectors

To be written: the HKDF derivation from the 24 words, every purpose string, the words fingerprint, and test vectors shared by the Rust core, the apps and the relay tests.

## Store format

To be written: the secret store folder, the `.id` file, `.sealed` files and how a file key binds the secret's name.

## Pairing QR code and proof

To be written: what the machine's QR code carries (pairing public key, one-time secret, name, OS, model, hardware hint), and how the phone's proof is computed. The relay stores the proof as an opaque string of up to 128 base64url characters and returns it to the machine, which checks it against its one-time secret.

## Request and reply encryption

To be written: how a request is sealed to the phone, how the reply is sealed with HPKE to the machine's one-time key and signed by the phone. The relay sees only the sealed strings.

## Relay API

The relay carries sealed requests from a machine to its phone and sealed replies back, keeps the phone's encrypted state, counts days with use, and holds the licence. It runs on Cloudflare Workers with one Durable Object per phone. The code is in the private `sealctl/relay` repository; this section is the contract it implements.

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

The relay refuses a call whose time is more than 300 seconds away from its own clock. A replay inside that window can only repeat the same call; calls that change things are safe to repeat or are guarded (state uses compare-and-swap, purchases are deduplicated).

Signature errors are `401` with one of: `unsigned`, `bad_key`, `bad_time`, `clock_skew`, `bad_signature`. Other request errors: `413 too_large` for a body over 1,500,000 bytes, `400 bad_json` for a body that is not JSON.

### Roles and the abuse limit

On every path under `/v1/phones/{phone}`, the signer is either:

- **the phone**, when the signer key is `{phone}`;
- **a machine**, when the signer key is paired with that phone;
- anyone else, who gets `403 forbidden`.

Each endpoint below lists the roles it accepts.

Every authorised call to a phone counts towards its abuse limit, WebSocket upgrades included: `ABUSE_LIMIT_PER_DAY` calls (5,000 by default) per UTC day, the same for paid and unpaid phones. Over the limit the relay answers `429 rate_limited` with `{"retryAfter": <seconds>}` and a `Retry-After` header that both point at the next UTC midnight. Calls refused with `403` do not count, so a stranger cannot use up someone else's limit. The counter is kept in memory and can reset if the phone's object is evicted while idle.

Errors always have the shape `{"error": "<code>", ...}`.

### Endpoints

| Method and path | Who | Body | Success |
| --- | --- | --- | --- |
| `GET /v1/health` | Anyone, unsigned | | `200 {"ok": true}` |
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

Times (`created`, `expires`, `pairedAt`, `since`) are Unix milliseconds.

**Pairing.** The phone registers a machine it scanned. `machine` is the machine's key; `name` is 1 to 200 characters; `os`, `model` and `hint` are up to 200 characters; `proof` is up to 128 base64url characters. Registering a known machine again updates its record and answers `200`. If the machine was paired with another phone, that phone forgets it. The machine polls `GET /v1/machines/{machine}` until it gets `200`, then checks `proof`.

- Errors: `400 bad_machine` (not a key, or the phone's own key), `bad_name`, `bad_os`, `bad_model`, `bad_hint`, `bad_proof`; `409 too_many_machines` past 100 machines; `402 licence_required` with `{"machines", "free"}` when the machine gate is on (below).
- `GET /v1/machines/{machine}`: `404 not_paired` until the phone registers it or after unpairing; `400 bad_machine`; `403 forbidden` for any other signer.
- Unpairing answers `404 not_paired` for an unknown machine, and closes that machine's open waits with the error `unpaired`.

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
| `{"type": "error", "error": "bad_json"}` | The message was not JSON (close code 1007) |
| `{"type": "error", "error": "bad_request"}` | Wrong type, id or sealed (1008) |
| `{"type": "error", "error": "duplicate_id"}` | Another pending request has this id (1008) |
| `{"type": "error", "error": "unpaired"}` | The machine is no longer paired (1008) |
| `{"type": "error", "error": "one_request_per_socket"}` | A second request on the same socket (1008) |

Before the upgrade, the relay can refuse with `426 websocket_required`, `403 forbidden`, `429 rate_limited`, or `429 too_many_pending` when 32 waits are already open for that phone.

The relay has no timer for expiry. It notices an expired request when the phone next lists requests or replies, so the machine should keep its own timer and stop waiting at `expires`.

The phone learns about requests in two ways:

- `GET /v1/phones/{phone}/socket`, signed, with `Upgrade: websocket`: the relay sends `{"type": "request", "id", "machine", "sealed", "created", "expires"}` for each new request. The phone sends nothing on this socket.
- `GET /v1/phones/{phone}/requests` lists the pending ones. Push notifications through APNs and FCM come later.

The phone replies with `POST /v1/phones/{phone}/requests/{id}/reply` and `{"sealed"}` (at most 4,096 characters). Errors: `400 bad_id`, `400 bad_sealed`, `404 gone` when the request expired, was answered, or its machine disconnected. A delivered reply counts the current UTC day as a day with use.

The approval path writes nothing to storage: a pending request lives in its WebSocket's attachment, which Cloudflare keeps through hibernation up to 16,384 bytes. The 4,096-character cap keeps it well inside that. If the machine disconnects, its request is gone and it asks again.

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
