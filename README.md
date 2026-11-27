# sealed-token-auth

A connection-authentication protocol whose server stores only **locked rows**.
At rest, the server cannot read a row, cannot search for a row by token ID,
cannot link connections to users in bulk, and cannot impersonate a user. A row
unlocks **transiently, in memory, for one request only** — and only when the
client that holds the connection's private key answers a fresh, single-use,
server-issued challenge with a valid signature.

TypeScript, ESM, datastore-free: pure functions plus an in-memory,
hash-indexed `Receiver` the host can back with any store (KV, D1, a file, a
database). Runs in Node 20+ and in Cloudflare Workers.

```sh
npm install sealed-token-auth
```

## The pieces

All created **on the client** at setup. Nothing in this list is created by the
server.

| Piece | Held by | On the wire |
|---|---|---|
| Ed25519 private key | Client only | **Never sent.** Used to sign per-request proofs and to derive the locking key. |
| Ed25519 public key | Client + server | Sent at registration, stored in the clear. |
| Lookup key | Both | `base64url(SHA-256(publicKey))`. The stable, hash-indexed key the server files the row under. Derived by the server from the public key — never trusted from the wire. |
| Derived key | Client only | HKDF-SHA256 over the private key. Never sent as a key at registration; per request it is released **sealed** (see below). Encrypts the token ID, salt and link fields. |
| Token ID | Client; server stores it encrypted | Sent encrypted at registration and again (freshly encrypted) per request. The server can never search by it. |
| Token secret | Client only | **Never sent in the clear and never stored.** At registration only its salted hash travels; per request it travels AEAD-encrypted under the derived key. |
| Salt | Client; server stores it encrypted | **Travels ONLY at registration, and only encrypted.** Per-request payloads contain no salt in any form — there is no salt field in the request format, and the test suite asserts the salt appears in no encoding anywhere in a serialized request. |

## Registration flow (once)

1. **Client generates everything** — a fresh Ed25519 keypair, a random token
   ID, a random 32-byte token secret, a random 32-byte salt.
2. **Client derives the locking key** — `HKDF-SHA256(privateKey)` with
   protocol domain separation.
3. **Client locks the identifying pieces** — token ID, salt, and link fields
   (e.g. `{ "accountId": "..." }`) are each encrypted with XChaCha20-Poly1305
   under the derived key.
4. **Client hashes the secret** — `SHA-256(secret ‖ salt)`, stored by the
   server as a clear matcher (a one-way value; useless without the salt,
   which the server cannot unlock on its own).
5. **Client sends one registration payload**: public key (clear), lookup key,
   encrypted token ID, encrypted salt, encrypted link fields, secret hash.
6. **Server stores the row exactly as received.** At this moment — and at
   every moment until a live request — the server cannot read, select or use
   the row.

## Per-request flow (every request)

1. **Server issues a challenge** (`receiver.issueChallenge(lookupKey)`): a
   random nonce, an expiry (default 60 s), and a **fresh ephemeral X25519
   keypair** whose private half never leaves the server. Challenges are
   single-use: every authentication attempt, pass or fail, consumes one.
2. **Client answers** with a `RequestPayload` containing:
   - a fresh Ed25519 **signature** over the exact challenge (challenge ID,
     nonce, ephemeral public key, lookup key, expiry);
   - the token ID, AEAD-encrypted under the derived key and bound to this
     challenge ID;
   - the token secret, AEAD-encrypted the same way (**not** in the clear);
   - the derived key **sealed** to the challenge's ephemeral public key
     (X25519 ECDH → HKDF → XChaCha20-Poly1305), so the server gains
     decryption capability only inside this request.
   
   No salt. No clear secret. No reusable proof.
3. **Server looks the row up** by lookup key — one hash-indexed `Map` get,
   never a scan.
4. **Server verifies the signature live, on every request**, against the
   stored public key. The API has no other path: `authenticate()` accepts
   only a payload answering a challenge this server minted, and burns that
   challenge on the attempt. A copied or static proof cannot be replayed —
   against a new challenge its signature does not verify; against the old
   one the challenge no longer exists.
5. **Server unseals the derived key in memory** using the challenge's
   ephemeral private key, then decrypts: the **stored** token ID and salt
   (the salt comes from the registration row — it is never re-sent), the
   presented token ID, and the presented secret.
6. **Server checks everything**: presented token ID equals the stored token
   ID (constant-time); `SHA-256(presented secret ‖ stored salt)` equals the
   registration matcher (constant-time).
7. **Only on a full match** does the server decrypt the link fields, in
   memory, for this request, and return them to the host application. The
   derived key, salt and secret buffers are zeroized before the call
   returns. The stored row is unchanged — still just a public key, three
   blobs, and a hash.

## Integrator quickstart

### Sender

```ts
import { SenderClient } from 'sealed-token-auth';

// Once, at connection setup. Store exportState() like a password —
// it contains the private key, the token secret and the salt.
const client = SenderClient.generate();
const clientState = client.exportState();

// Registration: send this payload to the server once.
const registration = client.createRegistration({ accountId: 'user-123' });

// Per request: the server first gives you a challenge…
const requestPayload = client.createRequest(challengeFromServer);
// …send requestPayload with your request.
```

### Receiver

```ts
import { Receiver } from 'sealed-token-auth';

const receiver = new Receiver({ challengeTtlMs: 60_000 });

// Registration endpoint:
receiver.register(registrationPayloadFromClient);

// Challenge endpoint (before each authenticated request):
const challenge = receiver.issueChallenge(lookupKey);

// Authenticated endpoint — throws AuthError with a machine-readable .code
// on any failure; on success you get the link fields for this request only.
const { tokenId, linkFields } = receiver.authenticate(requestPayload);
```

Back the receiver with your own store by persisting `receiver.exportState()`
and rebuilding with `Receiver.fromState(state)` — rows plus any still-live
challenges. (Pending challenges contain their ephemeral secret keys; store
them only somewhere as trustworthy as the server's own memory, and only for
the challenge TTL.)

### CLI

```sh
sealed-token-auth sender generate --out client.json
sealed-token-auth sender encrypt --state client.json --link-id user-123 --out registration.json
sealed-token-auth receiver register --store store.json --registration registration.json
sealed-token-auth receiver challenge --store store.json --lookup-key <lookupKey> --out challenge.json
sealed-token-auth sender encrypt-request --state client.json --challenge challenge.json --out request.json
sealed-token-auth receiver verify --store store.json --request request.json
```

## Security guarantees

- **Server at rest learns nothing.** Stored rows contain no readable token
  ID, salt, secret, or link field, in any encoding (asserted by tests).
- **Server cannot select a row by token ID**, enumerate who is who, or match
  the table up on its own — token IDs exist only inside blobs it cannot open.
- **Server cannot impersonate a user.** Doing so would require the private
  key (never sent), the derived key (released only sealed to a live
  challenge's ephemeral key, and only by the client itself), or the token
  secret (never stored, never sent in the clear).
- **No replay.** Challenges are random, bound to one connection, expire in
  60 s by default, and are consumed by any attempt. Presented blobs are
  AEAD-bound to the challenge ID, so they cannot be transplanted to another
  request either.
- **No proof without live verification.** There is no API surface that
  accepts a proof on trust — no cached "verified" flag, no skip parameter.
- **The hash matcher is inert at rest.** Without the salt — locked in a blob
  the server cannot open alone — the stored `SHA-256(secret ‖ salt)` cannot
  be reproduced or brute-forced (the secret is a random 32 bytes regardless).

## Honest limitations

- **During a live, verified request the server necessarily learns** the
  token ID, the presented secret, and the link fields, in memory. That is
  the design's purpose (the server must end up knowing who is calling). The
  guarantee is about what the server can do *on its own, at rest, and in
  bulk* — not about hiding the caller's identity from the server mid-call.
- **Zeroization is best-effort.** Buffers this library controls are wiped
  after use, but JavaScript runtimes may copy immutable strings and the GC
  may retain freed memory. Do not treat wiping as a hard memory-forensics
  boundary.
- **The host owns transport and storage security.** This package does not
  provide TLS, rate limiting, or access control for the registration /
  challenge / authenticate endpoints. Challenge issuance reveals that a
  lookup key is registered to whoever already knows that lookup key (a hash
  of a public key).
- **Client state is a single point of compromise by design.** Whoever holds
  `exportState()` output holds the connection. Store it like a password.
- **No forward secrecy for stored rows.** The derived key is stable per
  connection (it must be, so stored blobs stay openable). If a client state
  leaks, rotate the connection: generate a new one and re-register.
- The lookup key is a hash of the public key, so the server *can* find the
  row for a connection whose public key it is given — that is the intended
  quick lookup. What it cannot do is start from a token ID, an account ID, or
  the table itself.

## Motivation and design philosophy

Most connection-auth schemes make the server the trusted party: it holds the
credentials, so it can read every connection, search them, link them, and —
if it is compromised or simply curious — impersonate any of them. This
protocol starts from the opposite premise: **the server should be unable to
cheat, not merely trusted not to.** Everything below follows from that one
decision.

- **The server is a locked filing cabinet.** It stores rows it cannot read,
  cannot search by token ID, and cannot link to users in bulk. The only thing
  it holds in the clear is each connection's public key.
- **Decryption capability is a per-request grant, never a server property.**
  A signature alone cannot decrypt anything, so the client grants capability
  explicitly, one request at a time: having decided to make a request, the
  client seals the derived key to the challenge's one-time ephemeral X25519
  public key. The release is bound to that challenge (nonce as HKDF salt,
  challenge ID in the AEAD associated data) and is useless for any other.
- **Verification comes before decryption.** `authenticate()` verifies the
  Ed25519 signature *before* unsealing anything, so capability exists only
  transiently, in memory, during a live verified request — never at rest,
  never on the server's own initiative.
- **Secrets travel sealed or not at all.** The token secret is never sent in
  the clear and never stored: a salted hash at registration, an
  AEAD-encrypted copy per request. The salt is a registration-time input,
  delivered once, sealed with the rest of the row.
- **The client is the only place identity exists.** Registration material is
  generated on the client; the server receives a public key in the clear and
  everything else as ciphertext. What the server never holds, it cannot
  leak, sell, or be made to reveal.

## Crypto choices & dependencies

All cryptography comes from Paul Miller's audited `@noble/*` packages —
proven primitives, no hand-rolled crypto, no native code, identical behavior
in Node and Workers.

| Dependency | Version | License | Used for | Limits / cost |
|---|---|---|---|---|
| `@noble/curves` | ^2.4.0 | MIT | Ed25519 sign/verify, X25519 ECDH | Free, open source, no quotas. Pure JS: slower than native (irrelevant at one handshake per request). |
| `@noble/hashes` | ^2.4.0 | MIT | SHA-256, HKDF-SHA256 | Free, open source, no quotas. |
| `@noble/ciphers` | ^2.4.0 | MIT | XChaCha20-Poly1305 AEAD | Free, open source, no quotas. |

Dev-only: `typescript`, `tsx`, `@types/node` (all MIT / Apache-2.0 for
`@types/node`'s underlying definitions) — not shipped to consumers.

Algorithm summary: Ed25519 (signatures) · X25519 (ephemeral ECDH key
release) · HKDF-SHA256 (derived key + wrapping key) · XChaCha20-Poly1305
(all blobs) · SHA-256 (lookup key, secret matcher). Wire encodings are
base64url throughout.

## Development

```sh
npm install
npm run build   # tsc → dist/
npm test        # node:test via tsx — 13 tests
```

Tests cover: end-to-end happy path; wrong secret; a copied proof replayed
against a new challenge; exact replay of a consumed request; a forged
challenge ID; **the salt appearing nowhere in a per-request payload, in any
encoding**; the salt travelling only (encrypted) at registration; a tampered
encrypted token ID; an expired challenge; a failed attempt burning its
challenge; at-rest opacity of stored rows; receiver state round-trip
through a host-backed store; duplicate registration.

## License

MIT — see [LICENSE](./LICENSE).
