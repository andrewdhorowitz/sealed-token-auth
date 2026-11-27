/**
 * The receiver side: stores locked rows and authenticates live requests.
 *
 * Storage model: rows live in a Map keyed by the connection's lookup key
 * (base64url SHA-256 of its public key), so finding the row for a request is
 * one hash-indexed lookup — the receiver NEVER scans rows and CANNOT select a
 * row by token ID (token IDs exist only inside AEAD blobs it cannot open at
 * rest).
 *
 * Authentication model: authenticate() has no "pre-verified" path. Every call
 * requires a live challenge previously minted by issueChallenge() — fresh,
 * unexpired, single-use — and runs the full Ed25519 signature verification
 * against the stored public key on every call. Only after the signature
 * verifies does the receiver unseal the per-request derived key (sealed to
 * the challenge's ephemeral X25519 key) and decrypt anything. The derived
 * key, decrypted salt, decrypted secret and decrypted link fields exist only
 * in local variables for the duration of the call and are zeroized before
 * return.
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import {
  AAD,
  KEY_RELEASE_INFO,
  AuthError,
  challengeMessage,
  type Challenge,
  type RegistrationPayload,
  type RequestPayload,
} from './protocol.js';
import {
  b64d,
  b64e,
  concatBytes,
  fromUtf8,
  hkdf32,
  openSealed,
  randomBytes,
  sha256Bytes,
  timingSafeEqual,
  utf8,
  zeroize,
} from './crypto.js';
import { lookupKeyFor } from './client.js';

export interface StoredRow {
  lookupKey: string;
  publicKey: string;
  encryptedTokenId: string;
  encryptedSalt: string;
  encryptedLink: string;
  secretHash: string;
}

interface StoredChallenge {
  challengeId: string;
  nonce: string;
  ephemeralPublicKey: string;
  /** Server-side only; never leaves the receiver. Zeroized when consumed. */
  ephemeralSecretKey: string;
  lookupKey: string;
  expiresAt: number;
}

export interface ReceiverState {
  rows: StoredRow[];
  challenges: StoredChallenge[];
}

export interface AuthResult {
  lookupKey: string;
  tokenId: string;
  /** The link fields registered by the client (e.g. `{ accountId: "..." }`), decrypted in memory for this request only. */
  linkFields: unknown;
}

export interface ReceiverOptions {
  /** Challenge lifetime in milliseconds. Default 60_000. */
  challengeTtlMs?: number;
  /** Clock override (epoch ms), for tests and host integration. */
  now?: () => number;
}

const DEFAULT_TTL_MS = 60_000;

export class Receiver {
  readonly #rows = new Map<string, StoredRow>();
  readonly #challenges = new Map<string, StoredChallenge>();
  readonly #ttlMs: number;
  readonly #now: () => number;

  constructor(opts: ReceiverOptions = {}) {
    this.#ttlMs = opts.challengeTtlMs ?? DEFAULT_TTL_MS;
    this.#now = opts.now ?? (() => Date.now());
  }

  get rowCount(): number {
    return this.#rows.size;
  }

  has(lookupKey: string): boolean {
    return this.#rows.has(lookupKey);
  }

  /**
   * Store a registration exactly as received: public key and hash matcher in
   * the clear, token ID / salt / link fields as opaque AEAD blobs. The salt
   * arrives ONLY here, inside its blob; nothing in this row lets the receiver
   * read, search or impersonate the connection on its own.
   */
  register(payload: RegistrationPayload): { lookupKey: string } {
    if (
      !payload ||
      payload.type !== 'sealed-token-auth/registration/v1' ||
      typeof payload.publicKey !== 'string' ||
      typeof payload.encryptedTokenId !== 'string' ||
      typeof payload.encryptedSalt !== 'string' ||
      typeof payload.encryptedLink !== 'string' ||
      typeof payload.secretHash !== 'string'
    ) {
      throw new AuthError('MALFORMED_PAYLOAD', 'registration payload is missing required fields');
    }
    let publicKey: Uint8Array;
    try {
      publicKey = b64d(payload.publicKey);
    } catch {
      throw new AuthError('MALFORMED_PAYLOAD', 'publicKey is not valid base64url');
    }
    if (publicKey.length !== 32) {
      throw new AuthError('MALFORMED_PAYLOAD', 'publicKey must be a 32-byte Ed25519 key');
    }
    // The lookup key is derived from the public key, never trusted from the wire.
    const lookupKey = lookupKeyFor(publicKey);
    if (this.#rows.has(lookupKey)) {
      throw new AuthError('ALREADY_REGISTERED', 'a row already exists for this public key');
    }
    this.#rows.set(lookupKey, {
      lookupKey,
      publicKey: payload.publicKey,
      encryptedTokenId: payload.encryptedTokenId,
      encryptedSalt: payload.encryptedSalt,
      encryptedLink: payload.encryptedLink,
      secretHash: payload.secretHash,
    });
    return { lookupKey };
  }

  /**
   * Mint a fresh challenge for one connection. Each challenge carries its own
   * ephemeral X25519 keypair (the private half never leaves the receiver) and
   * expires after the configured TTL. Challenges are single-use.
   */
  issueChallenge(lookupKey: string): Challenge {
    if (!this.#rows.has(lookupKey)) {
      throw new AuthError('UNKNOWN_CONNECTION', 'no registered row for this lookup key');
    }
    this.#sweepExpired();
    const eph = x25519.keygen();
    const stored: StoredChallenge = {
      challengeId: b64e(randomBytes(16)),
      nonce: b64e(randomBytes(32)),
      ephemeralPublicKey: b64e(eph.publicKey),
      ephemeralSecretKey: b64e(eph.secretKey),
      lookupKey,
      expiresAt: this.#now() + this.#ttlMs,
    };
    this.#challenges.set(stored.challengeId, stored);
    return {
      type: 'sealed-token-auth/challenge/v1',
      challengeId: stored.challengeId,
      nonce: stored.nonce,
      ephemeralPublicKey: stored.ephemeralPublicKey,
      lookupKey: stored.lookupKey,
      expiresAt: stored.expiresAt,
    };
  }

  /**
   * Authenticate one live request. There is deliberately no overload, flag or
   * alternate entry point that skips the challenge + signature verification:
   * a copied or static proof cannot be presented to this API at all, because
   * the signature is checked against a challenge this receiver minted, which
   * is consumed (single-use) by the attempt.
   */
  authenticate(payload: RequestPayload): AuthResult {
    if (
      !payload ||
      payload.type !== 'sealed-token-auth/request/v1' ||
      typeof payload.lookupKey !== 'string' ||
      typeof payload.challengeId !== 'string' ||
      typeof payload.signature !== 'string' ||
      typeof payload.clientEphemeralPublicKey !== 'string' ||
      typeof payload.sealedDerivedKey !== 'string' ||
      typeof payload.encryptedTokenId !== 'string' ||
      typeof payload.encryptedSecret !== 'string'
    ) {
      throw new AuthError('MALFORMED_PAYLOAD', 'request payload is missing required fields');
    }

    // 1. One hash-indexed lookup by the stable lookup key. No row scanning.
    const row = this.#rows.get(payload.lookupKey);
    if (!row) throw new AuthError('UNKNOWN_CONNECTION', 'no registered row for this lookup key');

    // 2. The challenge must be live: minted by this receiver, for this
    //    connection, unexpired. It is consumed NOW — every attempt, pass or
    //    fail, burns the challenge, so nothing about a request can be replayed.
    const stored = this.#challenges.get(payload.challengeId);
    if (!stored) throw new AuthError('CHALLENGE_NOT_FOUND', 'unknown or already-consumed challenge');
    this.#challenges.delete(payload.challengeId);
    const ephSecret = b64d(stored.ephemeralSecretKey);
    try {
      if (stored.lookupKey !== payload.lookupKey) {
        throw new AuthError('CHALLENGE_MISMATCH', 'challenge was issued for a different connection');
      }
      if (this.#now() > stored.expiresAt) {
        throw new AuthError('CHALLENGE_EXPIRED', 'challenge has expired');
      }

      // 3. Live signature verification, on EVERY request, against the stored
      //    public key. Nothing is decrypted before this passes.
      let signatureOk = false;
      try {
        signatureOk = ed25519.verify(
          b64d(payload.signature),
          challengeMessage({
            challengeId: stored.challengeId,
            nonce: stored.nonce,
            ephemeralPublicKey: stored.ephemeralPublicKey,
            lookupKey: stored.lookupKey,
            expiresAt: stored.expiresAt,
          }),
          b64d(row.publicKey),
        );
      } catch {
        signatureOk = false;
      }
      if (!signatureOk) throw new AuthError('BAD_SIGNATURE', 'signature does not verify against the stored public key');

      // 4. Transient key release: recover the derived key, sealed by the
      //    client to this challenge's ephemeral key. This is the ONLY moment
      //    decryption capability exists on the receiver.
      let derivedKey: Uint8Array;
      try {
        const shared = x25519.getSharedSecret(ephSecret, b64d(payload.clientEphemeralPublicKey));
        const wrapKey = hkdf32(shared, b64d(stored.nonce), KEY_RELEASE_INFO);
        try {
          derivedKey = openSealed(wrapKey, payload.sealedDerivedKey, AAD.keyRelease(stored.challengeId, stored.nonce));
        } finally {
          zeroize(shared, wrapKey);
        }
      } catch (err) {
        if (err instanceof AuthError) throw err;
        throw new AuthError('KEY_RELEASE_FAILED', 'could not unseal the per-request derived key');
      }

      try {
        // 5. Decrypt, in memory only: the stored token ID and salt (the salt
        //    comes from the stored registration row — it is never sent per
        //    request), the presented token ID, and the presented secret.
        let storedTokenId: string;
        let presentedTokenId: string;
        let salt: Uint8Array;
        let secret: Uint8Array;
        try {
          storedTokenId = fromUtf8(openSealed(derivedKey, row.encryptedTokenId, AAD.storedTokenId));
          salt = openSealed(derivedKey, row.encryptedSalt, AAD.storedSalt);
          presentedTokenId = fromUtf8(
            openSealed(derivedKey, payload.encryptedTokenId, AAD.requestTokenId(stored.challengeId)),
          );
          secret = openSealed(derivedKey, payload.encryptedSecret, AAD.requestSecret(stored.challengeId));
        } catch {
          throw new AuthError('DECRYPT_FAILED', 'a presented or stored blob did not decrypt');
        }

        try {
          // 6. The presented token ID must be the registered token ID.
          if (!timingSafeEqual(utf8(storedTokenId), utf8(presentedTokenId))) {
            throw new AuthError('TOKEN_ID_MISMATCH', 'presented token ID does not match the registered row');
          }

          // 7. Hash the presented secret with the stored salt and compare
          //    against the registration matcher. The secret is checked, never stored.
          const computed = sha256Bytes(concatBytes(secret, salt));
          let expected: Uint8Array;
          try {
            expected = b64d(row.secretHash);
          } catch {
            throw new AuthError('DECRYPT_FAILED', 'stored secret hash is malformed');
          }
          if (!timingSafeEqual(computed, expected)) {
            throw new AuthError('SECRET_MISMATCH', 'presented secret does not match the registered hash');
          }

          // 8. Only now — every check matched — unlock the link fields, in
          //    memory, for this request.
          let linkFields: unknown;
          try {
            linkFields = JSON.parse(fromUtf8(openSealed(derivedKey, row.encryptedLink, AAD.storedLink)));
          } catch {
            throw new AuthError('DECRYPT_FAILED', 'stored link fields did not decrypt');
          }

          return { lookupKey: row.lookupKey, tokenId: storedTokenId, linkFields };
        } finally {
          zeroize(salt, secret);
        }
      } finally {
        zeroize(derivedKey);
      }
    } finally {
      zeroize(ephSecret);
    }
  }

  #sweepExpired(): void {
    const now = this.#now();
    for (const [id, ch] of this.#challenges) {
      if (now > ch.expiresAt) this.#challenges.delete(id);
    }
  }

  /**
   * Serialize rows + pending challenges so a host can back the receiver with
   * any store (KV, D1, a file, ...). NOTE: pending challenges contain their
   * ephemeral secret keys — persist them only somewhere as trustworthy as the
   * receiver's own memory, and only for the challenge TTL.
   */
  exportState(): ReceiverState {
    return {
      rows: [...this.#rows.values()].map((r) => ({ ...r })),
      challenges: [...this.#challenges.values()].map((c) => ({ ...c })),
    };
  }

  static fromState(state: ReceiverState, opts: ReceiverOptions = {}): Receiver {
    const r = new Receiver(opts);
    for (const row of state.rows ?? []) r.#rows.set(row.lookupKey, { ...row });
    const now = r.#now();
    for (const ch of state.challenges ?? []) {
      if (now <= ch.expiresAt) r.#challenges.set(ch.challengeId, { ...ch });
    }
    return r;
  }
}
