/**
 * The sender side: one connection's client.
 *
 * A SenderClient holds the connection's private key, token ID, token secret
 * and salt. It produces exactly two kinds of outbound payload:
 *  - a one-time RegistrationPayload (the only payload that ever carries the
 *    salt, and it carries it encrypted), and
 *  - per-request RequestPayloads answering live server challenges (no salt,
 *    no clear secret, a fresh signature every time).
 */
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import {
  AAD,
  DERIVED_KEY_INFO,
  DERIVED_KEY_SALT,
  KEY_RELEASE_INFO,
  challengeMessage,
  type Challenge,
  type ClientState,
  type RegistrationPayload,
  type RequestPayload,
} from './protocol.js';
import {
  b64d,
  b64e,
  concatBytes,
  fromUtf8,
  hkdf32,
  randomBytes,
  seal,
  sha256Bytes,
  utf8,
  zeroize,
} from './crypto.js';

/** Derive the stable lookup key from a public key: base64url(SHA-256(publicKey)). */
export function lookupKeyFor(publicKey: Uint8Array): string {
  return b64e(sha256Bytes(publicKey));
}

/** The salted hash matcher: base64url(SHA-256(secretBytes || saltBytes)). */
export function secretHashFor(secret: Uint8Array, salt: Uint8Array): string {
  return b64e(sha256Bytes(concatBytes(secret, salt)));
}

export class SenderClient {
  readonly #secretKey: Uint8Array;
  readonly #publicKey: Uint8Array;
  readonly #tokenId: string;
  readonly #tokenSecret: Uint8Array;
  readonly #salt: Uint8Array;
  #derivedKeyCache: Uint8Array | undefined;

  private constructor(state: ClientState) {
    this.#secretKey = b64d(state.privateKey);
    this.#publicKey = ed25519.getPublicKey(this.#secretKey);
    this.#tokenId = state.tokenId;
    this.#tokenSecret = b64d(state.tokenSecret);
    this.#salt = b64d(state.salt);
  }

  /** Create a brand-new connection: fresh keypair, token ID, secret and salt — all generated here, on the client. */
  static generate(): SenderClient {
    const { secretKey } = ed25519.keygen();
    return new SenderClient({
      privateKey: b64e(secretKey),
      tokenId: b64e(randomBytes(16)),
      tokenSecret: b64e(randomBytes(32)),
      salt: b64e(randomBytes(32)),
    });
  }

  static fromState(state: ClientState): SenderClient {
    return new SenderClient(state);
  }

  /** Export the client-side secret state (for the client's own storage only — never transmit it). */
  exportState(): ClientState {
    return {
      privateKey: b64e(this.#secretKey),
      tokenId: this.#tokenId,
      tokenSecret: b64e(this.#tokenSecret),
      salt: b64e(this.#salt),
    };
  }

  get publicKey(): string {
    return b64e(this.#publicKey);
  }

  get lookupKey(): string {
    return lookupKeyFor(this.#publicKey);
  }

  get tokenId(): string {
    return this.#tokenId;
  }

  /**
   * The derived locking key: HKDF-SHA256 over the Ed25519 secret key.
   * Producible only by the holder of the private key; never sent as a key at
   * registration — only its encrypted results are.
   */
  derivedKey(): Uint8Array {
    if (!this.#derivedKeyCache) {
      this.#derivedKeyCache = hkdf32(this.#secretKey, DERIVED_KEY_SALT, DERIVED_KEY_INFO);
    }
    return this.#derivedKeyCache;
  }

  /**
   * Build the one-time registration payload. `linkFields` is any
   * JSON-serializable value identifying the user in the host system
   * (e.g. `{ accountId: "..." }`); it is stored only in encrypted form.
   */
  createRegistration(linkFields: unknown): RegistrationPayload {
    const dk = this.derivedKey();
    return {
      type: 'sealed-token-auth/registration/v1',
      publicKey: this.publicKey,
      lookupKey: this.lookupKey,
      encryptedTokenId: seal(dk, utf8(this.#tokenId), AAD.storedTokenId),
      encryptedSalt: seal(dk, this.#salt, AAD.storedSalt),
      encryptedLink: seal(dk, utf8(JSON.stringify(linkFields ?? null)), AAD.storedLink),
      secretHash: secretHashFor(this.#tokenSecret, this.#salt),
    };
  }

  /**
   * Answer a live challenge from the receiver. The result contains:
   * a fresh signature over the challenge, the encrypted token ID, the
   * encrypted token secret, and the derived key sealed to the challenge's
   * ephemeral public key. It contains NO salt, in any encoding.
   */
  createRequest(challenge: Challenge): RequestPayload {
    const dk = this.derivedKey();

    // Fresh proof: sign the exact server-issued challenge.
    const signature = ed25519.sign(challengeMessage(challenge), this.#secretKey);

    // Transient key release: seal the derived key to the challenge's
    // ephemeral X25519 public key, so decryption capability exists only
    // inside this one live, signature-verified request.
    const eph = x25519.keygen();
    const shared = x25519.getSharedSecret(eph.secretKey, b64d(challenge.ephemeralPublicKey));
    const wrapKey = hkdf32(shared, b64d(challenge.nonce), KEY_RELEASE_INFO);
    const sealedDerivedKey = seal(wrapKey, dk, AAD.keyRelease(challenge.challengeId, challenge.nonce));
    zeroize(shared, wrapKey, eph.secretKey);

    return {
      type: 'sealed-token-auth/request/v1',
      lookupKey: this.lookupKey,
      challengeId: challenge.challengeId,
      signature: b64e(signature),
      clientEphemeralPublicKey: b64e(eph.publicKey),
      sealedDerivedKey,
      encryptedTokenId: seal(dk, utf8(this.#tokenId), AAD.requestTokenId(challenge.challengeId)),
      encryptedSecret: seal(dk, this.#tokenSecret, AAD.requestSecret(challenge.challengeId)),
    };
  }
}

export { fromUtf8 };
