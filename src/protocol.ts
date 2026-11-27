/**
 * Wire formats and shared protocol constants for sealed-token-auth v1.
 *
 * Design summary (see README for the full story):
 * - Registration (once): the client sends its Ed25519 public key, the token ID,
 *   salt and link fields each AEAD-encrypted under a client-derived key, and
 *   SHA-256(secret || salt) as a clear matcher. THE SALT TRAVELS ONLY HERE.
 * - Per request: the client sends a fresh Ed25519 signature over a
 *   server-issued, single-use, expiring challenge; the token ID and the token
 *   secret each AEAD-encrypted under the derived key; and the derived key
 *   itself sealed to the challenge's ephemeral X25519 public key. Per-request
 *   payloads NEVER contain the salt, in any form.
 */
import { utf8 } from './crypto.js';

export const PROTOCOL_VERSION = 'sealed-token-auth/v1';

/** HKDF domain separation for the client-derived locking key. */
export const DERIVED_KEY_INFO = utf8('sealed-token-auth/v1/derived-key');
export const DERIVED_KEY_SALT = utf8('sealed-token-auth/v1');

/** HKDF info for the per-request key-release wrapping key. */
export const KEY_RELEASE_INFO = utf8('sealed-token-auth/v1/key-release');

/** Associated-data labels binding each blob to its role (and, per request, to its challenge). */
export const AAD = {
  storedTokenId: utf8('sealed-token-auth/v1/stored/token-id'),
  storedSalt: utf8('sealed-token-auth/v1/stored/salt'),
  storedLink: utf8('sealed-token-auth/v1/stored/link'),
  requestTokenId: (challengeId: string) => utf8(`sealed-token-auth/v1/request/${challengeId}/token-id`),
  requestSecret: (challengeId: string) => utf8(`sealed-token-auth/v1/request/${challengeId}/secret`),
  keyRelease: (challengeId: string, nonce: string) =>
    utf8(`sealed-token-auth/v1/request/${challengeId}/key-release/${nonce}`),
};

/** Canonical bytes the client signs to prove it holds the private key, per request. */
export function challengeMessage(ch: {
  challengeId: string;
  nonce: string;
  ephemeralPublicKey: string;
  lookupKey: string;
  expiresAt: number;
}): Uint8Array {
  return utf8(
    [
      PROTOCOL_VERSION,
      'challenge',
      ch.challengeId,
      ch.nonce,
      ch.ephemeralPublicKey,
      ch.lookupKey,
      String(ch.expiresAt),
    ].join('\n'),
  );
}

/** Sent once, at registration. Contains the ONLY copy of the salt that ever travels (encrypted). */
export interface RegistrationPayload {
  type: 'sealed-token-auth/registration/v1';
  /** Ed25519 public key, base64url. Stored in the clear. */
  publicKey: string;
  /** base64url(SHA-256(publicKey)) — the stable, hash-indexed row lookup key. */
  lookupKey: string;
  /** AEAD blob (derived key) of the token ID. */
  encryptedTokenId: string;
  /** AEAD blob (derived key) of the salt. Sent ONLY at registration, never per request. */
  encryptedSalt: string;
  /** AEAD blob (derived key) of the JSON-serialized link fields (e.g. an account ID). */
  encryptedLink: string;
  /** base64url(SHA-256(secretBytes || saltBytes)) — a matcher, never the secret. */
  secretHash: string;
}

/** Issued by the receiver before each request. Single-use, short-lived. */
export interface Challenge {
  type: 'sealed-token-auth/challenge/v1';
  challengeId: string;
  /** base64url random nonce, also the HKDF salt for the key-release wrapping key. */
  nonce: string;
  /** Ephemeral X25519 public key (base64url) for this challenge only. */
  ephemeralPublicKey: string;
  /** The connection this challenge was issued for. */
  lookupKey: string;
  /** Epoch milliseconds after which this challenge is dead. */
  expiresAt: number;
}

/** Sent with every request. NOTE: no salt field exists in this format, by design. */
export interface RequestPayload {
  type: 'sealed-token-auth/request/v1';
  lookupKey: string;
  challengeId: string;
  /** Ed25519 signature (base64url) over challengeMessage() for the live challenge. */
  signature: string;
  /** Client's ephemeral X25519 public key (base64url) for the key release. */
  clientEphemeralPublicKey: string;
  /** The derived key, AEAD-sealed to the challenge's ephemeral key. Exists only for this request. */
  sealedDerivedKey: string;
  /** AEAD blob (derived key) of the token ID, bound to this challenge. */
  encryptedTokenId: string;
  /** AEAD blob (derived key) of the token secret, bound to this challenge. The secret never travels in the clear. */
  encryptedSecret: string;
}

/** Client-side secret state. NEVER sent anywhere; the salt inside it travels only inside the encrypted registration blob. */
export interface ClientState {
  /** Ed25519 secret key (seed), base64url. */
  privateKey: string;
  tokenId: string;
  /** Token secret, base64url. */
  tokenSecret: string;
  /** Salt, base64url. */
  salt: string;
}

export type AuthErrorCode =
  | 'MALFORMED_PAYLOAD'
  | 'UNKNOWN_CONNECTION'
  | 'ALREADY_REGISTERED'
  | 'CHALLENGE_NOT_FOUND'
  | 'CHALLENGE_MISMATCH'
  | 'CHALLENGE_EXPIRED'
  | 'BAD_SIGNATURE'
  | 'KEY_RELEASE_FAILED'
  | 'DECRYPT_FAILED'
  | 'TOKEN_ID_MISMATCH'
  | 'SECRET_MISMATCH';

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  constructor(code: AuthErrorCode, message?: string) {
    super(message ?? code);
    this.name = 'AuthError';
    this.code = code;
  }
}
