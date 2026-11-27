/**
 * Low-level helpers: encodings, randomness, hashing, HKDF, and an AEAD
 * (XChaCha20-Poly1305) blob format. Pure functions only — no storage, no I/O.
 * Everything here runs identically in Node 20+ and in a Cloudflare Worker.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** base64url (no padding) encode. */
export function b64e(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url decode. Throws on malformed input. */
export function b64d(s: string): Uint8Array {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error('invalid base64url string');
  }
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export const sha256Bytes = (data: Uint8Array): Uint8Array => sha256(data);

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function hkdf32(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array): Uint8Array {
  return hkdf(sha256, ikm, salt, info, 32);
}

/** Constant-time equality for same-length byte strings. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Best-effort wipe of sensitive material. */
export function zeroize(...bufs: Uint8Array[]): void {
  for (const b of bufs) b.fill(0);
}

const NONCE_LEN = 24; // XChaCha20-Poly1305 nonce

/**
 * AEAD-seal `plaintext` under `key` (32 bytes) with optional associated data.
 * Returns a base64url blob: nonce || ciphertext(+tag).
 */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): string {
  const nonce = randomBytes(NONCE_LEN);
  const cipher = xchacha20poly1305(key, nonce, aad);
  const ct = cipher.encrypt(plaintext);
  return b64e(concatBytes(nonce, ct));
}

/** Inverse of seal(). Throws if the blob is malformed or tampered with. */
export function openSealed(key: Uint8Array, blob: string, aad?: Uint8Array): Uint8Array {
  const raw = b64d(blob);
  if (raw.length <= NONCE_LEN) throw new Error('sealed blob too short');
  const nonce = raw.subarray(0, NONCE_LEN);
  const ct = raw.subarray(NONCE_LEN);
  const cipher = xchacha20poly1305(key, nonce, aad);
  return cipher.decrypt(ct);
}
