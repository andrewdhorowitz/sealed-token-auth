import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SenderClient } from '../src/client.js';
import { Receiver } from '../src/server.js';
import { AuthError, type RequestPayload } from '../src/protocol.js';
import { b64d, b64e, hexEncode } from '../src/crypto.js';

const LINK = { accountId: 'user-123456' };

function setup() {
  const client = SenderClient.generate();
  const receiver = new Receiver();
  receiver.register(client.createRegistration(LINK));
  return { client, receiver };
}

function liveRequest(client: SenderClient, receiver: Receiver): RequestPayload {
  const challenge = receiver.issueChallenge(client.lookupKey);
  return client.createRequest(challenge);
}

function expectAuthError(fn: () => unknown, codes: string[]): void {
  assert.throws(fn, (err: unknown) => {
    assert.ok(err instanceof AuthError, `expected AuthError, got ${String(err)}`);
    assert.ok(codes.includes(err.code), `expected code in ${codes.join('/')}, got ${err.code}`);
    return true;
  });
}

/** Every string encoding of a byte string we can think of, for leak assertions. */
function encodings(bytes: Uint8Array): string[] {
  return [
    b64e(bytes), // base64url, no padding (the wire encoding)
    Buffer.from(bytes).toString('base64'), // standard base64
    Buffer.from(bytes).toString('base64url'),
    hexEncode(bytes),
    Buffer.from(bytes).toString('latin1'),
  ].filter((s) => s.length >= 8);
}

function deepKeys(value: unknown, acc: string[] = []): string[] {
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      acc.push(k);
      deepKeys(v, acc);
    }
  }
  return acc;
}

test('happy path: register, challenge, request, authenticate end-to-end', () => {
  const { client, receiver } = setup();
  const result = receiver.authenticate(liveRequest(client, receiver));
  assert.equal(result.lookupKey, client.lookupKey);
  assert.equal(result.tokenId, client.tokenId);
  assert.deepEqual(result.linkFields, LINK);
});

test('wrong secret fails with SECRET_MISMATCH', () => {
  const { client, receiver } = setup();
  const state = client.exportState();
  state.tokenSecret = b64e(new Uint8Array(32).fill(7)); // same keypair, wrong secret
  const impostor = SenderClient.fromState(state);
  const challenge = receiver.issueChallenge(client.lookupKey);
  expectAuthError(() => receiver.authenticate(impostor.createRequest(challenge)), ['SECRET_MISMATCH']);
});

test('copied proof replayed against a NEW challenge fails (BAD_SIGNATURE)', () => {
  const { client, receiver } = setup();
  const first = liveRequest(client, receiver);
  receiver.authenticate(first); // legitimate use

  // Attacker copies the whole first payload but points it at a fresh challenge.
  const freshChallenge = receiver.issueChallenge(client.lookupKey);
  const replayed: RequestPayload = { ...first, challengeId: freshChallenge.challengeId };
  expectAuthError(() => receiver.authenticate(replayed), ['BAD_SIGNATURE']);
});

test('exact replay of a consumed request fails (challenge is single-use)', () => {
  const { client, receiver } = setup();
  const payload = liveRequest(client, receiver);
  receiver.authenticate(payload);
  expectAuthError(() => receiver.authenticate(payload), ['CHALLENGE_NOT_FOUND']);
});

test('a proof with no live server challenge is refused by the API surface', () => {
  const { client, receiver } = setup();
  // Fabricate a request against a challenge the receiver never issued.
  const payload = liveRequest(client, receiver);
  const forged: RequestPayload = { ...payload, challengeId: 'never-issued-challenge' };
  expectAuthError(() => receiver.authenticate(forged), ['CHALLENGE_NOT_FOUND']);
});

test('salt never appears in per-request payloads (any encoding, any field)', () => {
  const { client, receiver } = setup();
  const state = client.exportState();
  const saltBytes = b64d(state.salt);

  const payload = liveRequest(client, receiver);
  const serialized = JSON.stringify(payload);

  assert.ok(!deepKeys(payload).some((k) => k.toLowerCase().includes('salt')), 'payload must have no salt field');
  for (const enc of encodings(saltBytes)) {
    assert.ok(!serialized.includes(enc), `per-request payload leaked the salt as "${enc.slice(0, 12)}..."`);
  }
  // And the clear secret must not travel either.
  for (const enc of encodings(b64d(state.tokenSecret))) {
    assert.ok(!serialized.includes(enc), 'per-request payload leaked the token secret in the clear');
  }
});

test('salt travels only at registration — and only encrypted', () => {
  const client = SenderClient.generate();
  const state = client.exportState();
  const saltBytes = b64d(state.salt);
  const registration = client.createRegistration(LINK);
  const serialized = JSON.stringify(registration);
  assert.equal(typeof registration.encryptedSalt, 'string');
  for (const enc of encodings(saltBytes)) {
    assert.ok(!serialized.includes(enc), 'registration leaked the salt in the clear');
  }
});

test('tampered encrypted token ID fails', () => {
  const { client, receiver } = setup();
  const payload = liveRequest(client, receiver);
  const raw = payload.encryptedTokenId;
  const flipped = raw.slice(0, 10) + (raw[10] === 'A' ? 'B' : 'A') + raw.slice(11);
  expectAuthError(() => receiver.authenticate({ ...payload, encryptedTokenId: flipped }), [
    'DECRYPT_FAILED',
    'TOKEN_ID_MISMATCH',
  ]);
});

test('expired challenge fails with CHALLENGE_EXPIRED', () => {
  let now = 1_000_000;
  const client = SenderClient.generate();
  const receiver = new Receiver({ challengeTtlMs: 5_000, now: () => now });
  receiver.register(client.createRegistration(LINK));
  const challenge = receiver.issueChallenge(client.lookupKey);
  const payload = client.createRequest(challenge);
  now += 10_000; // past the TTL
  expectAuthError(() => receiver.authenticate(payload), ['CHALLENGE_EXPIRED']);
});

test('a failed attempt also burns the challenge (no oracle grinding)', () => {
  const { client, receiver } = setup();
  const payload = liveRequest(client, receiver);
  const bad: RequestPayload = { ...payload, signature: b64e(new Uint8Array(64).fill(1)) };
  expectAuthError(() => receiver.authenticate(bad), ['BAD_SIGNATURE']);
  // The genuine payload can no longer use that challenge either.
  expectAuthError(() => receiver.authenticate(payload), ['CHALLENGE_NOT_FOUND']);
});

test('stored row at rest reveals nothing: no token ID, salt, secret or link ID in any encoding', () => {
  const { client, receiver } = setup();
  const state = client.exportState();
  const atRest = JSON.stringify(receiver.exportState());
  assert.ok(!atRest.includes(LINK.accountId), 'link ID leaked at rest');
  for (const enc of encodings(b64d(state.salt))) assert.ok(!atRest.includes(enc), 'salt leaked at rest');
  for (const enc of encodings(b64d(state.tokenSecret))) assert.ok(!atRest.includes(enc), 'secret leaked at rest');
  for (const enc of encodings(new TextEncoder().encode(state.tokenId))) {
    assert.ok(!atRest.includes(enc), 'token ID leaked at rest');
  }
});

test('receiver state round-trips through exportState/fromState (host-backed store)', () => {
  const { client, receiver } = setup();
  const challenge = receiver.issueChallenge(client.lookupKey);
  const restored = Receiver.fromState(JSON.parse(JSON.stringify(receiver.exportState())) as never);
  const result = restored.authenticate(client.createRequest(challenge));
  assert.deepEqual(result.linkFields, LINK);
});

test('duplicate registration is rejected', () => {
  const { client, receiver } = setup();
  expectAuthError(() => receiver.register(client.createRegistration(LINK)), ['ALREADY_REGISTERED']);
});
