#!/usr/bin/env node
/**
 * CLI for sealed-token-auth.
 *
 *   sealed-token-auth sender generate [--out client.json]
 *   sealed-token-auth sender encrypt --state client.json --link-id <id> [--out registration.json]
 *   sealed-token-auth sender encrypt-request --state client.json --challenge challenge.json [--out request.json]
 *   sealed-token-auth receiver register --store store.json --registration registration.json
 *   sealed-token-auth receiver challenge --store store.json --lookup-key <key> [--out challenge.json]
 *   sealed-token-auth receiver verify --store store.json --request request.json
 *
 * JSON goes to --out when given, else stdout. The receiver "store" is a JSON
 * file holding Receiver.exportState() — rows plus pending challenges.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { SenderClient } from './client.js';
import { Receiver, type ReceiverState } from './server.js';
import { AuthError, type Challenge, type ClientState, type RegistrationPayload, type RequestPayload } from './protocol.js';

function parseArgs(argv: string[]): { positional: string[]; flags: Map<string, string> } {
  const positional: string[] = [];
  const flags = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      flags.set(key, val);
    } else {
      positional.push(a);
    }
  }
  return { positional, flags };
}

function emit(value: unknown, out: string | undefined): void {
  const text = JSON.stringify(value, null, 2) + '\n';
  if (out) writeFileSync(out, text);
  else process.stdout.write(text);
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

function loadReceiver(storePath: string | undefined): Receiver {
  if (storePath && existsSync(storePath)) {
    return Receiver.fromState(readJson<ReceiverState>(storePath));
  }
  return new Receiver();
}

function saveReceiver(receiver: Receiver, storePath: string | undefined): void {
  if (storePath) writeFileSync(storePath, JSON.stringify(receiver.exportState(), null, 2) + '\n');
}

function need(flags: Map<string, string>, name: string): string {
  const v = flags.get(name);
  if (!v) throw new Error(`missing required --${name}`);
  return v;
}

function main(argv: string[]): number {
  const { positional, flags } = parseArgs(argv);
  const [side, verb] = positional;

  if (side === 'sender' && verb === 'generate') {
    const client = SenderClient.generate();
    emit(client.exportState(), flags.get('out'));
    if (flags.get('out')) {
      process.stderr.write('client state written (contains the private key, secret and salt — store it like a password)\n');
    }
    return 0;
  }

  if (side === 'sender' && verb === 'encrypt') {
    const client = SenderClient.fromState(readJson<ClientState>(need(flags, 'state')));
    const linkId = need(flags, 'link-id');
    emit(client.createRegistration({ accountId: linkId }), flags.get('out'));
    return 0;
  }

  if (side === 'sender' && verb === 'encrypt-request') {
    const client = SenderClient.fromState(readJson<ClientState>(need(flags, 'state')));
    const challenge = readJson<Challenge>(need(flags, 'challenge'));
    emit(client.createRequest(challenge), flags.get('out'));
    return 0;
  }

  if (side === 'receiver' && verb === 'register') {
    const store = flags.get('store');
    const receiver = loadReceiver(store);
    const result = receiver.register(readJson<RegistrationPayload>(need(flags, 'registration')));
    saveReceiver(receiver, store);
    emit(result, flags.get('out'));
    return 0;
  }

  if (side === 'receiver' && verb === 'challenge') {
    const store = flags.get('store');
    const receiver = loadReceiver(store);
    const challenge = receiver.issueChallenge(need(flags, 'lookup-key'));
    saveReceiver(receiver, store);
    emit(challenge, flags.get('out'));
    return 0;
  }

  if (side === 'receiver' && verb === 'verify') {
    const store = flags.get('store');
    const receiver = loadReceiver(store);
    const result = receiver.authenticate(readJson<RequestPayload>(need(flags, 'request')));
    saveReceiver(receiver, store);
    emit({ ok: true, ...result }, flags.get('out'));
    return 0;
  }

  process.stderr.write(
    [
      'usage:',
      '  sealed-token-auth sender generate [--out client.json]',
      '  sealed-token-auth sender encrypt --state client.json --link-id <id> [--out registration.json]',
      '  sealed-token-auth sender encrypt-request --state client.json --challenge challenge.json [--out request.json]',
      '  sealed-token-auth receiver register --store store.json --registration registration.json',
      '  sealed-token-auth receiver challenge --store store.json --lookup-key <key> [--out challenge.json]',
      '  sealed-token-auth receiver verify --store store.json --request request.json',
      '',
    ].join('\n'),
  );
  return 2;
}

try {
  process.exit(main(process.argv.slice(2)));
} catch (err) {
  if (err instanceof AuthError) {
    process.stderr.write(`auth failed: ${err.code}: ${err.message}\n`);
  } else {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
  }
  process.exit(1);
}
