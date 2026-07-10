import * as native from './native.js';
import { callBytes, callString, callKeypair, callTwoBytes } from './call.js';
export { QuipuError } from './errors.js';

const pepperArgs = (pepper) => (pepper ? [pepper, pepper.length] : [null, 0]);

export function version() {
  return native.versionFn();
}

export function encryptStream(data, passphrase, opts = {}) {
  const { pepper, chunkSize = 0 } = opts;
  return callBytes(native.encryptStreamFn, [data, data.length, passphrase, ...pepperArgs(pepper), chunkSize]);
}

export function decryptStream(blob, passphrase, opts = {}) {
  const { pepper } = opts;
  return callBytes(native.decryptStreamFn, [blob, blob.length, passphrase, ...pepperArgs(pepper)]);
}

export function encode(data, passphrase, pepper) {
  return callString(native.encodeFn, [data, data.length, passphrase, ...pepperArgs(pepper)]);
}

export function decode(symbols, passphrase, pepper) {
  return callBytes(native.decodeFn, [symbols, passphrase, ...pepperArgs(pepper)]);
}

export function generateKeypair() {
  const [publicKey, secretKey] = callKeypair(native.generateKeypairFn);
  return { publicKey, secretKey };
}

export function encryptToRecipient(data, publicKey) {
  return callString(native.encryptToRecipientFn, [data, data.length, publicKey, publicKey.length]);
}

export function decryptAsRecipient(symbols, secretKey) {
  return callBytes(native.decryptAsRecipientFn, [symbols, secretKey, secretKey.length]);
}

export function generateSigningKeypair() {
  const [verifyingKey, signingKey] = callKeypair(native.generateSigningKeypairFn);
  return { verifyingKey, signingKey };
}

export function sign(data, signingKey) {
  return callString(native.signFn, [data, data.length, signingKey, signingKey.length]);
}

export function verify(symbols, verifyingKey) {
  return callBytes(native.verifyFn, [symbols, verifyingKey, verifyingKey.length]);
}

// --- VOPRF client hardening (talks to a quipu-oprf-server) ---

// Low-level: blind a password. Returns { state, blinded } (Buffers). Keep
// `state` for voprfFinalize; send `blinded` to the server. `password` is a Buffer.
export function voprfBlind(password) {
  const [state, blinded] = callTwoBytes(native.voprfBlindFn, [password, password.length]);
  return { state, blinded };
}

// Low-level: verify the DLEQ proof against the pinned `serverPublicKey` and, if
// valid, return the 32-byte hardened secret (Buffer). Throws QuipuError('AUTH')
// if the proof is invalid. All args are Buffers.
export function voprfFinalize(password, state, evaluated, proof, serverPublicKey) {
  return callBytes(native.voprfFinalizeFn, [
    password, password.length,
    state, state.length,
    evaluated, evaluated.length,
    proof, proof.length,
    serverPublicKey, serverPublicKey.length,
  ]);
}

// High-level: full verifiable hardening flow (blind -> HTTP -> finalize).
// `password` is a Buffer; if `serverPublicKey` is omitted it is fetched from the
// server (pin it out-of-band in production). Returns the hardened secret (Buffer).
export async function oprfHarden({ baseUrl, apiKey, password, serverPublicKey }) {
  const base = baseUrl.replace(/\/+$/, '');
  let pub = serverPublicKey;
  if (!pub) {
    const r = await fetch(base + '/v1/public-key');
    if (!r.ok) throw new Error(`public-key HTTP ${r.status}`);
    pub = Buffer.from((await r.json()).public_key, 'hex');
  }
  const { state, blinded } = voprfBlind(password);
  const r = await fetch(base + '/v1/oprf/evaluate', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'text/plain' },
    body: blinded.toString('hex'),
  });
  if (!r.ok) throw new Error(`evaluate HTTP ${r.status}: ${await r.text()}`);
  const { evaluation, proof } = await r.json();
  return voprfFinalize(password, state, Buffer.from(evaluation, 'hex'), Buffer.from(proof, 'hex'), pub);
}
