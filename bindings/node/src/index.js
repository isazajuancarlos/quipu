import * as native from './native.js';
import { callBytes, callString, callKeypair, callTwoBytes } from './call.js';
import { OprfUnavailable, OprfRejected } from './errors.js';
export { QuipuError, OprfError, OprfUnavailable, OprfRejected } from './errors.js';

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
// valid, return the 64-byte hardened secret (Buffer). Throws QuipuError('AUTH')
// if the proof is invalid. All args are Buffers.
//
// 64 bytes, not 32: RFC 9497's output is the full SHA-512 hash. It was 32 with
// the pre-conformance construction, which no longer exists.
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
// `password` is a Buffer; `serverPublicKey` is the 32-byte key, pinned
// out-of-band. Returns the hardened secret (Buffer).
//
// The key is REQUIRED and is never fetched from the server. Fetching it would
// make the DLEQ proof decorative: a malicious server (or a MITM) hands you its
// own key, the proof verifies against it, and hardening reports success while
// the password went somewhere you did not choose. The proof answers "is this
// the server I pinned?" -- asking that server for the answer is no answer.
// Throws OprfUnavailable (retryable) or OprfRejected (investigate); see errors.js.
export async function oprfHarden({ baseUrl, apiKey, password, serverPublicKey, timeoutMs = 5000 }) {
  if (!Buffer.isBuffer(serverPublicKey) || serverPublicKey.length !== 32) {
    throw new TypeError(
      'serverPublicKey must be a pinned 32-byte Buffer. Fetch it once, out of band ' +
      "(GET /v1/public-key), and ship it as config -- not at call time.",
    );
  }
  const base = baseUrl.replace(/\/+$/, '');
  const { state, blinded } = voprfBlind(password);

  let r;
  try {
    r = await fetch(base + '/v1/oprf/evaluate', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'text/plain' },
      body: blinded.toString('hex'),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (cause) {
    throw new OprfUnavailable(`oprf: no response from ${base}`, { cause });
  }
  if (!r.ok) {
    throw new OprfUnavailable(`oprf: evaluate HTTP ${r.status}: ${await r.text().catch(() => '')}`);
  }

  let evaluation, proof;
  try {
    ({ evaluation, proof } = await r.json());
  } catch (cause) {
    throw new OprfUnavailable('oprf: malformed response body', { cause });
  }

  try {
    return voprfFinalize(
      password, state,
      Buffer.from(evaluation, 'hex'), Buffer.from(proof, 'hex'),
      serverPublicKey,
    );
  } catch (cause) {
    throw new OprfRejected(
      'oprf: the DLEQ proof does not verify against the pinned public key. The server ' +
      'is not the one you pinned, or its key rotated. Do not retry blindly.',
      { cause },
    );
  }
}
