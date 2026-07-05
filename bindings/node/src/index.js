import * as native from './native.js';
import { callBytes, callString, callKeypair } from './call.js';
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
