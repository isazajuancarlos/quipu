import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as quipu from '../src/index.js';

test('version() returns a semver-ish string', () => {
  assert.match(quipu.version(), /^\d+\.\d+\.\d+/);
});

test('streaming roundtrip', () => {
  const msg = Buffer.from('streaming payload for node');
  const blob = quipu.encryptStream(msg, 'pw');
  assert.ok(Buffer.isBuffer(blob) && blob.length > 0);
  assert.deepEqual(quipu.decryptStream(blob, 'pw'), msg);
});

test('streaming with pepper roundtrip', () => {
  const msg = Buffer.from('peppered');
  const pepper = Buffer.from('spice');
  const blob = quipu.encryptStream(msg, 'pw', { pepper });
  assert.deepEqual(quipu.decryptStream(blob, 'pw', { pepper }), msg);
});

test('symmetric codec roundtrip (string symbols)', () => {
  const msg = Buffer.from('hello glyphs');
  const sym = quipu.encode(msg, 'pw');
  assert.equal(typeof sym, 'string');
  assert.ok(sym.length >= 115);
  assert.deepEqual(quipu.decode(sym, 'pw'), msg);
});

test('post-quantum recipient roundtrip', () => {
  const { publicKey, secretKey } = quipu.generateKeypair();
  assert.equal(publicKey.length, 1600);
  // X25519 (32) + la semilla de 64 bytes de ML-KEM-1024, no la forma
  // expandida de 3168 que se serializaba antes de ml-kem 0.3. Ver SPEC.md §7.1.
  assert.equal(secretKey.length, 96);
  const msg = Buffer.from('for your eyes only');
  const sym = quipu.encryptToRecipient(msg, publicKey);
  assert.deepEqual(quipu.decryptAsRecipient(sym, secretKey), msg);
});

test('hybrid signature roundtrip', () => {
  const { verifyingKey, signingKey } = quipu.generateSigningKeypair();
  assert.equal(verifyingKey.length, 2624);
  assert.equal(signingKey.length, 64);
  const msg = Buffer.from('acta oficial');
  const signed = quipu.sign(msg, signingKey);
  assert.deepEqual(quipu.verify(signed, verifyingKey), msg);
});
