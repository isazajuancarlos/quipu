import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as quipu from '../src/index.js';

test('version() returns a semver-ish string', () => {
  assert.match(quipu.version(), /^\d+\.\d+\.\d+/);
});

test('streaming roundtrip', async () => {
  const msg = Buffer.from('streaming payload for node');
  const blob = await quipu.encryptStream(msg, 'pw');
  assert.ok(Buffer.isBuffer(blob) && blob.length > 0);
  const back = await quipu.decryptStream(blob, 'pw');
  assert.deepEqual(back, msg);
});

test('streaming with pepper roundtrip', async () => {
  const msg = Buffer.from('peppered');
  const pepper = Buffer.from('spice');
  const blob = await quipu.encryptStream(msg, 'pw', { pepper });
  assert.deepEqual(await quipu.decryptStream(blob, 'pw', { pepper }), msg);
});

test('symmetric codec roundtrip (string symbols)', async () => {
  const msg = Buffer.from('hello glyphs');
  const sym = await quipu.encode(msg, 'pw');
  assert.equal(typeof sym, 'string');
  assert.ok(sym.length >= 115);
  assert.deepEqual(await quipu.decode(sym, 'pw'), msg);
});

test('post-quantum recipient roundtrip', async () => {
  const { publicKey, secretKey } = await quipu.generateKeypair();
  assert.equal(publicKey.length, 1600);
  assert.equal(secretKey.length, 3200);
  const msg = Buffer.from('for your eyes only');
  const sym = await quipu.encryptToRecipient(msg, publicKey);
  assert.deepEqual(await quipu.decryptAsRecipient(sym, secretKey), msg);
});
