import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as quipu from '../src/index.js';

test('wrong passphrase -> QuipuError code AUTH', () => {
  const blob = quipu.encryptStream(Buffer.from('x'), 'right');
  assert.throws(() => quipu.decryptStream(blob, 'wrong'), (e) => {
    assert.ok(e instanceof quipu.QuipuError);
    assert.equal(e.code, 'AUTH');
    return true;
  });
});

test('out-of-range chunkSize -> code CHUNK', () => {
  assert.throws(() => quipu.encryptStream(Buffer.from('x'), 'pw', { chunkSize: 64 }), (e) => {
    assert.equal(e.code, 'CHUNK');
    return true;
  });
});

test('decode with wrong passphrase -> AUTH', () => {
  const sym = quipu.encode(Buffer.from('data'), 'right');
  assert.throws(() => quipu.decode(sym, 'wrong'), (e) => {
    assert.equal(e.code, 'AUTH');
    return true;
  });
});

test('wrong-length recipient key -> KEY', () => {
  assert.throws(() => quipu.encryptToRecipient(Buffer.from('x'), Buffer.alloc(10)), (e) => {
    assert.equal(e.code, 'KEY');
    return true;
  });
});

test('verify with a different key -> AUTH', () => {
  const a = quipu.generateSigningKeypair();
  const b = quipu.generateSigningKeypair();
  const signed = quipu.sign(Buffer.from('m'), a.signingKey);
  assert.throws(() => quipu.verify(signed, b.verifyingKey), (e) => {
    assert.equal(e.code, 'AUTH');
    return true;
  });
});
