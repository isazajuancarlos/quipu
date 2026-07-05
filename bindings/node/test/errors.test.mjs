import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as quipu from '../src/index.js';

test('wrong passphrase -> QuipuError code AUTH', async () => {
  const blob = await quipu.encryptStream(Buffer.from('x'), 'right');
  await assert.rejects(quipu.decryptStream(blob, 'wrong'), (e) => {
    assert.ok(e instanceof quipu.QuipuError);
    assert.equal(e.code, 'AUTH');
    return true;
  });
});

test('out-of-range chunkSize -> code CHUNK', async () => {
  await assert.rejects(quipu.encryptStream(Buffer.from('x'), 'pw', { chunkSize: 64 }), (e) => {
    assert.equal(e.code, 'CHUNK');
    return true;
  });
});

test('decode with wrong passphrase -> AUTH', async () => {
  const sym = await quipu.encode(Buffer.from('data'), 'right');
  await assert.rejects(quipu.decode(sym, 'wrong'), (e) => {
    assert.equal(e.code, 'AUTH');
    return true;
  });
});

test('wrong-length recipient key -> KEY', async () => {
  await assert.rejects(quipu.encryptToRecipient(Buffer.from('x'), Buffer.alloc(10)), (e) => {
    assert.equal(e.code, 'KEY');
    return true;
  });
});
