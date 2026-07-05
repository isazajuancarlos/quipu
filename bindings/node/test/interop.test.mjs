import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as quipu from '../src/index.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, '..', '..', '..', 'tests', 'vectors', 'quipu_vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));

test('decrypts Rust-produced QST1 streaming vectors (cross-language interop)', () => {
  const cases = vectors.frozen.streaming_decode;
  assert.ok(Array.isArray(cases) && cases.length > 0);
  for (const v of cases) {
    const blob = Buffer.from(v.blob_hex, 'hex');
    const pepper = v.pepper_hex ? Buffer.from(v.pepper_hex, 'hex') : undefined;
    const plain = quipu.decryptStream(blob, v.passphrase, { pepper });
    assert.deepEqual(plain, Buffer.from(v.plaintext_hex, 'hex'), v.desc);
  }
});
