// Tests against a REAL quipu-oprf-server on localhost -- no fakes in any layer.
//
// Start one first:
//   export QUIPU_OPRF_DB=$PWD/oprf.db QUIPU_OPRF_SEED=$(openssl rand -hex 32)
//   quipu-oprf-server init && quipu-oprf-server issue test
//   QUIPU_OPRF_ADDR=127.0.0.1:8791 quipu-oprf-server serve
//
// then: QUIPU_OPRF_URL=http://127.0.0.1:8791 QUIPU_OPRF_API_KEY=<key> npm test
// The public key is read from the server at test setup; in production you pin it.

import { test, before, describe } from 'node:test';
import assert from 'node:assert/strict';
import { OprfArgon2Hasher, OprfUnavailable, OprfRejected, ALGORITHM } from '../src/index.js';

const BASE = process.env.QUIPU_OPRF_URL ?? 'http://127.0.0.1:8791';
const KEY = process.env.QUIPU_OPRF_API_KEY;

// Argon2id at 19 MiB is deliberately slow; a few seconds per call is the point.
const SLOW = { timeout: 30_000 };

let PUB;
let hasher;

before(async () => {
  if (!KEY) throw new Error('set QUIPU_OPRF_API_KEY (see header)');
  const r = await fetch(BASE + '/v1/public-key');
  if (!r.ok) throw new Error(`no OPRF server at ${BASE} (HTTP ${r.status})`);
  PUB = (await r.json()).public_key;
  hasher = new OprfArgon2Hasher({ baseUrl: BASE, apiKey: KEY, serverPublicKey: PUB });
});

describe('configuration', () => {
  const ok = { baseUrl: BASE, apiKey: 'k', serverPublicKey: 'ab'.repeat(32) };

  test('rejects a missing pinned key', () => {
    assert.throws(() => new OprfArgon2Hasher({ ...ok, serverPublicKey: undefined }), TypeError);
  });

  test('rejects a short pinned key', () => {
    assert.throws(() => new OprfArgon2Hasher({ ...ok, serverPublicKey: 'ab'.repeat(16) }), TypeError);
  });

  test('rejects a non-hex pinned key', () => {
    assert.throws(() => new OprfArgon2Hasher({ ...ok, serverPublicKey: 'z'.repeat(64) }), TypeError);
  });

  test('rejects a missing baseUrl / apiKey', () => {
    assert.throws(() => new OprfArgon2Hasher({ ...ok, baseUrl: undefined }), TypeError);
    assert.throws(() => new OprfArgon2Hasher({ ...ok, apiKey: undefined }), TypeError);
  });

  test('accepts the key as hex or as a Buffer', () => {
    assert.ok(new OprfArgon2Hasher(ok));
    assert.ok(new OprfArgon2Hasher({ ...ok, serverPublicKey: Buffer.alloc(32, 1) }));
  });
});

describe('hash and verify', () => {
  test('round-trips', SLOW, async () => {
    const e = await hasher.hash('correcta');
    assert.ok(e.startsWith(ALGORITHM + '$'));
    assert.equal(await hasher.verify('correcta', e), true);
  });

  test('rejects a wrong password', SLOW, async () => {
    const e = await hasher.hash('correcta');
    assert.equal(await hasher.verify('incorrecta', e), false);
  });

  test('salts: same password, different stored values', SLOW, async () => {
    assert.notEqual(await hasher.hash('misma'), await hasher.hash('misma'));
  });

  test('survives non-ASCII and long passwords', SLOW, async () => {
    for (const pw of ['contraseña-ñandú-€', '🔐'.repeat(20), 'x'.repeat(500)]) {
      assert.equal(await hasher.verify(pw, await hasher.hash(pw)), true);
    }
  });

  test('accepts a Buffer password', SLOW, async () => {
    const e = await hasher.hash(Buffer.from('desde-buffer', 'utf8'));
    assert.equal(await hasher.verify('desde-buffer', e), true);
  });
});

describe('failure modes', () => {
  test('a wrong pinned key is OprfRejected, never a silent pass', SLOW, async () => {
    const liar = new OprfArgon2Hasher({
      baseUrl: BASE, apiKey: KEY, serverPublicKey: Buffer.alloc(32, 7),
    });
    await assert.rejects(() => liar.hash('x'), OprfRejected);
  });

  test('a bad api key is OprfUnavailable', SLOW, async () => {
    const h = new OprfArgon2Hasher({ baseUrl: BASE, apiKey: 'quipu_live_falsa', serverPublicKey: PUB });
    await assert.rejects(() => h.hash('x'), OprfUnavailable);
  });

  test('an unreachable server is OprfUnavailable, not a wrong password', SLOW, async () => {
    const e = await hasher.hash('correcta');
    const down = new OprfArgon2Hasher({
      baseUrl: 'http://127.0.0.1:9', apiKey: KEY, serverPublicKey: PUB, timeoutMs: 800,
    });
    // The point: it throws rather than returning false. Returning false would
    // tell a user with the RIGHT password that it was wrong, during an outage.
    await assert.rejects(() => down.verify('correcta', e), OprfUnavailable);
  });
});

describe('migration', () => {
  const BCRYPT = '$2b$12$' + 'a'.repeat(53);

  test('needsRehash flags legacy rows and clears ours', SLOW, async () => {
    assert.equal(hasher.needsRehash(BCRYPT), true);
    assert.equal(hasher.needsRehash(await hasher.hash('x')), false);
  });

  test('identify does not claim someone else\'s hashes', () => {
    assert.equal(hasher.identify(BCRYPT), false);
    assert.equal(hasher.identify('$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA'), false);
    assert.equal(hasher.identify(undefined), false);
  });

  test('verify refuses a legacy row instead of guessing', async () => {
    await assert.rejects(() => hasher.verify('x', BCRYPT), TypeError);
  });
});
