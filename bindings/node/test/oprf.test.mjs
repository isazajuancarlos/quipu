import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as quipu from '../src/index.js';

// Smoke tests offline del FFI VOPRF (no requieren servidor). El round-trip
// válido completo se cubre en scripts/oprf-e2e.sh.

test('voprfBlind returns state(64) and blinded(32)', () => {
  const { state, blinded } = quipu.voprfBlind(Buffer.from('password'));
  assert.equal(state.length, 64);
  assert.equal(blinded.length, 32);
});

test('voprfBlind is randomized', () => {
  const a = quipu.voprfBlind(Buffer.from('password')).blinded;
  const b = quipu.voprfBlind(Buffer.from('password')).blinded;
  assert.ok(!a.equals(b));
});

test('voprfFinalize rejects a bogus proof -> AUTH', () => {
  const { state } = quipu.voprfBlind(Buffer.from('password'));
  assert.throws(
    () => quipu.voprfFinalize(Buffer.from('password'), state, Buffer.alloc(32), Buffer.alloc(64), Buffer.alloc(32)),
    (e) => {
      assert.ok(e instanceof quipu.QuipuError);
      assert.equal(e.code, 'AUTH');
      return true;
    },
  );
});
