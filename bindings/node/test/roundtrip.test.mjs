import { test } from 'node:test';
import assert from 'node:assert/strict';
import { versionFn } from '../src/native.js';

test('version() returns a semver-ish string', () => {
  const v = versionFn();
  assert.equal(typeof v, 'string');
  assert.match(v, /^\d+\.\d+\.\d+/);
});
