import { errorFor } from './errors.js';
import { decodeBytes, decodeCString } from './memory.js';
import { bytesFreeFn, stringFreeFn } from './native.js';

// Calls are synchronous: the Rust core's ML-DSA operations overflow the small
// stack of a libuv threadpool worker (koffi's async path), so we run on the main
// thread where the stack is full-size. Non-blocking use is a documented
// follow-up (run these in a worker_thread). See the README.

// Call whose success writes (uint8_t** out, size_t* out_len).
export function callBytes(fn, args) {
  const out = [null];
  const outLen = [0n];
  const rc = fn(...args, out, outLen);
  const e = errorFor(rc);
  if (e) throw e;
  const len = Number(outLen[0]);
  const buf = decodeBytes(out[0], len);
  bytesFreeFn(out[0], len);
  return buf;
}

// Call whose success writes (uint8_t** out) holding a C string.
export function callString(fn, args) {
  const out = [null];
  const rc = fn(...args, out);
  const e = errorFor(rc);
  if (e) throw e;
  const s = decodeCString(out[0]);
  stringFreeFn(out[0]);
  return s;
}

// Keypair generator: (uint8_t** a, size_t* aLen, uint8_t** b, size_t* bLen).
export function callKeypair(fn) {
  const a = [null];
  const aLen = [0n];
  const b = [null];
  const bLen = [0n];
  const rc = fn(a, aLen, b, bLen);
  const e = errorFor(rc);
  if (e) throw e;
  const al = Number(aLen[0]);
  const bl = Number(bLen[0]);
  const aBuf = decodeBytes(a[0], al);
  bytesFreeFn(a[0], al);
  const bBuf = decodeBytes(b[0], bl);
  bytesFreeFn(b[0], bl);
  return [aBuf, bBuf];
}
