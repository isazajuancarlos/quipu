import { errorFor } from './errors.js';
import { decodeBytes, decodeCString } from './memory.js';
import { bytesFreeFn, stringFreeFn } from './native.js';

// Async call whose success writes (uint8_t** out, size_t* out_len).
export function callBytes(fn, args) {
  return new Promise((resolve, reject) => {
    const out = [null];
    const outLen = [0n];
    fn.async(...args, out, outLen, (err, rc) => {
      if (err) return reject(err);
      const e = errorFor(rc);
      if (e) return reject(e);
      const len = Number(outLen[0]);
      const buf = decodeBytes(out[0], len);
      bytesFreeFn(out[0], len);
      resolve(buf);
    });
  });
}

// Async call whose success writes (uint8_t** out) holding a C string.
export function callString(fn, args) {
  return new Promise((resolve, reject) => {
    const out = [null];
    fn.async(...args, out, (err, rc) => {
      if (err) return reject(err);
      const e = errorFor(rc);
      if (e) return reject(e);
      const s = decodeCString(out[0]);
      stringFreeFn(out[0]);
      resolve(s);
    });
  });
}

// Async keypair generator: (uint8_t** a, size_t* aLen, uint8_t** b, size_t* bLen).
export function callKeypair(fn) {
  return new Promise((resolve, reject) => {
    const a = [null];
    const aLen = [0n];
    const b = [null];
    const bLen = [0n];
    fn.async(a, aLen, b, bLen, (err, rc) => {
      if (err) return reject(err);
      const e = errorFor(rc);
      if (e) return reject(e);
      const al = Number(aLen[0]);
      const bl = Number(bLen[0]);
      const aBuf = decodeBytes(a[0], al);
      bytesFreeFn(a[0], al);
      const bBuf = decodeBytes(b[0], bl);
      bytesFreeFn(b[0], bl);
      resolve([aBuf, bBuf]);
    });
  });
}
