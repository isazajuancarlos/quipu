import { koffi } from './native.js';

// Copy `len` native bytes at `ptr` into a JS Buffer.
export function decodeBytes(ptr, len) {
  return Buffer.from(koffi.decode(ptr, koffi.array('uint8_t', len)));
}

// Read a NUL-terminated C string at `ptr`. A lazy zero-copy view is scanned only
// up to the terminating NUL, which is the last allocated byte — so this never
// reads past the allocation. Quipu glyph strings are always >= 115 bytes, so the
// first 256-byte window is always in-bounds; the loop covers longer outputs.
export function decodeCString(ptr) {
  const CHUNK = 256;
  let size = CHUNK;
  for (;;) {
    const view = Buffer.from(koffi.view(ptr, size));
    const nul = view.indexOf(0);
    if (nul !== -1) return view.toString('latin1', 0, nul);
    size += CHUNK;
  }
}
