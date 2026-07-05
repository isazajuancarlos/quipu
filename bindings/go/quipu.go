// Package quipu provides Go bindings for the Quipu post-quantum crypto library
// over its stable C ABI (bindings/c). It statically links libquipu_capi.a; build
// it first with `cargo build -p quipu-capi --release`.
package quipu

/*
#cgo CFLAGS: -I${SRCDIR}/../c/include
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libquipu_capi.a -lpthread -ldl -lm
#include "quipu.h"
#include <stdlib.h>
*/
import "C"

import "unsafe"

// Version returns the Quipu C ABI version string.
func Version() string {
	return C.GoString(C.quipu_version())
}

// cbytes passes a read-only []byte to C as (ptr, len); the returned func frees
// the C copy. An empty slice yields a NULL pointer and length 0.
func cbytes(b []byte) (unsafe.Pointer, C.size_t, func()) {
	if len(b) == 0 {
		return nil, 0, func() {}
	}
	p := C.CBytes(b)
	return p, C.size_t(len(b)), func() { C.free(p) }
}

// goBytesFree copies a native byte buffer to a Go slice and frees the native one.
func goBytesFree(ptr *C.uint8_t, n C.size_t) []byte {
	b := C.GoBytes(unsafe.Pointer(ptr), C.int(n))
	C.quipu_bytes_free(ptr, n)
	return b
}

// goStringFree copies a native C string to a Go string and frees the native one.
func goStringFree(ptr *C.char) string {
	s := C.GoString(ptr)
	C.quipu_string_free(ptr)
	return s
}

// StreamOptions configures streaming encryption. A zero ChunkSize uses the
// format default; a nil Pepper means none.
type StreamOptions struct {
	Pepper    []byte
	ChunkSize int
}

// EncryptStream encrypts data into the streaming AEAD container (QST1).
func EncryptStream(data []byte, passphrase string, opts StreamOptions) ([]byte, error) {
	dp, dn, dfree := cbytes(data)
	defer dfree()
	pp, pn, pfree := cbytes(opts.Pepper)
	defer pfree()
	cpass := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpass))

	var out *C.uint8_t
	var outLen C.size_t
	rc := C.quipu_encrypt_stream((*C.uint8_t)(dp), dn, cpass, (*C.uint8_t)(pp), pn, C.size_t(opts.ChunkSize), &out, &outLen)
	if err := errorFor(int32(rc)); err != nil {
		return nil, err
	}
	return goBytesFree(out, outLen), nil
}

// DecryptStream decrypts a QST1 container produced by EncryptStream.
func DecryptStream(blob []byte, passphrase string, pepper []byte) ([]byte, error) {
	bp, bn, bfree := cbytes(blob)
	defer bfree()
	pp, pn, pfree := cbytes(pepper)
	defer pfree()
	cpass := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpass))

	var out *C.uint8_t
	var outLen C.size_t
	rc := C.quipu_decrypt_stream((*C.uint8_t)(bp), bn, cpass, (*C.uint8_t)(pp), pn, &out, &outLen)
	if err := errorFor(int32(rc)); err != nil {
		return nil, err
	}
	return goBytesFree(out, outLen), nil
}
