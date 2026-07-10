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

// Encode encrypts data under a passphrase and returns glyph symbols.
func Encode(data []byte, passphrase string, pepper []byte) (string, error) {
	dp, dn, dfree := cbytes(data)
	defer dfree()
	pp, pn, pfree := cbytes(pepper)
	defer pfree()
	cpass := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpass))

	var out *C.char
	rc := C.quipu_encode((*C.uint8_t)(dp), dn, cpass, (*C.uint8_t)(pp), pn, &out)
	if err := errorFor(int32(rc)); err != nil {
		return "", err
	}
	return goStringFree(out), nil
}

// Decode decrypts glyph symbols under a passphrase.
func Decode(symbols string, passphrase string, pepper []byte) ([]byte, error) {
	csym := C.CString(symbols)
	defer C.free(unsafe.Pointer(csym))
	cpass := C.CString(passphrase)
	defer C.free(unsafe.Pointer(cpass))
	pp, pn, pfree := cbytes(pepper)
	defer pfree()

	var out *C.uint8_t
	var outLen C.size_t
	rc := C.quipu_decode(csym, cpass, (*C.uint8_t)(pp), pn, &out, &outLen)
	if err := errorFor(int32(rc)); err != nil {
		return nil, err
	}
	return goBytesFree(out, outLen), nil
}

// GenerateKeypair produces a hybrid X25519+ML-KEM-1024 recipient keypair.
func GenerateKeypair() (publicKey, secretKey []byte, err error) {
	var pk, sk *C.uint8_t
	var pkl, skl C.size_t
	rc := C.quipu_generate_keypair(&pk, &pkl, &sk, &skl)
	if e := errorFor(int32(rc)); e != nil {
		return nil, nil, e
	}
	return goBytesFree(pk, pkl), goBytesFree(sk, skl), nil
}

// EncryptToRecipient encrypts data to a recipient public key, returning glyph symbols.
func EncryptToRecipient(data []byte, publicKey []byte) (string, error) {
	dp, dn, dfree := cbytes(data)
	defer dfree()
	kp, kn, kfree := cbytes(publicKey)
	defer kfree()

	var out *C.char
	rc := C.quipu_encrypt_to_recipient((*C.uint8_t)(dp), dn, (*C.uint8_t)(kp), kn, &out)
	if err := errorFor(int32(rc)); err != nil {
		return "", err
	}
	return goStringFree(out), nil
}

// DecryptAsRecipient decrypts glyph symbols using the recipient secret key.
func DecryptAsRecipient(symbols string, secretKey []byte) ([]byte, error) {
	csym := C.CString(symbols)
	defer C.free(unsafe.Pointer(csym))
	kp, kn, kfree := cbytes(secretKey)
	defer kfree()

	var out *C.uint8_t
	var outLen C.size_t
	rc := C.quipu_decrypt_as_recipient(csym, (*C.uint8_t)(kp), kn, &out, &outLen)
	if err := errorFor(int32(rc)); err != nil {
		return nil, err
	}
	return goBytesFree(out, outLen), nil
}

// GenerateSigningKeypair generates a hybrid signing keypair (Ed25519 + ML-DSA-87).
func GenerateSigningKeypair() (verifyingKey, signingKey []byte, err error) {
	var vk, sk *C.uint8_t
	var vkl, skl C.size_t
	rc := C.quipu_generate_signing_keypair(&vk, &vkl, &sk, &skl)
	if e := errorFor(int32(rc)); e != nil {
		return nil, nil, e
	}
	return goBytesFree(vk, vkl), goBytesFree(sk, skl), nil
}

// Sign signs data with the hybrid signing key; returns a signed glyph artifact.
func Sign(data []byte, signingKey []byte) (string, error) {
	dp, dn, dfree := cbytes(data)
	defer dfree()
	kp, kn, kfree := cbytes(signingKey)
	defer kfree()

	var out *C.char
	rc := C.quipu_sign((*C.uint8_t)(dp), dn, (*C.uint8_t)(kp), kn, &out)
	if err := errorFor(int32(rc)); err != nil {
		return "", err
	}
	return goStringFree(out), nil
}

// Verify checks a signed artifact against the pinned verifying key and, only if
// it validates, returns the message.
func Verify(symbols string, verifyingKey []byte) ([]byte, error) {
	csym := C.CString(symbols)
	defer C.free(unsafe.Pointer(csym))
	kp, kn, kfree := cbytes(verifyingKey)
	defer kfree()

	var out *C.uint8_t
	var outLen C.size_t
	rc := C.quipu_verify(csym, (*C.uint8_t)(kp), kn, &out, &outLen)
	if err := errorFor(int32(rc)); err != nil {
		return nil, err
	}
	return goBytesFree(out, outLen), nil
}

// VoprfBlind blinds a password for a quipu-oprf-server. Returns the ephemeral
// blind state (64 B, keep for VoprfFinalize) and the blinded point (32 B, send
// to the server). The server never sees the password.
func VoprfBlind(password []byte) (state, blinded []byte, err error) {
	pp, pn, pfree := cbytes(password)
	defer pfree()

	var st, bl *C.uint8_t
	var stl, bll C.size_t
	rc := C.quipu_voprf_blind((*C.uint8_t)(pp), pn, &st, &stl, &bl, &bll)
	if e := errorFor(int32(rc)); e != nil {
		return nil, nil, e
	}
	return goBytesFree(st, stl), goBytesFree(bl, bll), nil
}

// VoprfFinalize verifies the DLEQ proof against the pinned serverPub (32 B) and,
// only if valid, returns the 32-byte hardened secret. Returns ErrAuth if the
// proof is invalid (dishonest server or wrong pinned key). state (64 B) is from
// VoprfBlind; evaluated (32 B) and proof (64 B) come from the server.
func VoprfFinalize(password, state, evaluated, proof, serverPub []byte) ([]byte, error) {
	pp, pn, pfree := cbytes(password)
	defer pfree()
	sp, sn, sfree := cbytes(state)
	defer sfree()
	ep, en, efree := cbytes(evaluated)
	defer efree()
	fp, fn, ffree := cbytes(proof)
	defer ffree()
	kp, kn, kfree := cbytes(serverPub)
	defer kfree()

	var out *C.uint8_t
	var outLen C.size_t
	rc := C.quipu_voprf_finalize(
		(*C.uint8_t)(pp), pn,
		(*C.uint8_t)(sp), sn,
		(*C.uint8_t)(ep), en,
		(*C.uint8_t)(fp), fn,
		(*C.uint8_t)(kp), kn,
		&out, &outLen,
	)
	if err := errorFor(int32(rc)); err != nil {
		return nil, err
	}
	return goBytesFree(out, outLen), nil
}
