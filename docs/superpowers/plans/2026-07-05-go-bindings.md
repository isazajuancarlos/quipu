# Quipu Go Bindings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Go package (`bindings/go`, module `github.com/isazajuancarlos/quipu/bindings/go`) that consumes the Quipu C ABI via cgo, static-linking `libquipu_capi.a`, exposing an idiomatic `(result, error)` API verified by roundtrip, error, and cross-language interop tests.

**Architecture:** One cgo file (`quipu.go`) holds the `import "C"` preamble, the pointer/copy/free helpers, and the public API; `errors.go` is pure Go (error type, sentinels, status mapping). Inputs are copied to C with `C.CBytes`/`C.CString` (freed via `defer`); outputs are copied out with `C.GoBytes`/`C.GoString` then freed with `quipu_bytes_free`/`quipu_string_free`.

**Tech Stack:** Go ≥ 1.21 with cgo (`CGO_ENABLED=1`), the `quipu-capi` staticlib, a C compiler (`cc`/`gcc`).

## Global Constraints

- **Consumes the C ABI only** — static-links `libquipu_capi.a`; never re-links the Rust core or reimplements crypto.
- **cgo directives (verified):** `CFLAGS: -I${SRCDIR}/../c/include`; `LDFLAGS: ${SRCDIR}/../../target/release/libquipu_capi.a -lpthread -ldl -lm`. Build prerequisite: `cargo build -p quipu-capi --release`.
- **Header types:** string outputs are `char **` (read with `C.GoString`, freed with `quipu_string_free((*C.char))`); byte outputs are `uint8_t **out, size_t *out_len` (read with `C.GoBytes`, freed with `quipu_bytes_free`).
- **Idiomatic** — `[]byte` in/out, `string` for glyph symbols, `(result, error)`; `pepper`/`nil` → `(NULL, 0)`; `ChunkSize` `0` → format default.
- **Errors** — non-`QUIPU_OK` status → an `*Error` sentinel (`ErrAuth`/`ErrKey`/`ErrChunk`/`ErrNullArg`/`ErrInternal`), matchable with `errors.Is`. Codes are coarse/non-oracular: `AUTH` merges decrypt/verify/truncation. `QUIPU_OK` (0) → `nil`.
- **Memory** — copy-out-then-free; `quipu_bytes_free` wipes on free, so no secret residue. Inputs copied with `C.CBytes`/`C.CString`, freed in `defer`, so no Go pointer is retained by C.
- **Fixed key lengths** (asserted in tests): recipient public 1600 / secret 3200; verifying 2624 / signing 64.
- **Concurrency-safe** — the C ABI is stateless; safe to call from many goroutines (verified: 8 concurrent ML-DSA signs, no crash).

## File Structure

- Create: `bindings/go/go.mod` — module path, Go version.
- Create: `bindings/go/quipu.go` — cgo preamble, helpers, public API.
- Create: `bindings/go/errors.go` — `Error`, sentinels, `errorFor`.
- Create: `bindings/go/quipu_test.go` — roundtrip + error tests.
- Create: `bindings/go/interop_test.go` — decrypts Rust-produced QST1 vectors.
- Create: `bindings/go/README.md`.
- Modify: `.github/workflows/ci.yml` — add `go` job.
- Modify: `CHANGELOG.md` — note the Go bindings.

The executor has a portable Go on PATH and `CGO_ENABLED=1`. Every `go` command runs from `bindings/go` and requires `cargo build -p quipu-capi --release` to have produced `target/release/libquipu_capi.a` first.

---

## Task 1: Module skeleton, cgo preamble, helpers, `Version()`, errors

**Files:**
- Create: `bindings/go/go.mod`, `bindings/go/quipu.go`, `bindings/go/errors.go`,
  `bindings/go/quipu_test.go`

**Interfaces:**
- Produces: `Version() string`; helpers `cbytes([]byte) (unsafe.Pointer, C.size_t, func())`,
  `goBytesFree(*C.uint8_t, C.size_t) []byte`, `goStringFree(*C.char) string`;
  `Error`, sentinels `ErrAuth`/`ErrKey`/`ErrChunk`/`ErrNullArg`/`ErrInternal`,
  `errorFor(int32) error`.

- [ ] **Step 1: Create `bindings/go/go.mod`**

```go
module github.com/isazajuancarlos/quipu/bindings/go

go 1.21
```

- [ ] **Step 2: Create `bindings/go/errors.go`**

```go
package quipu

// Error is a Quipu failure with a coarse, non-oracular code.
type Error struct{ Code string }

func (e *Error) Error() string {
	switch e.Code {
	case "AUTH":
		return "quipu: authentication failed"
	case "KEY":
		return "quipu: malformed key or container"
	case "CHUNK":
		return "quipu: chunk size out of range"
	case "NULL_ARG":
		return "quipu: invalid argument"
	default:
		return "quipu: internal error"
	}
}

// Is lets errors.Is match by Code, so errors.Is(err, ErrAuth) works.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Sentinel errors, one per C ABI status. Compare with errors.Is.
var (
	ErrAuth     = &Error{Code: "AUTH"}
	ErrKey      = &Error{Code: "KEY"}
	ErrChunk    = &Error{Code: "CHUNK"}
	ErrNullArg  = &Error{Code: "NULL_ARG"}
	ErrInternal = &Error{Code: "INTERNAL"}
)

// errorFor maps a C status code to an error (nil for QUIPU_OK = 0).
func errorFor(rc int32) error {
	switch rc {
	case 0:
		return nil
	case -1:
		return ErrNullArg
	case -2:
		return ErrAuth
	case -3:
		return ErrKey
	case -4:
		return ErrChunk
	default:
		return ErrInternal
	}
}
```

- [ ] **Step 3: Create `bindings/go/quipu.go`** (preamble + helpers + `Version`)

```go
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
```

- [ ] **Step 4: Create `bindings/go/quipu_test.go`** with the version test

```go
package quipu

import "testing"

func TestVersion(t *testing.T) {
	v := Version()
	if len(v) == 0 {
		t.Fatal("empty version")
	}
}
```

- [ ] **Step 5: Build the native lib and run the test**

Run:
```bash
cargo build -p quipu-capi --release
cd bindings/go && CGO_ENABLED=1 go test -run TestVersion -v ./...
```
Expected: `TestVersion` passes. (`go vet`/build compiles the cgo package, proving the LDFLAGS link.)

Note: Go does not flag unused package-level functions, so `cbytes`/`goBytesFree`/`goStringFree` (used from Task 2 on) compile cleanly now; `unsafe` is used by them, so its import is not unused.

- [ ] **Step 6: Commit**

```bash
git add bindings/go/go.mod bindings/go/errors.go bindings/go/quipu.go bindings/go/quipu_test.go
git commit -m "feat(go): module skeleton, cgo preamble, helpers, Version(), errors"
```

---

## Task 2: Streaming AEAD

**Files:**
- Modify: `bindings/go/quipu.go`, `bindings/go/quipu_test.go`

**Interfaces:**
- Consumes: `cbytes`, `goBytesFree`, `errorFor`.
- Produces: `StreamOptions{Pepper []byte; ChunkSize int}`;
  `EncryptStream(data []byte, passphrase string, opts StreamOptions) ([]byte, error)`;
  `DecryptStream(blob []byte, passphrase string, pepper []byte) ([]byte, error)`.

- [ ] **Step 1: Add to `bindings/go/quipu.go`** (after `goStringFree`)

```go
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
```

- [ ] **Step 2: Add tests to `bindings/go/quipu_test.go`**

Add the imports and tests:

```go
import (
	"bytes"
	"errors"
	"testing"
)

func TestStreamRoundtrip(t *testing.T) {
	msg := []byte("streaming payload for go")
	blob, err := EncryptStream(msg, "pw", StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) == 0 {
		t.Fatal("empty blob")
	}
	back, err := DecryptStream(blob, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatalf("mismatch: %q", back)
	}
}

func TestStreamWithPepper(t *testing.T) {
	msg := []byte("peppered")
	pepper := []byte("spice")
	blob, err := EncryptStream(msg, "pw", StreamOptions{Pepper: pepper})
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecryptStream(blob, "pw", pepper)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("pepper roundtrip mismatch")
	}
}

func TestStreamWrongPassphrase(t *testing.T) {
	blob, err := EncryptStream([]byte("x"), "right", StreamOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptStream(blob, "wrong", nil)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestStreamBadChunkSize(t *testing.T) {
	_, err := EncryptStream([]byte("x"), "pw", StreamOptions{ChunkSize: 64})
	if !errors.Is(err, ErrChunk) {
		t.Fatalf("want ErrChunk, got %v", err)
	}
}
```

Note: the version test's file gains the `import` block; ensure `TestVersion` stays and the single `import "testing"` line is replaced by the grouped import above.

- [ ] **Step 3: Run the tests**

Run: `cd bindings/go && CGO_ENABLED=1 go test -v ./...`
Expected: `TestVersion`, `TestStreamRoundtrip`, `TestStreamWithPepper`, `TestStreamWrongPassphrase`, `TestStreamBadChunkSize` all pass.

- [ ] **Step 4: Commit**

```bash
git add bindings/go/quipu.go bindings/go/quipu_test.go
git commit -m "feat(go): streaming AEAD encrypt/decrypt"
```

---

## Task 3: Symmetric glyph codec

**Files:**
- Modify: `bindings/go/quipu.go`, `bindings/go/quipu_test.go`

**Interfaces:**
- Consumes: `cbytes`, `goBytesFree`, `goStringFree`, `errorFor`.
- Produces: `Encode(data []byte, passphrase string, pepper []byte) (string, error)`;
  `Decode(symbols string, passphrase string, pepper []byte) ([]byte, error)`.

- [ ] **Step 1: Add to `bindings/go/quipu.go`**

```go
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
```

- [ ] **Step 2: Add tests to `bindings/go/quipu_test.go`**

```go
func TestCodecRoundtrip(t *testing.T) {
	msg := []byte("hello glyphs")
	sym, err := Encode(msg, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sym) < 115 {
		t.Fatalf("unexpectedly short symbols: %d", len(sym))
	}
	back, err := Decode(sym, "pw", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("codec roundtrip mismatch")
	}
}

func TestDecodeWrongPassphrase(t *testing.T) {
	sym, err := Encode([]byte("data"), "right", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decode(sym, "wrong", nil)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `cd bindings/go && CGO_ENABLED=1 go test -v ./...`
Expected: all prior tests plus `TestCodecRoundtrip`, `TestDecodeWrongPassphrase` pass.

- [ ] **Step 4: Commit**

```bash
git add bindings/go/quipu.go bindings/go/quipu_test.go
git commit -m "feat(go): symmetric glyph codec Encode/Decode"
```

---

## Task 4: Post-quantum recipient

**Files:**
- Modify: `bindings/go/quipu.go`, `bindings/go/quipu_test.go`

**Interfaces:**
- Consumes: `cbytes`, `goBytesFree`, `goStringFree`, `errorFor`.
- Produces: `GenerateKeypair() (publicKey, secretKey []byte, err error)`;
  `EncryptToRecipient(data []byte, publicKey []byte) (string, error)`;
  `DecryptAsRecipient(symbols string, secretKey []byte) ([]byte, error)`.

- [ ] **Step 1: Add to `bindings/go/quipu.go`**

```go
// GenerateKeypair generates a hybrid post-quantum keypair (X25519 + ML-KEM-1024).
func GenerateKeypair() (publicKey, secretKey []byte, err error) {
	var pk, sk *C.uint8_t
	var pkl, skl C.size_t
	rc := C.quipu_generate_keypair(&pk, &pkl, &sk, &skl)
	if e := errorFor(int32(rc)); e != nil {
		return nil, nil, e
	}
	return goBytesFree(pk, pkl), goBytesFree(sk, skl), nil
}

// EncryptToRecipient encrypts data to a recipient's public key; returns symbols.
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

// DecryptAsRecipient decrypts recipient symbols with the secret key.
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
```

- [ ] **Step 2: Add tests to `bindings/go/quipu_test.go`**

```go
func TestRecipientRoundtrip(t *testing.T) {
	pub, sec, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 1600 || len(sec) != 3200 {
		t.Fatalf("key sizes: %d/%d want 1600/3200", len(pub), len(sec))
	}
	msg := []byte("for your eyes only")
	sym, err := EncryptToRecipient(msg, pub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecryptAsRecipient(sym, sec)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("recipient roundtrip mismatch")
	}
}

func TestRecipientBadKey(t *testing.T) {
	_, err := EncryptToRecipient([]byte("x"), make([]byte, 10))
	if !errors.Is(err, ErrKey) {
		t.Fatalf("want ErrKey, got %v", err)
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `cd bindings/go && CGO_ENABLED=1 go test -v ./...`
Expected: all prior plus `TestRecipientRoundtrip` (sizes 1600/3200), `TestRecipientBadKey` pass.

- [ ] **Step 4: Commit**

```bash
git add bindings/go/quipu.go bindings/go/quipu_test.go
git commit -m "feat(go): post-quantum recipient keypair/encrypt/decrypt"
```

---

## Task 5: Hybrid signature

**Files:**
- Modify: `bindings/go/quipu.go`, `bindings/go/quipu_test.go`

**Interfaces:**
- Consumes: `cbytes`, `goBytesFree`, `goStringFree`, `errorFor`.
- Produces: `GenerateSigningKeypair() (verifyingKey, signingKey []byte, err error)`;
  `Sign(data []byte, signingKey []byte) (string, error)`;
  `Verify(symbols string, verifyingKey []byte) ([]byte, error)`.

- [ ] **Step 1: Add to `bindings/go/quipu.go`**

```go
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
```

- [ ] **Step 2: Add tests to `bindings/go/quipu_test.go`**

```go
func TestSignatureRoundtrip(t *testing.T) {
	vk, sk, err := GenerateSigningKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(vk) != 2624 || len(sk) != 64 {
		t.Fatalf("key sizes: %d/%d want 2624/64", len(vk), len(sk))
	}
	msg := []byte("acta oficial")
	signed, err := Sign(msg, sk)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Verify(signed, vk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, msg) {
		t.Fatal("signature roundtrip mismatch")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, sk, _ := GenerateSigningKeypair()
	vk2, _, _ := GenerateSigningKeypair()
	signed, err := Sign([]byte("m"), sk)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(signed, vk2)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}
```

- [ ] **Step 3: Run the tests**

Run: `cd bindings/go && CGO_ENABLED=1 go test -v ./...`
Expected: all prior plus `TestSignatureRoundtrip` (sizes 2624/64), `TestVerifyWrongKey` pass.

- [ ] **Step 4: Commit**

```bash
git add bindings/go/quipu.go bindings/go/quipu_test.go
git commit -m "feat(go): hybrid signature keypair/sign/verify"
```

---

## Task 6: Cross-language interop test + README

**Files:**
- Create: `bindings/go/interop_test.go`, `bindings/go/README.md`

**Interfaces:**
- Consumes: `DecryptStream`; `../../tests/vectors/quipu_vectors.json`.

- [ ] **Step 1: Create `bindings/go/interop_test.go`**

```go
package quipu

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInteropStreamingVectors(t *testing.T) {
	path := filepath.Join("..", "..", "tests", "vectors", "quipu_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Frozen struct {
			StreamingDecode []struct {
				BlobHex      string `json:"blob_hex"`
				Passphrase   string `json:"passphrase"`
				PepperHex    string `json:"pepper_hex"`
				PlaintextHex string `json:"plaintext_hex"`
				Desc         string `json:"desc"`
			} `json:"streaming_decode"`
		} `json:"frozen"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	cases := doc.Frozen.StreamingDecode
	if len(cases) == 0 {
		t.Fatal("no streaming_decode vectors")
	}
	for _, v := range cases {
		blob, err := hex.DecodeString(v.BlobHex)
		if err != nil {
			t.Fatalf("%s: bad blob hex: %v", v.Desc, err)
		}
		var pepper []byte
		if v.PepperHex != "" {
			pepper, _ = hex.DecodeString(v.PepperHex)
		}
		want, _ := hex.DecodeString(v.PlaintextHex)
		got, err := DecryptStream(blob, v.Passphrase, pepper)
		if err != nil {
			t.Fatalf("%s: %v", v.Desc, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: plaintext mismatch", v.Desc)
		}
	}
}
```

- [ ] **Step 2: Create `bindings/go/README.md`**

```markdown
# Quipu Go bindings

Go bindings for [Quipu](../../README.md) — hybrid post-quantum crypto for data at
rest — over the stable [C ABI](../c) via cgo. Statically links `libquipu_capi.a`,
so a built binary needs no runtime shared library.

## Build

```sh
cargo build -p quipu-capi --release          # produces target/release/libquipu_capi.a
cd bindings/go && CGO_ENABLED=1 go test ./...
```

`CGO_ENABLED=1` and a C compiler (`cc`/`gcc`) are required.

## Usage

```go
import quipu "github.com/isazajuancarlos/quipu/bindings/go"

quipu.Version()

// streaming AEAD
blob, _ := quipu.EncryptStream([]byte("big data"), "passphrase", quipu.StreamOptions{})
plain, _ := quipu.DecryptStream(blob, "passphrase", nil)

// symmetric codec (glyph symbols)
sym, _ := quipu.Encode([]byte("secret"), "passphrase", nil)
back, _ := quipu.Decode(sym, "passphrase", nil)

// post-quantum recipient
pub, sec, _ := quipu.GenerateKeypair()
c, _ := quipu.EncryptToRecipient([]byte("m"), pub)
quipu.DecryptAsRecipient(c, sec)

// hybrid signature
vk, sk, _ := quipu.GenerateSigningKeypair()
signed, _ := quipu.Sign([]byte("acta"), sk)
if _, err := quipu.Verify(signed, vk); err != nil { /* tampered */ }
```

## Contract

- Functions return `(result, error)`. Failures are `*quipu.Error` sentinels,
  matchable with `errors.Is(err, quipu.ErrAuth)` (codes `AUTH`, `KEY`, `CHUNK`,
  `NULL_ARG`, `INTERNAL`; coarse and non-oracular, like the C ABI).
- Calls are synchronous and block only the calling goroutine — run them in
  goroutines for concurrency. The C ABI is stateless and safe to call from many
  goroutines at once.
- `pepper` may be `nil`. The native side wipes its output buffers on free, so
  secrets leave no residue; zero your own `[]byte`s when done.
```

- [ ] **Step 3: Run the full suite**

Run: `cd bindings/go && CGO_ENABLED=1 go test -v ./...`
Expected: every test passes, including `TestInteropStreamingVectors` decrypting the Rust-produced QST1 vectors.

- [ ] **Step 4: Commit**

```bash
git add bindings/go/interop_test.go bindings/go/README.md
git commit -m "test(go): cross-language interop vectors + README"
```

---

## Task 7: CI job and CHANGELOG

**Files:**
- Modify: `.github/workflows/ci.yml`, `CHANGELOG.md`

**Interfaces:**
- Consumes: everything from Tasks 1–6.

- [ ] **Step 1: Add the `go` job to `.github/workflows/ci.yml`**

Append under the `jobs:` map (two-space indentation, matching existing jobs):

```yaml
  go:
    name: Go bindings (bindings/go)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - uses: actions/setup-go@v5
        with:
          go-version: "1.23"
      - name: Build native staticlib
        run: cargo build -p quipu-capi --release
      - name: Test
        working-directory: bindings/go
        run: CGO_ENABLED=1 go test -v ./...
```

- [ ] **Step 2: Validate the workflow YAML**

Run: `python3 -c "import yaml; d=yaml.safe_load(open('.github/workflows/ci.yml')); print('OK', list(d['jobs']))"`
Expected: `OK [...]` including `go`.

- [ ] **Step 3: Note the Go bindings in `CHANGELOG.md`**

Under `[Unreleased]` → `### Added`, append:

```markdown
- **Go bindings** (`bindings/go`, module `github.com/isazajuancarlos/quipu/bindings/go`):
  an idiomatic `(result, error)` API over the C ABI via cgo, static-linking
  `libquipu_capi.a` — symmetric codec, streaming AEAD, post-quantum recipient, and
  hybrid signature. Errors are `*quipu.Error` sentinels (`errors.Is`-matchable). A
  `testing` suite includes a **cross-language interop** test that decrypts
  Rust-produced QST1 vectors. Unlike the Node bindings, no async workaround is
  needed: cgo runs on the goroutine system stack, so ML-DSA-87 has room and calls
  are concurrency-safe. New `go` CI job.
```

And update the `### Planned` line to drop Go:

```markdown
- A non-blocking `worker_threads` wrapper for the Node.js bindings; publishing the
  Node (`quipu-crypto`) and Go modules; macOS/Windows prebuilds + CI matrix.
```

- [ ] **Step 4: Full check**

Run:
```bash
cargo build -p quipu-capi --release
cd bindings/go && CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test ./...
```
Expected: `go vet` clean; all tests pass.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml CHANGELOG.md
git commit -m "ci(go): Go bindings job + changelog"
```

---

## Self-Review Notes

- **Spec coverage:** §2 (no async trap) → verified in the spike and reflected in the sync `(result, error)` API + README; §3 linking → Task 1 cgo directives (LDFLAGS verified); §4 layout → Tasks 1–6; §5 memory (copy-out-then-free, `C.CBytes`/`C.CString` inputs) → Task 1 helpers used throughout; §6 errors → Task 1 `errors.go`; §7 API (11 funcs + `Version`) → Tasks 1–5; §8 tests → Tasks 2–6; §9 CI → Task 7. All spec sections map to a task.
- **Verified mechanics:** the cgo LDFLAGS, `char**`/`GoString`/`quipu_string_free` string path, `uint8_t**`+`GoBytes`+`quipu_bytes_free` byte path, keypair, and ML-DSA sign/verify (incl. 8 concurrent goroutines, no crash) were all validated against the real `libquipu_capi.a` before writing this plan.
- **Type consistency:** helper names (`cbytes`, `goBytesFree`, `goStringFree`, `errorFor`) and sentinels (`ErrAuth`/`ErrKey`/`ErrChunk`/`ErrNullArg`/`ErrInternal`) are defined once (Task 1) and consumed unchanged; public function names match the spec's §7 exactly.
- **Import note:** Task 2 replaces Task 1's single `import "testing"` in `quipu_test.go` with a grouped import (`bytes`, `errors`, `testing`); later tasks add no new imports there. `interop_test.go` (Task 6) is a separate file with its own imports.
```
