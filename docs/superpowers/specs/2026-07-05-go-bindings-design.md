# Quipu Go Bindings — Design

**Date:** 2026-07-05
**Status:** Design for review, then implementation
**Scope:** A Go package that consumes the Quipu **C ABI** (`quipu-capi` /
`bindings/c/include/quipu.h`) via cgo, exposing an idiomatic Go API. Builds on
the C ABI (PR #20); a sibling of the Node bindings (PR #21).

## 1 · Goal & non-goals

**Goal.** Let Go programs use Quipu's data-at-rest crypto through an idiomatic,
statically-linked cgo binding *over the C ABI* — not by re-linking the Rust core
directly, not by reimplementing crypto. The binding must be:

- **Idiomatic** — `[]byte` in/out, `string` for glyph symbols, the `(result,
  error)` pattern, sentinel errors usable with `errors.Is`.
- **Self-contained** — static-links `libquipu_capi.a`, so a built Go binary needs
  no runtime shared library.
- **Concurrency-safe** — the C ABI is stateless and thread-safe, so the package
  is safe to call from multiple goroutines.
- **Interoperable** — proven to decrypt a container produced by the Rust core,
  using the shared interop vectors.

**Non-goals (v1).**

- No dynamic linking (static is idiomatic for Go and yields a self-contained
  binary).
- No macOS/Windows CI matrix (Linux only in v1, mirroring the C/Node bindings;
  the code stays platform-neutral where practical).
- No module publish/tag in this iteration.
- No KDF-cost tuning knobs (mirrors the C ABI, which uses the format defaults).

## 2 · Why Go avoids the Node async trap

The Node bindings had to ship synchronous because koffi's async path runs on a
small-stack libuv worker where the core's ML-DSA-87 operations overflow and
SIGSEGV. **This does not apply to Go.** A cgo call runs on the calling
goroutine's system stack (large), so ML-DSA has room. And a cgo call blocks only
its own goroutine — other goroutines keep running on other OS threads — so a
plain synchronous `(result, error)` API is already non-blocking at the program
level. No async wrapper is needed; concurrency is the caller's to compose with
goroutines. This is a genuine advantage of the Go/cgo model over Node/koffi here.

## 3 · Linking (cgo)

The package statically links the Rust `staticlib`:

```go
/*
#cgo CFLAGS: -I${SRCDIR}/../c/include
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libquipu_capi.a -lpthread -ldl -lm
#include "quipu.h"
#include <stdlib.h>
*/
import "C"
```

- `CFLAGS` points cgo at the checked-in `quipu.h`.
- `LDFLAGS` names the `.a` by full path (so the linker takes the static archive,
  not the sibling `.so`) plus the system libraries the Rust std needs. The exact
  system-library list is finalized against the real linker during implementation
  (a build detail); `pthread`/`dl`/`m` is the expected baseline on Linux.
- A prerequisite build step runs `cargo build -p quipu-capi --release` to produce
  `target/release/libquipu_capi.a`.

## 4 · Package layout

```
quipu/
└── bindings/
    └── go/                     # module github.com/isazajuancarlos/quipu/bindings/go
        ├── go.mod
        ├── quipu.go            # cgo directives + public API + the pointer/free helpers
        ├── errors.go           # Error type + sentinels + status mapping
        ├── quipu_test.go       # roundtrip + error tests
        ├── interop_test.go     # decrypts Rust-produced QST1 vectors
        └── README.md
```

The cgo surface and the pointer/free helpers live together in `quipu.go`
(cgo requires the `import "C"` preamble in each file that uses C directly; the
package keeps the raw calls in one file). Error mapping is isolated in
`errors.go`.

## 5 · Memory ownership

The library allocates outputs; the wrapper copies them into Go values and frees
the native buffer. Callers never see an `unsafe.Pointer`.

- Byte outputs: `C.quipu_*` writes `out (**C.uint8_t)` and `outLen (*C.size_t)`;
  the helper does `C.GoBytes(unsafe.Pointer(out), C.int(outLen))` (a copy), then
  `C.quipu_bytes_free(out, outLen)`.
- String outputs: `C.GoString((*C.char)(unsafe.Pointer(out)))` (a copy), then
  `C.quipu_string_free(out)`.
- Inputs: Go `[]byte`/`string` are passed via `C.CBytes`/`C.CString` (freed with
  `C.free` after the call) or, for read-only slices, a pinned pointer to the
  slice data. The implementation uses `C.CBytes`/`C.CString` for clarity and
  safety, freeing them in `defer`.

Because `quipu_bytes_free` wipes before releasing, secret keys and decrypted
plaintext leave no native residue once copied out. On any non-`QUIPU_OK` status
the C ABI writes no output pointer, so the helper reads/frees nothing and returns
the error instead.

## 6 · Error handling (`errors.go`)

```go
type Error struct { Code string } // Code ∈ {"AUTH","KEY","CHUNK","NULL_ARG","INTERNAL"}
func (e *Error) Error() string

var (
    ErrAuth     = &Error{Code: "AUTH"}
    ErrKey      = &Error{Code: "KEY"}
    ErrChunk    = &Error{Code: "CHUNK"}
    ErrNullArg  = &Error{Code: "NULL_ARG"}
    ErrInternal = &Error{Code: "INTERNAL"}
)
```

`errorFor(rc C.int) error` maps a non-zero status to the matching sentinel (`0` →
`nil`). `(*Error).Is` returns true when the target has the same `Code`, so
`errors.Is(err, quipu.ErrAuth)` works. Codes stay coarse and non-oracular, like
the C ABI: `AUTH` merges decrypt failure, bad signature, and truncation.

## 7 · Public API (`quipu.go`)

```go
func Version() string

func Encode(data []byte, passphrase string, pepper []byte) (string, error)
func Decode(symbols string, passphrase string, pepper []byte) ([]byte, error)

type StreamOptions struct { Pepper []byte; ChunkSize int }
func EncryptStream(data []byte, passphrase string, opts StreamOptions) ([]byte, error)
func DecryptStream(blob []byte, passphrase string, pepper []byte) ([]byte, error)

func GenerateKeypair() (publicKey, secretKey []byte, err error)
func EncryptToRecipient(data []byte, publicKey []byte) (string, error)
func DecryptAsRecipient(symbols string, secretKey []byte) ([]byte, error)

func GenerateSigningKeypair() (verifyingKey, signingKey []byte, err error)
func Sign(data []byte, signingKey []byte) (string, error)
func Verify(symbols string, verifyingKey []byte) ([]byte, error)
```

Notes: `pepper` may be `nil` → `(NULL, 0)` at the boundary; `ChunkSize` `0` →
format default (non-zero outside 4 KiB–16 MiB → `ErrChunk`); `Version()` is a
cheap call returning the static C string. Key lengths are fixed by the core
(recipient public 1600 / secret 3200; verifying 2624 / signing 64) and asserted
in tests.

## 8 · Testing (`testing`, stdlib only)

- **`quipu_test.go`** — roundtrip for all four modes; asserts plaintext equality
  and the fixed key sizes; wrong passphrase → `errors.Is(err, ErrAuth)`;
  out-of-range `ChunkSize` → `ErrChunk`; wrong-length recipient key → `ErrKey`;
  verify with a different key → `ErrAuth`.
- **`interop_test.go`** — reads `../../tests/vectors/quipu_vectors.json`, takes
  `frozen.streaming_decode`, calls `DecryptStream(blobFromHex, passphrase,
  pepper)`, and asserts the plaintext. Proves the format contract holds across
  languages through the C ABI.

## 9 · CI

New **`go`** job in `.github/workflows/ci.yml` (Linux): checkout →
`dtolnay/rust-toolchain@stable` → `actions/setup-go` → `cargo build -p
quipu-capi --release` → `cd bindings/go && go test ./...`. macOS/Windows matrix
is a follow-up.

## 10 · Risks & mitigations

- **Static-link symbol/library gaps.** → Full-path `.a` in `LDFLAGS`; the exact
  system-lib set is nailed against the real linker in the first task and pinned.
- **Pointer/free correctness.** → Confined to the `quipu.go` helpers; every
  mode's roundtrip test exercises copy-then-free; error paths never touch
  pointers (C ABI writes only on success).
- **cgo input lifetime.** → Inputs are copied with `C.CBytes`/`C.CString` and
  freed in `defer`, so no Go pointer is retained by C across the call.
- **Interop drift.** → `interop_test.go` fails if Go and the Rust vectors
  disagree.

## 11 · Deliverables checklist (for the implementation plan)

- [ ] `bindings/go/go.mod` + module path.
- [ ] `quipu.go`: cgo directives, pointer/free helpers, the 13-symbol API.
- [ ] `errors.go`: `Error`, sentinels, `errorFor`, `Is`.
- [ ] `quipu_test.go` (roundtrip + errors) and `interop_test.go`.
- [ ] `go` CI job (Linux).
- [ ] `bindings/go/README.md`; CHANGELOG note.
- [ ] Update `quipu-roadmap-status` memory (Go done).

## 12 · Follow-ups (out of scope here)

Module tag/publish; macOS/Windows prebuilds + CI matrix; a `cgo`-free pure-Go
option is explicitly rejected (would reimplement crypto).
