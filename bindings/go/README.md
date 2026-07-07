# Quipu Go bindings

Go bindings for [Quipu](../../README.md) — hybrid post-quantum crypto for data at
rest — over the stable [C ABI](../c) via cgo. Statically links `libquipu_capi.a`,
so a built binary needs no runtime shared library.

## Install

The module is versioned and go-gettable at:

```sh
go get github.com/isazajuancarlos/quipu/bindings/go@v0.7.0
```

> **Note:** linking currently requires a repo checkout. The cgo directives link
> `${SRCDIR}/../../target/release/libquipu_capi.a` and include `../c/include`,
> which live outside the Go module, so a stand-alone `go build` won't link yet —
> you must build the static lib from the repo first (see below). A self-contained
> module with vendored/prebuilt libs is a planned follow-up.

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
