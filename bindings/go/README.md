# Quipu Go bindings

Go bindings for [Quipu](../../README.md) — hybrid post-quantum crypto for data at
rest — over the stable [C ABI](../c) via cgo. Statically links `libquipu_capi.a`,
so a built binary needs no runtime shared library.

## Install

The module is versioned and go-gettable at:

```sh
go get github.com/isazajuancarlos/quipu/bindings/go@v0.9.1
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

// VOPRF online hardening (talks to a quipu-oprf-server)
secret, err := quipu.OprfHarden(
    "https://oprf.tudominio.com",
    "quipu_live_...",
    []byte("user password"),
    pub, // pinned server public key (32 B) — required
)
// `secret` is a rate-limited, quantum-safe hardened key.
```

The pinned key is **required**, and is never fetched from the server: one that
supplies the key it is checked against cannot be checked at all. Get it once
with `curl <baseURL>/v1/public-key` and ship it as config.

Two failures, opposite reactions — never collapse them (match with `errors.Is`):

| Error | Means | Do |
|---|---|---|
| `ErrOprfUnavailable` | no answer, timeout, 5xx, or the API key was refused | retry, or fail closed |
| `ErrOprfRejected` | the DLEQ proof failed against your pinned key | **investigate.** Never retry blindly |

Neither ever falls back to the unhardened password: that would hide the loss of
the guarantee at the exact moment it matters. Requests time out after
`DefaultOprfTimeout` (5 s); use `OprfHardenTimeout` to change it. Note
`http.DefaultClient` has no timeout at all, which is why this does not use it.

See [`integrations/go`](../../integrations/go) to wire this into an app's
signup/login.

`VoprfBlind` / `VoprfFinalize` expose the low-level primitives if you drive the
HTTP yourself. See [the server](../../crates/quipu-oprf-server) for how to run one.

## Contract

- Functions return `(result, error)`. Failures are `*quipu.Error` sentinels,
  matchable with `errors.Is(err, quipu.ErrAuth)` (codes `AUTH`, `KEY`, `CHUNK`,
  `NULL_ARG`, `INTERNAL`; coarse and non-oracular, like the C ABI).
- Calls are synchronous and block only the calling goroutine — run them in
  goroutines for concurrency. The C ABI is stateless and safe to call from many
  goroutines at once.
- `pepper` may be `nil`. The native side wipes its output buffers on free, so
  secrets leave no residue; zero your own `[]byte`s when done.
