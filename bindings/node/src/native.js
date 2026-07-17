import koffi from 'koffi';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const ext = process.platform === 'darwin' ? 'dylib' : process.platform === 'win32' ? 'dll' : 'so';
const libFile = process.platform === 'win32' ? `quipu_capi.${ext}` : `libquipu_capi.${ext}`;

function resolveLib() {
  const candidates = [
    process.env.QUIPU_CAPI_LIB,
    join(here, '..', 'prebuilds', `${process.platform}-${process.arch}`, libFile),
    join(here, '..', '..', '..', 'target', 'release', libFile),
  ].filter(Boolean);
  for (const p of candidates) if (existsSync(p)) return p;
  throw new Error(
    `quipu-capi native library not found. Looked in:\n  ${candidates.join('\n  ')}\n` +
      `Build it with: npm run build`,
  );
}

export { koffi };
export const lib = koffi.load(resolveLib());

// String outputs are declared as `uint8_t **` (not `char **`): koffi auto-copies
// a `char **` to a JS string and discards the pointer, which would leak the
// native allocation. As `uint8_t **` we get the raw pointer, read it safely, and
// free it via quipu_string_free.
export const versionFn = lib.func('const char* quipu_version()');
export const encodeFn = lib.func('int32_t quipu_encode(const uint8_t *data, size_t data_len, const char *passphrase, const uint8_t *pepper, size_t pepper_len, _Out_ uint8_t **out)');
export const decodeFn = lib.func('int32_t quipu_decode(const char *symbols, const char *passphrase, const uint8_t *pepper, size_t pepper_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const encryptStreamFn = lib.func('int32_t quipu_encrypt_stream(const uint8_t *data, size_t data_len, const char *passphrase, const uint8_t *pepper, size_t pepper_len, size_t chunk_size, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const decryptStreamFn = lib.func('int32_t quipu_decrypt_stream(const uint8_t *blob, size_t blob_len, const char *passphrase, const uint8_t *pepper, size_t pepper_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const generateKeypairFn = lib.func('int32_t quipu_generate_keypair(_Out_ uint8_t **pk, _Out_ size_t *pk_len, _Out_ uint8_t **sk, _Out_ size_t *sk_len)');
export const encryptToRecipientFn = lib.func('int32_t quipu_encrypt_to_recipient(const uint8_t *data, size_t data_len, const uint8_t *pk, size_t pk_len, _Out_ uint8_t **out)');
export const decryptAsRecipientFn = lib.func('int32_t quipu_decrypt_as_recipient(const char *symbols, const uint8_t *sk, size_t sk_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const generateSigningKeypairFn = lib.func('int32_t quipu_generate_signing_keypair(_Out_ uint8_t **vk, _Out_ size_t *vk_len, _Out_ uint8_t **sk, _Out_ size_t *sk_len)');
export const signFn = lib.func('int32_t quipu_sign(const uint8_t *data, size_t data_len, const uint8_t *sk, size_t sk_len, _Out_ uint8_t **out)');
export const verifyFn = lib.func('int32_t quipu_verify(const char *symbols, const uint8_t *vk, size_t vk_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const voprfBlindFn = lib.func('int32_t quipu_voprf_blind(const uint8_t *password, size_t password_len, _Out_ uint8_t **state, _Out_ size_t *state_len, _Out_ uint8_t **blinded, _Out_ size_t *blinded_len)');
export const voprfFinalizeFn = lib.func('int32_t quipu_voprf_finalize(const uint8_t *password, size_t password_len, const uint8_t *state, size_t state_len, const uint8_t *evaluated, size_t evaluated_len, const uint8_t *proof, size_t proof_len, const uint8_t *server_pub, size_t server_pub_len, _Out_ uint8_t **out, _Out_ size_t *out_len)');
export const bytesFreeFn = lib.func('void quipu_bytes_free(uint8_t *ptr, size_t len)');
export const stringFreeFn = lib.func('void quipu_string_free(uint8_t *ptr)');
