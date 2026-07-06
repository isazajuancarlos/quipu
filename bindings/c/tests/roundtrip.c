/* Links the real libquipu_capi + the generated header and exercises the ABI:
 * a streaming encrypt->decrypt roundtrip and a wrong-passphrase error path. */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "quipu.h"

int main(void) {
    const char *pass = "correct horse battery staple";
    const uint8_t msg[] = "attack at dawn";
    const size_t msg_len = sizeof(msg) - 1; /* drop the trailing NUL */

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    int rc = quipu_encrypt_stream(msg, msg_len, pass, NULL, 0, 0, &blob, &blob_len);
    assert(rc == QUIPU_OK);
    assert(blob != NULL && blob_len > 0);

    uint8_t *out = NULL;
    size_t out_len = 0;
    rc = quipu_decrypt_stream(blob, blob_len, pass, NULL, 0, &out, &out_len);
    assert(rc == QUIPU_OK);
    assert(out_len == msg_len);
    assert(memcmp(out, msg, msg_len) == 0);

    uint8_t *bad = NULL;
    size_t bad_len = 0;
    rc = quipu_decrypt_stream(blob, blob_len, "wrong", NULL, 0, &bad, &bad_len);
    assert(rc == QUIPU_ERR_AUTH);
    assert(bad == NULL);

    quipu_bytes_free(blob, blob_len);
    quipu_bytes_free(out, out_len);
    quipu_bytes_free(NULL, 0); /* no-op */

    printf("C ABI roundtrip OK (%zu bytes, version %s)\n", out_len, quipu_version());
    return 0;
}
