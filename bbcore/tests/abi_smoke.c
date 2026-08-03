#include <bbcore/bbcore.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int main(void)
{
    static const uint8_t input[] = {0x00, 0x01, 0x02};
    char encoded[16] = {0};
    size_t encoded_len = 0;

    if (bb_init() != BB_OK) {
        return 1;
    }
    if (bb_version() == NULL || strstr(bb_version(), "bbcore") == NULL) {
        return 2;
    }
    if (bb_base32_encode(input, sizeof input, encoded, sizeof encoded, &encoded_len) != BB_OK) {
        return 3;
    }
    if (encoded_len != 5 || memcmp(encoded, "aaaqe", 5) != 0) {
        return 4;
    }
    if (bb_mnemonic_new(12, encoded, sizeof encoded, &encoded_len) != BB_ERR_INVALID_ARG) {
        return 5;
    }
    {
        const char *mnemonic =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        bb_identity *identity = NULL;
        uint8_t state[128] = {0};
        size_t state_len = 0;
        if (bb_identity_open(mnemonic, "", 0, &identity) != BB_OK || identity == NULL) {
            return 6;
        }
        if (bb_identity_state_seal(identity, input, sizeof input,
                                   state, sizeof state, &state_len) != BB_OK) {
            bb_identity_free(identity);
            return 7;
        }
        bb_identity_free(identity);
    }
    return 0;
}
