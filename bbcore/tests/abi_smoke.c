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
    return 0;
}

