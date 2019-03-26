#include <stdio.h>
#include <time.h>
#include <string.h>
#include "bip39.h"
#include <sodium.h>

// NOTE: We must override this to implement actual RNG!
void random_buffer(uint8_t *buf, size_t len) {
    if( len > 0 ) {
        randombytes_buf(buf, len);
    }
}

int main(int argc, char **argv)
{
    char *this = argv[0];
    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", this);
        return 1;
    }
    if (sodium_init() == -1) {
        fprintf(stderr, "libsodium init failed! :(\n");
        return 1;
    }
    int strength = 256;
    const char *mnemonic = mnemonic_generate(strength);
    printf("%s\n", mnemonic);
    return 0;
}
