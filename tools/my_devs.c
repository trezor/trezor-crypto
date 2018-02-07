#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sha2.h"

#include "bip32.h"
#include "curves.h"

void generate_shared_key(const char *seed_str) {

    HDNode alice;
    const char* curve_name = SECP256K1_NAME;

    // shared key variables
    int res, key_size;
    uint8_t session_key1[65];



    hdnode_from_seed((const uint8_t *)seed_str, strlen(seed_str), curve_name, &alice);
    hdnode_fill_public_key(&alice);

    printf("Pub key: ");
    for (int i = 0; i < 33; ++i)
    {
    printf("%02x", alice.public_key[i]);
    }
    printf("\n");


    printf("Sec key: ");
    for (int i = 0; i < 32; ++i)
    {
    printf("%02x", alice.private_key[i]);
    }
    printf("\n");

    res = hdnode_get_shared_key(&alice, alice.public_key, session_key1, &key_size);


    printf("Shared key (status: %d, key_size: %d): ", res, key_size);
    for (int i = 0; i < key_size; ++i)
    {
    printf("%02x", session_key1[i]);
    }
    printf("\n");
}



int compute_sha256sum(int argc, char *argv[])
{

    unsigned int i = 0;
    char test[256] = "";

    if (argc >= 2)
    {
        strcpy(test, argv[1]);
    }

    SHA256_CTX ctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Init(&ctx);

    sha256_Update(&ctx, (const uint8_t*) test, strlen(test));
    sha256_Final(&ctx, digest);

    printf("output: \n");
    for(i=0;i<SHA256_DIGEST_LENGTH;i++) {
        printf("%02x", digest[i]);
    }

    printf("\n");

    return 0;
}


int main(int argc, char *argv[]) 
{
    if (argc >= 2)
    {
        generate_shared_key(argv[1]);
    }
    else
    {
        generate_shared_key("");
    }
    return compute_sha256sum(argc, argv);
}