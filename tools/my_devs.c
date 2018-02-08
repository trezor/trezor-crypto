#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sha2.h"

#include "bip32.h"
#include "curves.h"

#include "bignum.h"

void compute_sha256sum(const char *seed, uint8_t* digest /*size SHA256_DIGEST_LENGTH*/, size_t seed_lenght);

void generate_shared_key(const char *seed_str) {

    HDNode alice;
    const char* curve_name = SECP256K1_NAME;

    // shared key variables
    int res, key_size;
    uint8_t session_key1[65] = {0};



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


    printf("Shared key (status: %d, key_size: %d): \n", res, key_size);
    for (int i = 0; i < key_size; ++i)
    {
        printf("%02x", session_key1[i]);
    }

    bignum256 bigshared;
    bn_read_be(session_key1, &bigshared);
    printf("\nbignum sharedkey : \n");
    bn_print(&bigshared);
    printf("\ncurve prime : \n");
    bn_print(&alice.curve->params->order);

    printf("\nbignum sharedkey after mod : \n");
    bn_fast_mod(&bigshared, &alice.curve->params->order);
    bn_print(&bigshared);
    printf("\n");

    uint8_t digest[SHA256_DIGEST_LENGTH]= {0};
    compute_sha256sum((const char*) session_key1, digest, sizeof(session_key1));
    
    printf("\nSha256 of output: \n");
    for(uint i=0;i<SHA256_DIGEST_LENGTH;i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}



void compute_sha256sum(const char *seed, uint8_t* digest /*size SHA256_DIGEST_LENGTH*/, size_t seed_lenght)
{
    SHA256_CTX ctx;
    sha256_Init(&ctx);

    printf("Len seed: %lu\n", seed_lenght);
    sha256_Update(&ctx, (const uint8_t*) seed, seed_lenght);
    sha256_Final(&ctx, digest);
}


int main(int argc, char *argv[]) 
{
    char seed[256] = "";

    if (argc >= 2)
    {
        strcpy(seed, argv[1]);
    }

    generate_shared_key(seed);


    uint8_t digest[SHA256_DIGEST_LENGTH]= {0};
    compute_sha256sum(seed, digest, strlen(seed));

    printf("Sha256: \n");
    for(uint i=0;i<SHA256_DIGEST_LENGTH;i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");

    return 0;
}