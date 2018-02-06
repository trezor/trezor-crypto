#include <stdio.h>
#include "sha2.h"
#include <stdint.h>
#include <string.h>


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
    return compute_sha256sum(argc, argv);
}