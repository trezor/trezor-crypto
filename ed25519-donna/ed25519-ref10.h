#ifndef ED25519_REF10_H
#define ED25519_REF10_H

#include "ed25519-donna.h"

typedef unsigned char ed25519_keypair_public_key[32];
typedef unsigned char ed25519_keypair_secret_key[64];

typedef uint32_t fe[10];

void ge25519_scalarmult_base(ge25519_p3 *, const unsigned char *);
void ge25519_p3_tobytes(unsigned char *,const ge25519_p3 *);
#endif // ED25519_REF10_H