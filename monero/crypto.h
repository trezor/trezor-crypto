//
// Created by Dusan Klinec on 29/04/2018.
//

#ifndef TREZOR_XMR_CRYPTO_H
#define TREZOR_XMR_CRYPTO_H

#include <stddef.h>
#include <ed25519-donna/ed25519-donna.h>
#include <hasher.h>

/* 64bit uint to scalar value */
void set256_modm(bignum256modm r, uint64_t v);

/* scalar value to 64bit uint */
int get256_modm(uint64_t * v, const bignum256modm r);

/* equality test on two reduced scalar values */
int eq256_modm(const bignum256modm x, const bignum256modm y);

/* comparison of two reduced scalar values */
int cmp256_modm(const bignum256modm x, const bignum256modm y);

/* scalar null check, has to be reduced */
int iszero256_modm(const bignum256modm x);

/* simple copy, no reduction */
void copy256_modm(bignum256modm r, const bignum256modm x);

/* check if nonzero && same after reduction */
int check256_modm(const bignum256modm x);

/* (cc - aa * bb) % l */
void mulsub256_modm(bignum256modm r, const bignum256modm a, const bignum256modm b, const bignum256modm c);

/* (cc + aa * bb) % l */
void muladd256_modm(bignum256modm r, const bignum256modm a, const bignum256modm b, const bignum256modm c);

/* uint32_t to Zmod(2^255-19) */
void curve25519_set(bignum25519 r, uint32_t x);

/* set d */
void curve25519_set_d(bignum25519 r);

/* set 2d */
void curve25519_set_2d(bignum25519 r);

/* set sqrt(-1) */
void curve25519_set_sqrtneg1(bignum25519 r);

/* constant time Zmod(2^255-19) negative test */
int curve25519_isnegative(const bignum25519 f);

/* constant time Zmod(2^255-19) non-zero test */
int curve25519_isnonzero(const bignum25519 f);

/* reduce Zmod(2^255-19) */
void curve25519_reduce(bignum25519 r, const bignum25519 in);

/* Zmod(2^255-19) from byte array to bignum25519 expansion with modular reduction */
void curve25519_expand_reduce(bignum25519 out, const unsigned char in[32]);

/* check if r is on curve */
int ge25519_check(const ge25519 *r);

/* a == b */
int ge25519_eq(const ge25519 *a, const ge25519 *b);

/* copies one point to another */
void ge25519_copy(ge25519 *dst, const ge25519 *src);

/* sets B point to r */
void ge25519_set_base(ge25519 *r);

/* 8*P */
void ge25519_mul8(ge25519 *r, const ge25519 *t);

/* -P */
void ge25519_neg_partial(ge25519 *r);

/* -P */
void ge25519_neg_full(ge25519 *r);

/* reduce all coords */
void ge25519_reduce(ge25519 *r, const ge25519 *t);

/* normalizes coords. (x, y, 1, x*y) */
void ge25519_norm(ge25519 *r, const ge25519 * t);

/* Simple addition */
void ge25519_add(ge25519 *r, const ge25519 *a, const ge25519 *b, unsigned char signbit);

/* point from bytes, used in H_p() */
void ge25519_fromfe_frombytes_vartime(ge25519 *r, const unsigned char *s);

/* point from bytes */
int ge25519_unpack_vartime(ge25519 *r, const unsigned char *s);

/* aG, wrapper for niels base mult. */
void ge25519_scalarmult_base_wrapper(ge25519 *r, const bignum256modm s);

/* aP, wrapper. General purpose, normalizes after multiplication */
void ge25519_scalarmult_wrapper(ge25519 *r, const ge25519 *P, const bignum256modm a);


#endif //TREZOR_XMR_CRYPTO_H
