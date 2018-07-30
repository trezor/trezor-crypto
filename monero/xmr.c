//
// Created by Dusan Klinec on 10/05/2018.
//

#include "xmr.h"
#include "int-util.h"
#include "serialize.h"
#include "rand.h"


const ge25519 ALIGN(16) xmr_h = {
		{0x1861ec7, 0x1ceac77, 0x2f11626, 0x1f261d3, 0x346107c, 0x06d8c4a, 0x254201d, 0x1675c09, 0x1301c3f, 0x0211d73},
		{0x326feb4, 0x12e30cc, 0x0cf54b4, 0x1117305, 0x318f5d5, 0x06cf754, 0x2e578a1, 0x1daf058, 0x34430a1, 0x04410e9},
		{0x0fde4d2, 0x0774049, 0x22ca951, 0x05aec2b, 0x07a36a5, 0x1394f13, 0x3c5385c, 0x1adb924, 0x2b6c581, 0x0a55fa4},
		{0x24517f7, 0x05ee936, 0x3acf5d9, 0x14b08aa, 0x3363738, 0x1051745, 0x360601e, 0x0f3f2c9, 0x1ead2cd, 0x1d3e3df}
};


void ge25519_set_xmr_h(ge25519 *r){
	ge25519_copy(r, &xmr_h);
}

void xmr_random_scalar(bignum256modm m){
	unsigned char buff[32]={0};
	random_buffer(buff, sizeof(buff));
	expand256_modm(m, buff, sizeof(buff));
}

void xmr_fast_hash(uint8_t * hash, const void *data, size_t length){
	hasher_Raw(HASHER_SHA3K, data, length, hash);
}

void xmr_hasher_init(Hasher * hasher){
	hasher_Init(hasher, HASHER_SHA3K);
}

void xmr_hasher_update(Hasher * hasher, const void *data, size_t length){
	hasher_Update(hasher, data, length);
}

void xmr_hasher_final(Hasher * hasher, uint8_t * hash){
	hasher_Final(hasher, hash);
}

void xmr_hasher_copy(Hasher * dst, const Hasher * src){
	memcpy(dst, src, sizeof(Hasher));
}

void xmr_hash_to_scalar(bignum256modm r, const void *data, size_t length){
	uint8_t hash[HASHER_DIGEST_LENGTH];
	hasher_Raw(HASHER_SHA3K, data, length, hash);
	expand256_modm(r, hash, HASHER_DIGEST_LENGTH);
}

void xmr_hash_to_ec(ge25519 *P, const void *data, size_t length){
	ge25519 point2;
	uint8_t hash[HASHER_DIGEST_LENGTH];
	hasher_Raw(HASHER_SHA3K, data, length, hash);

	ge25519_fromfe_frombytes_vartime(&point2, hash);
	ge25519_mul8(P, &point2);
}

void xmr_derivation_to_scalar(bignum256modm s, const ge25519 * p, uint32_t output_index){
	uint8_t buff[32 + 8];
	ge25519_pack(buff, p);
	int written = xmr_write_varint(buff + 32, 8, output_index);
	xmr_hash_to_scalar(s, buff, 32u + written);
}

void xmr_generate_key_derivation(ge25519 * r, const ge25519 * A, const bignum256modm b){
	ge25519 bA;
	ge25519_scalarmult(&bA, A, b);
	ge25519_norm(&bA, &bA);
	ge25519_mul8(r, &bA);
}

void xmr_derive_private_key(bignum256modm s, const ge25519 * deriv, uint32_t idx, const bignum256modm base){
	xmr_derivation_to_scalar(s, deriv, idx);
	add256_modm(s, s, base);
}

void xmr_derive_public_key(ge25519 * r, const ge25519 * deriv, uint32_t idx, const ge25519 * base){
	bignum256modm s={0};
	ge25519 p2;
	ge25519_pniels Bp;
	ge25519_p1p1 p1;

	xmr_derivation_to_scalar(s, deriv, idx);
	ge25519_scalarmult_base_niels(&p2, ge25519_niels_base_multiples, s);
	ge25519_norm(&p2, &p2);

	ge25519_full_to_pniels(&Bp, base);
	ge25519_pnielsadd_p1p1(&p1, &p2, &Bp, 0);
	ge25519_p1p1_to_full(r, &p1);
}

void xmr_add_keys2(ge25519 * r, const bignum256modm a, const bignum256modm b, const ge25519 * B){
	// aG + bB, G is basepoint
	ge25519 aG, bB;
	ge25519_pniels bBn;
	ge25519_p1p1 p1;
	ge25519_scalarmult_base_niels(&aG, ge25519_niels_base_multiples, a);
	ge25519_scalarmult(&bB, B, b);
	ge25519_norm(&bB, &bB);
	ge25519_norm(&aG, &aG);

	ge25519_full_to_pniels(&bBn, &bB);
	ge25519_pnielsadd_p1p1(&p1, &aG, &bBn, 0);
	ge25519_p1p1_to_full(r, &p1);
}

void xmr_add_keys2_vartime(ge25519 * r, const bignum256modm a, const bignum256modm b, const ge25519 * B){
	// aG + bB, G is basepoint
	ge25519_double_scalarmult_vartime(r, B, b, a);
	ge25519_norm(r, r);
}

void xmr_add_keys3(ge25519 * r, const bignum256modm a, const ge25519 * A, const bignum256modm b, const ge25519 * B){
	// aA + bB
	ge25519 aA, bB;
	ge25519_pniels bBn;
	ge25519_p1p1 p1;
	ge25519_scalarmult(&aA, A, a);
	ge25519_scalarmult(&bB, B, b);
	ge25519_norm(&bB, &bB);
	ge25519_norm(&aA, &aA);

	ge25519_full_to_pniels(&bBn, &bB);
	ge25519_pnielsadd_p1p1(&p1, &aA, &bBn, 0);
	ge25519_p1p1_to_full(r, &p1);
}

void xmr_add_keys3_vartime(ge25519 * r, const bignum256modm a, const ge25519 * A, const bignum256modm b, const ge25519 * B){
	// aA + bB
	ge25519_double_scalarmult_vartime2(r, A, a, B, b);
	ge25519_norm(r, r);
}

void xmr_get_subaddress_secret_key(bignum256modm r, uint32_t major, uint32_t minor, const bignum256modm m){
	const char prefix[] = "SubAddr";
	unsigned char buff[32];
	contract256_modm(buff, m);

	char data[sizeof(prefix) + sizeof(buff) + 2 * sizeof(uint32_t)];
	memcpy(data, prefix, sizeof(prefix));
	memcpy(data + sizeof(prefix), buff, sizeof(buff));
	uint32_t idx = SWAP32LE(major);
	memcpy(data + sizeof(prefix) + sizeof(buff), &idx, sizeof(uint32_t));
	idx = SWAP32LE(minor);
	memcpy(data + sizeof(prefix) + sizeof(buff) + sizeof(uint32_t), &idx, sizeof(uint32_t));

	xmr_hash_to_scalar(r, data, sizeof(data));
}

void xmr_gen_c(ge25519 * r, const bignum256modm a, uint64_t amount){
	// C = aG + bH
	bignum256modm b={0};
	set256_modm(b, amount);
	xmr_add_keys2(r, a, b, &xmr_h);
}
