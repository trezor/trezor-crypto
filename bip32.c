/**
 * Copyright (c) 2013-2016 Tomas Dzetkulic
 * Copyright (c) 2013-2016 Pavol Rusnak
 * Copyright (c) 2015-2016 Jochen Hoenicke
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include <stdbool.h>

#include "aes/aes.h"
#include "address.h"
#include "bignum.h"
#include "hmac.h"
#include "ecdsa.h"
#include "bip32.h"
#include "sha2.h"
#include "sha3.h"
#include "base58.h"
#include "curves.h"
#include "secp256k1.h"
#include "nist256p1.h"
#include "ed25519-donna/ed25519.h"
#include "ed25519-donna/ed25519-sha3.h"
#if USE_KECCAK
#include "ed25519-donna/ed25519-keccak.h"
#endif
#if USE_NEM
#include "nem.h"
#endif
#if USE_CARDANO
#include "pbkdf2.h"
#endif
#include "memzero.h"
#if USE_HYCON
#include <stdio.h>
#include <openssl/aes.h>
#include "base58.h"
#include "blake2b.h"
#include "address.h"
#include "rand.h"
#include "protob/hyconTx.pb-c.h"
#endif

const curve_info ed25519_info = {
	.bip32_name = "ed25519 seed",
	.params = NULL,
	.hasher_base58 = HASHER_SHA2D,
	.hasher_sign = HASHER_SHA2D,
	.hasher_pubkey = HASHER_SHA2_RIPEMD,
	.hasher_script = HASHER_SHA2,
};

const curve_info ed25519_cardano_info = {
	.bip32_name = "ed25519 cardano seed",
	.params = NULL,
	.hasher_base58 = HASHER_SHA2D,
	.hasher_sign = HASHER_SHA2D,
	.hasher_pubkey = HASHER_SHA2_RIPEMD,
	.hasher_script = HASHER_SHA2,
};

const curve_info ed25519_sha3_info = {
	.bip32_name = "ed25519-sha3 seed",
	.params = NULL,
	.hasher_base58 = HASHER_SHA2D,
	.hasher_sign = HASHER_SHA2D,
	.hasher_pubkey = HASHER_SHA2_RIPEMD,
	.hasher_script = HASHER_SHA2,
};

#if USE_KECCAK
const curve_info ed25519_keccak_info = {
	.bip32_name = "ed25519-keccak seed",
	.params = NULL,
	.hasher_base58 = HASHER_SHA2D,
	.hasher_sign = HASHER_SHA2D,
	.hasher_pubkey = HASHER_SHA2_RIPEMD,
	.hasher_script = HASHER_SHA2,
};
#endif

const curve_info curve25519_info = {
	.bip32_name = "curve25519 seed",
	.params = NULL,
	.hasher_base58 = HASHER_SHA2D,
	.hasher_sign = HASHER_SHA2D,
	.hasher_pubkey = HASHER_SHA2_RIPEMD,
	.hasher_script = HASHER_SHA2,
};

int hdnode_from_xpub(uint32_t depth, uint32_t child_num, const uint8_t *chain_code, const uint8_t *public_key, const char* curve, HDNode *out)
{
	const curve_info *info = get_curve_by_name(curve);
	if (info == 0) {
		return 0;
	}
	if (public_key[0] != 0x02 && public_key[0] != 0x03) { // invalid pubkey
		return 0;
	}
	out->curve = info;
	out->depth = depth;
	out->child_num = child_num;
	memcpy(out->chain_code, chain_code, 32);
	memzero(out->private_key, 32);
	memzero(out->private_key_extension,32);
	memcpy(out->public_key, public_key, 33);
	return 1;
}

int hdnode_from_xprv(uint32_t depth, uint32_t child_num, const uint8_t *chain_code, const uint8_t *private_key, const char* curve, HDNode *out)
{
	bool failed = false;
	const curve_info *info = get_curve_by_name(curve);
	if (info == 0) {
		failed = true;
	} else if (info->params) {
		bignum256 a;
		bn_read_be(private_key, &a);
		if (bn_is_zero(&a)) { // == 0
			failed = true;
		} else {
			if (!bn_is_less(&a, &info->params->order)) { // >= order
				failed = true;
			}
		}
		memzero(&a, sizeof(a));
	}

	if (failed) {
		return 0;
	}

	out->curve = info;
	out->depth = depth;
	out->child_num = child_num;
	memcpy(out->chain_code, chain_code, 32);
	memcpy(out->private_key, private_key, 32);
	memzero(out->public_key, sizeof(out->public_key));
	memzero(out->private_key_extension, sizeof(out->private_key_extension));
	return 1;
}

int hdnode_from_seed(const uint8_t *seed, int seed_len, const char* curve, HDNode *out)
{
	static CONFIDENTIAL uint8_t I[32 + 32];
	memset(out, 0, sizeof(HDNode));
	out->depth = 0;
	out->child_num = 0;
	out->curve = get_curve_by_name(curve);
	if (out->curve == 0) {
		return 0;
	}
	static CONFIDENTIAL HMAC_SHA512_CTX ctx;
	hmac_sha512_Init(&ctx, (const uint8_t*) out->curve->bip32_name, strlen(out->curve->bip32_name));
	hmac_sha512_Update(&ctx, seed, seed_len);
	hmac_sha512_Final(&ctx, I);

	if (out->curve->params) {
		bignum256 a;
		while (true) {
			bn_read_be(I, &a);
			if (!bn_is_zero(&a) // != 0
				&& bn_is_less(&a, &out->curve->params->order)) { // < order
				break;
			}
			hmac_sha512_Init(&ctx, (const uint8_t*) out->curve->bip32_name, strlen(out->curve->bip32_name));
			hmac_sha512_Update(&ctx, I, sizeof(I));
			hmac_sha512_Final(&ctx, I);
		}
		memzero(&a, sizeof(a));
	}
	memcpy(out->private_key, I, 32);
	memcpy(out->chain_code, I + 32, 32);
	memzero(out->public_key, sizeof(out->public_key));
	memzero(I, sizeof(I));
	return 1;
}

#if USE_HYCON
int hdnode_from_seed_hycon(const uint8_t *seed, int seed_len, HDNode *out) 
{
	memset(out, 0, sizeof(HDNode));
	hdnode_from_seed(seed, seed_len, SECP256K1_NAME, out);

	hdnode_private_ckd_prime(out, 44);
    hdnode_private_ckd_prime(out, 1397);
    hdnode_private_ckd_prime(out, 0);
    hdnode_private_ckd(out, 0);
    hdnode_private_ckd(out, 0);
    hdnode_fill_public_key(out);

	return 1;
}
#endif

uint32_t hdnode_fingerprint(HDNode *node)
{
	uint8_t digest[32];
	uint32_t fingerprint;

	hdnode_fill_public_key(node);
	hasher_Raw(node->curve->hasher_pubkey, node->public_key, 33, digest);
	fingerprint = ((uint32_t) digest[0] << 24) + (digest[1] << 16) + (digest[2] << 8) + digest[3];
	memzero(digest, sizeof(digest));
	return fingerprint;
}

int hdnode_private_ckd(HDNode *inout, uint32_t i)
{
	static CONFIDENTIAL uint8_t data[1 + 32 + 4];
	static CONFIDENTIAL uint8_t I[32 + 32];
	static CONFIDENTIAL bignum256 a, b;

	if (i & 0x80000000) { // private derivation
		data[0] = 0;
		memcpy(data + 1, inout->private_key, 32);
	} else { // public derivation
		if (!inout->curve->params) {
			return 0;
		}
		hdnode_fill_public_key(inout);
		memcpy(data, inout->public_key, 33);
	}
	write_be(data + 33, i);

	bn_read_be(inout->private_key, &a);

	static CONFIDENTIAL HMAC_SHA512_CTX ctx;
	hmac_sha512_Init(&ctx, inout->chain_code, 32);
	hmac_sha512_Update(&ctx, data, sizeof(data));
	hmac_sha512_Final(&ctx, I);

	if (inout->curve->params) {
		while (true) {
			bool failed = false;
			bn_read_be(I, &b);
			if (!bn_is_less(&b, &inout->curve->params->order)) { // >= order
				failed = true;
			} else {
				bn_add(&b, &a);
				bn_mod(&b, &inout->curve->params->order);
				if (bn_is_zero(&b)) {
					failed = true;
				}
			}

			if (!failed) {
				bn_write_be(&b, inout->private_key);
				break;
			}

			data[0] = 1;
			memcpy(data + 1, I + 32, 32);
			hmac_sha512_Init(&ctx, inout->chain_code, 32);
			hmac_sha512_Update(&ctx, data, sizeof(data));
			hmac_sha512_Final(&ctx, I);
		}
	} else {
		memcpy(inout->private_key, I, 32);
	}

	memcpy(inout->chain_code, I + 32, 32);
	inout->depth++;
	inout->child_num = i;
	memzero(inout->public_key, sizeof(inout->public_key));

	// making sure to wipe our memory
	memzero(&a, sizeof(a));
	memzero(&b, sizeof(b));
	memzero(I, sizeof(I));
	memzero(data, sizeof(data));
	return 1;
}

#if USE_CARDANO
static void scalar_multiply8(const uint8_t *src, int bytes, uint8_t *dst)
{
	uint8_t prev_acc = 0;
	for (int i = 0; i < bytes; i++) {
		dst[i] = (src[i] << 3) + (prev_acc & 0x7);
		prev_acc = src[i] >> 5;
	}
	dst[bytes] = src[bytes - 1] >> 5;
}

static void scalar_add_256bits(const uint8_t *src1, const uint8_t *src2, uint8_t *dst)
{
	uint16_t r = 0;
	for (int i = 0; i < 32; i++) {
		r = r + (uint16_t)src1[i] + (uint16_t)src2[i];
		dst[i] = r & 0xff;
		r >>= 8;
	}
}

int hdnode_private_ckd_cardano(HDNode *inout, uint32_t index)
{
	// checks for hardened/non-hardened derivation, keysize 32 means we are dealing with public key and thus non-h, keysize 64 is for private key
	int keysize = 32;
	if (index & 0x80000000) {
		keysize = 64;
	}

	static CONFIDENTIAL uint8_t data[1 + 64 + 4];
	static CONFIDENTIAL uint8_t z[32 + 32];
	static CONFIDENTIAL uint8_t priv_key[64];
	static CONFIDENTIAL uint8_t res_key[64];

	write_le(data + keysize + 1, index);

	memcpy(priv_key, inout->private_key, 32);
	memcpy(priv_key + 32, inout->private_key_extension, 32);

	if (keysize == 64) { // private derivation
		data[0] = 0;
		memcpy(data + 1, inout->private_key, 32);
		memcpy(data + 1 + 32, inout->private_key_extension, 32);
	} else { // public derivation
		hdnode_fill_public_key(inout);
		data[0] = 2;
		memcpy(data + 1, inout->public_key + 1, 32);
	}

	static CONFIDENTIAL HMAC_SHA512_CTX ctx;
	hmac_sha512_Init(&ctx, inout->chain_code, 32);
	hmac_sha512_Update(&ctx, data, 1 + keysize + 4);
	hmac_sha512_Final(&ctx, z);

	static CONFIDENTIAL uint8_t zl8[32];
	memset(zl8, 0, 32);

	/* get 8 * Zl */
	scalar_multiply8(z, 28, zl8);
	/* Kl = 8*Zl + parent(K)l */
	scalar_add_256bits(zl8, priv_key, res_key);

	/* Kr = Zr + parent(K)r */
	scalar_add_256bits(z + 32, priv_key + 32, res_key + 32);

	memcpy(inout->private_key, res_key, 32);
	memcpy(inout->private_key_extension, res_key + 32, 32);

	if (keysize == 64) {
		data[0] = 1;
	} else {
		data[0] = 3;
	}
	hmac_sha512_Init(&ctx, inout->chain_code, 32);
	hmac_sha512_Update(&ctx, data, 1 + keysize + 4);
	hmac_sha512_Final(&ctx, z);

	memcpy(inout->chain_code, z + 32, 32);
	inout->depth++;
	inout->child_num = index;
	memzero(inout->public_key, sizeof(inout->public_key));

	// making sure to wipe our memory
	memzero(z, sizeof(z));
	memzero(data, sizeof(data));
	memzero(priv_key, sizeof(priv_key));
	memzero(res_key, sizeof(res_key));
	return 1;
}

int hdnode_from_seed_cardano(const uint8_t *pass, int pass_len, const uint8_t *seed, int seed_len, HDNode *out) {
	static CONFIDENTIAL uint8_t secret[96];
	pbkdf2_hmac_sha512(pass, pass_len, seed, seed_len, 4096, secret, 96);
	
	secret[0] &= 248;
	secret[31] &= 31;
	secret[31] |= 64;

	memset(out, 0, sizeof(HDNode));
	out->depth = 0;
	out->child_num = 0;
	out->curve = get_curve_by_name(ED25519_CARDANO_NAME);

	memcpy(out->private_key, secret, 32);
	memcpy(out->private_key_extension, secret + 32, 32);

	out->public_key[0] = 0;
	hdnode_fill_public_key(out);

	memcpy(out->chain_code, secret + 64, 32);
	memzero(secret, sizeof(secret));

	return 1;
}
#endif

int hdnode_public_ckd_cp(const ecdsa_curve *curve, const curve_point *parent, const uint8_t *parent_chain_code, uint32_t i, curve_point *child, uint8_t *child_chain_code) {
	uint8_t data[1 + 32 + 4];
	uint8_t I[32 + 32];
	bignum256 c;

	if (i & 0x80000000) { // private derivation
		return 0;
	}

	data[0] = 0x02 | (parent->y.val[0] & 0x01);
	bn_write_be(&parent->x, data + 1);
	write_be(data + 33, i);

	while (true) {
		hmac_sha512(parent_chain_code, 32, data, sizeof(data), I);
		bn_read_be(I, &c);
		if (bn_is_less(&c, &curve->order)) { // < order
			scalar_multiply(curve, &c, child); // b = c * G
			point_add(curve, parent, child);   // b = a + b
			if (!point_is_infinity(child)) {
				if (child_chain_code) {
					memcpy(child_chain_code, I + 32, 32);
				}

				// Wipe all stack data.
				memzero(data, sizeof(data));
				memzero(I, sizeof(I));
				memzero(&c, sizeof(c));
				return 1;
			}
		}

		data[0] = 1;
		memcpy(data + 1, I + 32, 32);
	}
}

int hdnode_public_ckd(HDNode *inout, uint32_t i)
{
	curve_point parent, child;

	if (!ecdsa_read_pubkey(inout->curve->params, inout->public_key, &parent)) {
		return 0;
	}
	if (!hdnode_public_ckd_cp(inout->curve->params, &parent, inout->chain_code, i, &child, inout->chain_code)) {
		return 0;
	}
	memzero(inout->private_key, 32);
	inout->depth++;
	inout->child_num = i;
	inout->public_key[0] = 0x02 | (child.y.val[0] & 0x01);
	bn_write_be(&child.x, inout->public_key + 1);

	// Wipe all stack data.
	memzero(&parent, sizeof(parent));
	memzero(&child, sizeof(child));

	return 1;
}

void hdnode_public_ckd_address_optimized(const curve_point *pub, const uint8_t *chain_code, uint32_t i, uint32_t version, HasherType hasher_pubkey, HasherType hasher_base58, char *addr, int addrsize, int addrformat)
{
	uint8_t child_pubkey[33];
	curve_point b;

	hdnode_public_ckd_cp(&secp256k1, pub, chain_code, i, &b, NULL);
	child_pubkey[0] = 0x02 | (b.y.val[0] & 0x01);
	bn_write_be(&b.x, child_pubkey + 1);

	switch (addrformat) {
		case 1: // Segwit-in-P2SH
			ecdsa_get_address_segwit_p2sh(child_pubkey, version, hasher_pubkey, hasher_base58, addr, addrsize);
			break;
		default: // normal address
			ecdsa_get_address(child_pubkey, version, hasher_pubkey, hasher_base58, addr, addrsize);
			break;
	}
}

#if USE_BIP32_CACHE
static bool private_ckd_cache_root_set = false;
static CONFIDENTIAL HDNode private_ckd_cache_root;
static int private_ckd_cache_index = 0;

static CONFIDENTIAL struct {
	bool set;
	size_t depth;
	uint32_t i[BIP32_CACHE_MAXDEPTH];
	HDNode node;
} private_ckd_cache[BIP32_CACHE_SIZE];

int hdnode_private_ckd_cached(HDNode *inout, const uint32_t *i, size_t i_count, uint32_t *fingerprint)
{
	if (i_count == 0) {
		// no way how to compute parent fingerprint
		return 1;
	}
	if (i_count == 1) {
		if (fingerprint) {
			*fingerprint = hdnode_fingerprint(inout);
		}
		if (hdnode_private_ckd(inout, i[0]) == 0) return 0;
		return 1;
	}

	bool found = false;
	// if root is not set or not the same
	if (!private_ckd_cache_root_set || memcmp(&private_ckd_cache_root, inout, sizeof(HDNode)) != 0) {
		// clear the cache
		private_ckd_cache_index = 0;
		memzero(private_ckd_cache, sizeof(private_ckd_cache));
		// setup new root
		memcpy(&private_ckd_cache_root, inout, sizeof(HDNode));
		private_ckd_cache_root_set = true;
	} else {
		// try to find parent
		int j;
		for (j = 0; j < BIP32_CACHE_SIZE; j++) {
			if (private_ckd_cache[j].set &&
				private_ckd_cache[j].depth == i_count - 1 &&
				memcmp(private_ckd_cache[j].i, i, (i_count - 1) * sizeof(uint32_t)) == 0 &&
				private_ckd_cache[j].node.curve == inout->curve) {
				memcpy(inout, &(private_ckd_cache[j].node), sizeof(HDNode));
				found = true;
				break;
			}
		}
	}

	// else derive parent
	if (!found) {
		size_t k;
		for (k = 0; k < i_count - 1; k++) {
			if (hdnode_private_ckd(inout, i[k]) == 0) return 0;
		}
		// and save it
		memset(&(private_ckd_cache[private_ckd_cache_index]), 0, sizeof(private_ckd_cache[private_ckd_cache_index]));
		private_ckd_cache[private_ckd_cache_index].set = true;
		private_ckd_cache[private_ckd_cache_index].depth = i_count - 1;
		memcpy(private_ckd_cache[private_ckd_cache_index].i, i, (i_count - 1) * sizeof(uint32_t));
		memcpy(&(private_ckd_cache[private_ckd_cache_index].node), inout, sizeof(HDNode));
		private_ckd_cache_index = (private_ckd_cache_index + 1) % BIP32_CACHE_SIZE;
	}

	if (fingerprint) {
		*fingerprint = hdnode_fingerprint(inout);
	}
	if (hdnode_private_ckd(inout, i[i_count - 1]) == 0) return 0;

	return 1;
}
#endif

void hdnode_get_address_raw(HDNode *node, uint32_t version, uint8_t *addr_raw)
{
	hdnode_fill_public_key(node);
	ecdsa_get_address_raw(node->public_key, version, node->curve->hasher_pubkey, addr_raw);
}

void hdnode_get_address(HDNode *node, uint32_t version, char *addr, int addrsize)
{
	hdnode_fill_public_key(node);
	ecdsa_get_address(node->public_key, version, node->curve->hasher_pubkey, node->curve->hasher_base58, addr, addrsize);
}

#if USE_HYCON

int hdnode_get_hycon_address(HDNode *node, char *address, const size_t address_len) 
{
	if(node == NULL) 
	{
		return 0;
	}

	size_t pubick_key_len = 33;
	size_t hash_len = 32;
	uint8_t hash[hash_len];
	memset(hash, 0, hash_len);

	blake2b(node->public_key, pubick_key_len, hash, hash_len);

	size_t address_arr_len = 20;
	uint8_t address_arr[address_arr_len];
	memset(address_arr, 0, address_arr_len);
	size_t start_idx = hash_len - address_arr_len;
	for(size_t i=start_idx; i<hash_len; ++i) {
		address_arr[i - start_idx] = hash[i];
	}

	size_t address_str_len = 29;
	char address_str[address_str_len];
	memset(address_str, 0, address_arr_len);
	b58enc(address_str, &address_str_len, address_arr, address_arr_len);

	size_t checksum_len = 5;
	char checksum[checksum_len];
	memset(checksum, 0, checksum_len);
	hycon_address_checksum(address_arr, address_arr_len, checksum, checksum_len);

	memset(address, 0, address_len);
	address[0] = 'H';
	memcpy(address + 1, address_str, address_str_len - 1);
	memcpy(address + address_str_len, checksum, checksum_len - 1);

	return 1;
}
#endif

void hdnode_fill_public_key(HDNode *node)
{
	if (node->public_key[0] != 0)
		return;

#if USE_BIP32_25519_CURVES
	if (node->curve->params) {
		ecdsa_get_public_key33(node->curve->params, node->private_key, node->public_key);
	} else {
		node->public_key[0] = 1;
		if (node->curve == &ed25519_info) {
			ed25519_publickey(node->private_key, node->public_key + 1);
		} else if (node->curve == &ed25519_sha3_info) {
			ed25519_publickey_sha3(node->private_key, node->public_key + 1);
#if USE_KECCAK
		} else if (node->curve == &ed25519_keccak_info) {
			ed25519_publickey_keccak(node->private_key, node->public_key + 1);
#endif
		} else if (node->curve == &curve25519_info) {
			curve25519_scalarmult_basepoint(node->public_key + 1, node->private_key);
#if USE_CARDANO
		} else if (node->curve == &ed25519_cardano_info) {
			ed25519_publickey_ext(node->private_key, node->private_key_extension, node->public_key + 1);
#endif
		}
	}
#else

	ecdsa_get_public_key33(node->curve->params, node->private_key, node->public_key);
#endif
}

#if USE_ETHEREUM
int hdnode_get_ethereum_pubkeyhash(const HDNode *node, uint8_t *pubkeyhash)
{
	uint8_t buf[65];
	SHA3_CTX ctx;

	/* get uncompressed public key */
	ecdsa_get_public_key65(node->curve->params, node->private_key, buf);

	/* compute sha3 of x and y coordinate without 04 prefix */
	sha3_256_Init(&ctx);
	sha3_Update(&ctx, buf + 1, 64);
	keccak_Final(&ctx, buf);

	/* result are the least significant 160 bits */
	memcpy(pubkeyhash, buf + 12, 20);

	return 1;
}
#endif

#if USE_NEM
int hdnode_get_nem_address(HDNode *node, uint8_t version, char *address) {
	if (node->curve != &ed25519_keccak_info) {
		return 0;
	}

	hdnode_fill_public_key(node);
	return nem_get_address(&node->public_key[1], version, address);
}

int hdnode_get_nem_shared_key(const HDNode *node, const ed25519_public_key peer_public_key, const uint8_t *salt, ed25519_public_key mul, uint8_t *shared_key) {
	if (node->curve != &ed25519_keccak_info) {
		return 0;
	}

	// sizeof(ed25519_public_key) == SHA3_256_DIGEST_LENGTH
	if (mul == NULL) mul = shared_key;

	if (ed25519_scalarmult_keccak(mul, node->private_key, peer_public_key)) {
		return 0;
	}

	for (size_t i = 0; i < 32; i++) {
		shared_key[i] = mul[i] ^ salt[i];
	}

	keccak_256(shared_key, 32, shared_key);
	return 1;
}

int hdnode_nem_encrypt(const HDNode *node, const ed25519_public_key public_key, const uint8_t *iv_immut, const uint8_t *salt, const uint8_t *payload, size_t size, uint8_t *buffer) {
	uint8_t last_block[AES_BLOCK_SIZE];
	uint8_t remainder = size % AES_BLOCK_SIZE;

	// Round down to last whole block
	size -= remainder;
	// Copy old last block
	memcpy(last_block, &payload[size], remainder);
	// Pad new last block with number of missing bytes
	memset(&last_block[remainder], AES_BLOCK_SIZE - remainder, AES_BLOCK_SIZE - remainder);

	// the IV gets mutated, so we make a copy not to touch the original
	uint8_t iv[AES_BLOCK_SIZE];
	memcpy(iv, iv_immut, AES_BLOCK_SIZE);

	uint8_t shared_key[SHA3_256_DIGEST_LENGTH];
	if (!hdnode_get_nem_shared_key(node, public_key, salt, NULL, shared_key)) {
		return 0;
	}

	aes_encrypt_ctx ctx;

	int ret = aes_encrypt_key256(shared_key, &ctx);
	memzero(shared_key, sizeof(shared_key));

	if (ret != EXIT_SUCCESS) {
		return 0;
	}

	if (aes_cbc_encrypt(payload, buffer, size, iv, &ctx) != EXIT_SUCCESS) {
		return 0;
	}

	if (aes_cbc_encrypt(last_block, &buffer[size], sizeof(last_block), iv, &ctx) != EXIT_SUCCESS) {
		return 0;
	}

	return 1;
}

int hdnode_nem_decrypt(const HDNode *node, const ed25519_public_key public_key, uint8_t *iv, const uint8_t *salt, const uint8_t *payload, size_t size, uint8_t *buffer) {
	uint8_t shared_key[SHA3_256_DIGEST_LENGTH];

	if (!hdnode_get_nem_shared_key(node, public_key, salt, NULL, shared_key)) {
		return 0;
	}

	aes_decrypt_ctx ctx;

	int ret = aes_decrypt_key256(shared_key, &ctx);
	memzero(shared_key, sizeof(shared_key));

	if (ret != EXIT_SUCCESS) {
		return 0;
	}

	if (aes_cbc_decrypt(payload, buffer, size, iv, &ctx) != EXIT_SUCCESS) {
		return 0;
	}

	return 1;
}
#endif

// msg is a data to be signed
// msg_len is the message length
int hdnode_sign(HDNode *node, const uint8_t *msg, uint32_t msg_len, HasherType hasher_sign, uint8_t *sig, uint8_t *pby, int (*is_canonical)(uint8_t by, uint8_t sig[64]))
{
	if (node->curve->params) {
		return ecdsa_sign(node->curve->params, hasher_sign, node->private_key, msg, msg_len, sig, pby, is_canonical);
	} else if (node->curve == &curve25519_info) {
		return 1;  // signatures are not supported
	} else {
		hdnode_fill_public_key(node);
		if (node->curve == &ed25519_info) {
			ed25519_sign(msg, msg_len, node->private_key, node->public_key + 1, sig);
		} else if (node->curve == &ed25519_sha3_info) {
			ed25519_sign_sha3(msg, msg_len, node->private_key, node->public_key + 1, sig);
#if USE_KECCAK
		} else if (node->curve == &ed25519_keccak_info) {
			ed25519_sign_keccak(msg, msg_len, node->private_key, node->public_key + 1, sig);
#endif
		}
		return 0;
	}
}

#if USE_HYCON
int hdnode_hycon_sign_tx(HDNode *node, const uint8_t* txhash, uint8_t* signature, uint8_t* recovery) 
{
	if(node == NULL) 
	{
		return 0;
	}

	const ecdsa_curve *curve = &secp256k1;
    ecdsa_sign_digest(curve, node->private_key, txhash, signature, recovery, NULL);

	return 1;
}

#define FROMHEX_MAXLEN 512

const uint8_t *fromHex(const char *str)
{
	static uint8_t buf[FROMHEX_MAXLEN];
	size_t len = strlen(str) / 2;
	if (len > FROMHEX_MAXLEN) len = FROMHEX_MAXLEN;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = 0;
		if (str[i * 2] >= '0' && str[i*2] <= '9') c += (str[i * 2] - '0') << 4;
		if ((str[i * 2] & ~0x20) >= 'A' && (str[i*2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
		if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
		if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
		buf[i] = c;
	}
	return buf;
}

int hdnode_hycon_encode_tx(const char* from_address_str, const char* to_address_str, const uint32_t nonce, const uint64_t amount, const uint64_t fee, uint8_t* txhash, size_t hash_len)
{
	size_t address_arr_len = 20;
	uint8_t from_address_arr[address_arr_len];
	hycon_address_to_address_arr(from_address_str, from_address_arr, address_arr_len);
	size_t checksum_len = 4;
	char checksum[checksum_len+1];
	hycon_address_checksum(from_address_arr, address_arr_len, checksum, checksum_len);
    if(strncmp(checksum, from_address_str + sizeof(from_address_str) - checksum_len, checksum_len) == 0)
	{
		return 0;
	}
	ProtobufCBinaryData from_address;
    from_address.len = address_arr_len;
    from_address.data = from_address_arr;

	uint8_t to_address_arr[address_arr_len];
	hycon_address_to_address_arr(to_address_str, to_address_arr, address_arr_len);
	hycon_address_checksum(to_address_arr, address_arr_len, checksum, checksum_len);
    if(strncmp(checksum, to_address_str + sizeof(to_address_str) - checksum_len, checksum_len) == 0) 
	{
		return 0;
	}
	ProtobufCBinaryData to_address;
    to_address.len = address_arr_len;
    to_address.data = to_address_arr;

	HyconTx tx = HYCON_TX__INIT;
    tx.to =  to_address;
    tx.from = from_address;
    tx.nonce = nonce;
    tx.amount = amount;
    tx.fee = fee;

	uint8_t* protoTx;
	size_t protoTx_len = hycon_tx__get_packed_size(&tx);
	protoTx = malloc(protoTx_len);
	hycon_tx__pack(&tx, protoTx);

	memset(txhash, 0, hash_len);
	blake2b(protoTx, protoTx_len, txhash, hash_len);

	free(protoTx);

	return 1;
}

int hdnode_hycon_hash_password(const char* password, uint8_t* password_hash) 
{
	size_t password_len = strlen(password);
	size_t password_hash_len = 32;
	memset(password_hash, 0, password_hash_len);

	blake2b((uint8_t*)password, password_len, password_hash, password_hash_len);

	return 1;
}
int hdnode_hycon_encrypt(HDNode *node, const uint8_t* password, uint8_t* iv, const size_t iv_len, uint8_t* data, const size_t data_len)
{
	if(node == NULL) 
	{
		return 0;
	}

	memset(iv, 0, iv_len);
	random_buffer(iv, iv_len);

	uint8_t iv_enc[iv_len];
	memset(iv_enc, 0, iv_len);
	memcpy(iv_enc, iv, iv_len);

	size_t hash_len = 32;

	size_t private_key_char_len = 64;
	char private_key_char[private_key_char_len];
	memset(private_key_char, 0, private_key_char_len);

	for(size_t i=0; i<hash_len; ++i) {
		sprintf(private_key_char + (i * 2), "%02x", (node->private_key)[i]);
	}

	AES_KEY aes_key;
	AES_set_encrypt_key(password, 256, &aes_key);

	memset(data, 0, data_len);
	AES_cbc_encrypt((unsigned char*)private_key_char, data, private_key_char_len, &aes_key, iv_enc, AES_ENCRYPT);

	return 1;
}
int hdnode_hycon_decrypt(uint8_t* iv, const uint8_t* data, const size_t data_len, const uint8_t* password, uint8_t* private_key)
{
	AES_KEY aes_key;
    AES_set_decrypt_key(password, 256, &aes_key);
    size_t decrypt_result_length = 65;
    unsigned char decrypt_result[decrypt_result_length];
    size_t private_key_char_length = 65;
    char private_key_char[private_key_char_length];
    memset(decrypt_result, 0, decrypt_result_length);
    memset(private_key_char, 0, private_key_char_length);

    AES_cbc_encrypt(data, decrypt_result, data_len, &aes_key, iv, AES_DECRYPT);
    decrypt_result[64] = 0;
    sprintf(private_key_char, "%s", decrypt_result);

    size_t private_key_length = 32;
    memset(private_key, 0, private_key_length);
    memcpy(private_key, fromHex(private_key_char), private_key_length);
	
	return 1;
}
#endif

int hdnode_sign_digest(HDNode *node, const uint8_t *digest, uint8_t *sig, uint8_t *pby, int (*is_canonical)(uint8_t by, uint8_t sig[64]))
{
	if (node->curve->params) {
		return ecdsa_sign_digest(node->curve->params, node->private_key, digest, sig, pby, is_canonical);
	} else if (node->curve == &curve25519_info) {
		return 1;  // signatures are not supported
	} else {
		return hdnode_sign(node, digest, 32, 0, sig, pby, is_canonical);
	}
}

int hdnode_get_shared_key(const HDNode *node, const uint8_t *peer_public_key, uint8_t *session_key, int *result_size)
{
	// Use elliptic curve Diffie-Helman to compute shared session key
	if (node->curve->params) {
		if (ecdh_multiply(node->curve->params, node->private_key, peer_public_key, session_key) != 0) {
			return 1;
		}
		*result_size = 65;
		return 0;
	} else if (node->curve == &curve25519_info) {
		session_key[0] = 0x04;
		if (peer_public_key[0] != 0x40) {
			return 1;  // Curve25519 public key should start with 0x40 byte.
		}
		curve25519_scalarmult(session_key + 1, node->private_key, peer_public_key + 1);
		*result_size = 33;
		return 0;
	} else {
		*result_size = 0;
		return 1;  // ECDH is not supported
	}
}

static int hdnode_serialize(const HDNode *node, uint32_t fingerprint, uint32_t version, char use_public, char *str, int strsize)
{
	uint8_t node_data[78];
	write_be(node_data, version);
	node_data[4] = node->depth;
	write_be(node_data + 5, fingerprint);
	write_be(node_data + 9, node->child_num);
	memcpy(node_data + 13, node->chain_code, 32);
	if (use_public) {
		memcpy(node_data + 45, node->public_key, 33);
	} else {
		node_data[45] = 0;
		memcpy(node_data + 46, node->private_key, 32);
	}
	int ret = base58_encode_check(node_data, sizeof(node_data), node->curve->hasher_base58, str, strsize);
	memzero(node_data, sizeof(node_data));
	return ret;
}

int hdnode_serialize_public(const HDNode *node, uint32_t fingerprint, uint32_t version, char *str, int strsize)
{
	return hdnode_serialize(node, fingerprint, version, 1, str, strsize);
}

int hdnode_serialize_private(const HDNode *node, uint32_t fingerprint, uint32_t version, char *str, int strsize)
{
	return hdnode_serialize(node, fingerprint, version, 0, str, strsize);
}

// check for validity of curve point in case of public data not performed
int hdnode_deserialize(const char *str, uint32_t version_public, uint32_t version_private, const char *curve, HDNode *node, uint32_t *fingerprint)
{
	uint8_t node_data[78];
	memset(node, 0, sizeof(HDNode));
	node->curve = get_curve_by_name(curve);
	if (base58_decode_check(str, node->curve->hasher_base58, node_data, sizeof(node_data)) != sizeof(node_data)) {
		return -1;
	}
	uint32_t version = read_be(node_data);
	if (version == version_public) {
		memzero(node->private_key, sizeof(node->private_key));
		memcpy(node->public_key, node_data + 45, 33);
	} else if (version == version_private) { // private node
		if (node_data[45]) { // invalid data
			return -2;
		}
		memcpy(node->private_key, node_data + 46, 32);
		memzero(node->public_key, sizeof(node->public_key));
	} else {
		return -3; // invalid version
	}
	node->depth = node_data[4];
	if (fingerprint) {
		*fingerprint = read_be(node_data + 5);
	}
	node->child_num = read_be(node_data + 9);
	memcpy(node->chain_code, node_data + 13, 32);
	return 0;
}

const curve_info *get_curve_by_name(const char *curve_name) {
	if (curve_name == 0) {
		return 0;
	}
	if (strcmp(curve_name, SECP256K1_NAME) == 0) {
		return &secp256k1_info;
	}
	if (strcmp(curve_name, SECP256K1_DECRED_NAME) == 0) {
		return &secp256k1_decred_info;
	}
	if (strcmp(curve_name, SECP256K1_GROESTL_NAME) == 0) {
		return &secp256k1_groestl_info;
	}
	if (strcmp(curve_name, SECP256K1_SMART_NAME) == 0) {
		return &secp256k1_smart_info;
	}
	if (strcmp(curve_name, NIST256P1_NAME) == 0) {
		return &nist256p1_info;
	}
	if (strcmp(curve_name, ED25519_NAME) == 0) {
		return &ed25519_info;
	}
	if (strcmp(curve_name, ED25519_CARDANO_NAME) == 0) {
		return &ed25519_cardano_info;
	}
	if (strcmp(curve_name, ED25519_SHA3_NAME) == 0) {
		return &ed25519_sha3_info;
	}
#if USE_KECCAK
	if (strcmp(curve_name, ED25519_KECCAK_NAME) == 0) {
		return &ed25519_keccak_info;
	}
#endif
	if (strcmp(curve_name, CURVE25519_NAME) == 0) {
		return &curve25519_info;
	}
	return 0;
}
