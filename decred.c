/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2016 Peter Banik <peter@froggle.org>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */



#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "sha2.h"
#include "rand.h"
#include "blake256.h"
#include "curves.h"
#include "secp256k1.h"
#include "ripemd160.h"
#include "base58.h"
#include "address.h"

#include "decred.h"
#include "decred_pgpwordlist_english.h"


uint32_t decred_ser_length_hash(BLAKE256_CTX *ctx, uint32_t len)
{
	if (len < 253) {
		blake256_Update(ctx, (const uint8_t *)&len, 1);
		return 1;
	}
	if (len < 0x10000) {
		uint8_t d = 253;
		blake256_Update(ctx, &d, 1);
		blake256_Update(ctx, (const uint8_t *)&len, 2);
		return 3;
	}
	uint8_t d = 254;
	blake256_Update(ctx, &d, 1);
	blake256_Update(ctx, (const uint8_t *)&len, 4);
	return 5;
}


// Returns the PGP word list encoding of b when found at index.
static const char *decred_pgp_byte_to_mnemonic(uint8_t byte, uint16_t index)
{
	uint16_t bb = (uint16_t)byte * 2;
	if(index % 2){
		++bb;
	}
	return pgpwordlist[bb];
}


static int get_word_index(const char *word)
{
	for(uint16_t i = 0; pgpwordlist[i]; i++){
		if(strcasecmp(pgpwordlist[i], word) == 0){
			// printf("+ strcasecmp: %s == %s\t%d\n", pgpwordlist[i], word, i);
			return i;
		}
	}
	return -1;
}


// Returns the checksum byte used at the end of the seed mnemonic
// encoding.  The "checksum" is the first byte of the double SHA256.
static uint8_t pgp_checksum_byte(const uint8_t *data, uint8_t len)
{
	uint8_t intermediate_hash[SHA256_DIGEST_LENGTH + 1];
	uint8_t final_hash[SHA256_DIGEST_LENGTH + 1];
	sha256_Raw(data, len, intermediate_hash);
	sha256_Raw(intermediate_hash, SHA256_DIGEST_LENGTH, final_hash);
	return final_hash[0];
}


char *decred_pgp_words_from_data(const uint8_t *data, int seed_len)
{

	if (seed_len < MIN_SEED_LENGTH || seed_len > MAX_SEED_LENGTH) {
		return 0;
	}

	int i;
	int word_len;
	static char mnemonics[WORDLIST_MAX_LENGTH];
	const char *word;
	char *pos = mnemonics;

	for (i = 0; i < seed_len; i++) {
		word = decred_pgp_byte_to_mnemonic(data[i], i);
		word_len = strlen(word);
		memcpy(pos, word, word_len);
		pos += word_len;
		if(i < (seed_len - 1)) {
			*pos++ = ' ';
		}
	}

	*pos = 0;

	return mnemonics;
}


int decred_mnemonic_to_seed(const char *mnemonics, uint8_t seed[MAX_SEED_LENGTH + 1])
{
	char mnemonic_tokens[WORDLIST_MAX_LENGTH];
	int byte, idx;

	strncpy(mnemonic_tokens, mnemonics, WORDLIST_MAX_LENGTH);
	memset(seed, 0, MAX_SEED_LENGTH + 1);

	char *tok = strtok(mnemonic_tokens, " ");

	for(idx = 0; tok; ) {
		if(strlen(tok) == 0){
			continue;
		}
		byte = get_word_index(tok);
		if(byte == -1){
			fprintf(stderr, "word %s is not in the PGP word list\n", tok);
			return -1;
		}
		if((int)(byte % 2) != (idx % 2)){
			fprintf(stderr, "word %s is not valid at position %d\n", tok, idx);
			return -2;
		}
		seed[idx] = (uint8_t)(byte/2);
		tok = strtok(NULL, " ");
		idx++;
	}
	return 0;
}


const char *decred_seed_to_mnemonic(const uint8_t *data, int seed_len)
{
  uint8_t checksum = pgp_checksum_byte(data, seed_len);
  const char *checksum_word = decred_pgp_byte_to_mnemonic(checksum, seed_len);
  char *wordlist = decred_pgp_words_from_data(data, seed_len);

  int word_len = strlen(checksum_word);
  char *p = wordlist + strlen(wordlist);
  *p++ = ' ';
  memcpy(p, checksum_word, word_len);

  return wordlist;
}


const char *decred_generate_seed(int strength)
{
	if (strength % 32 || strength < 128 || strength > 256) {
		return 0;
	}
	uint8_t data[32];
	random_buffer(data, 32);
	return decred_seed_to_mnemonic(data, strength / 8);
}


int decred_check_mnemonic(const char *mnemonic)
{
	int result;
	uint8_t seed[MAX_SEED_LENGTH + 1];

	result = decred_mnemonic_to_seed(mnemonic, seed);

	// invalid word in the wordlist, unable to get compute the seed
	if(result != 0){
		fprintf(stderr, "invalid word");
		return 0;
	}

	uint8_t checksum = pgp_checksum_byte(seed, MAX_SEED_LENGTH);

	fprintf(stderr, "checksum byte %d\n", checksum);

	if(checksum == seed[MAX_SEED_LENGTH]){
		return 1;
	}

	return 0;
}
