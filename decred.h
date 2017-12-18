/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2016 Peter Banik <peter@prioritylane.com>
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



#ifndef __DECRED_H__
#define __DECRED_H__

#include <stdbool.h>

#define MAX_WORD_LENGTH 12
#define MAX_SEED_LENGTH 32
#define MIN_SEED_LENGTH 16

// 1 additional word added for storing checksum
#define WORDLIST_MAX_LENGTH ((MAX_SEED_LENGTH + 1) * (MAX_WORD_LENGTH + 1) + 1)

char *decred_pgp_words_from_data(const uint8_t *data, int len);

int decred_mnemonic_to_seed(const char *mnemonics, uint8_t seed[MAX_SEED_LENGTH]);

const char *decred_seed_to_mnemonic(const uint8_t *data, int seed_len);

const char *decred_generate_seed(int strength);

int decred_check_mnemonic(const char *mnemonic);

#endif
