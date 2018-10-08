/**
 * Copyright (c) 2016 Daira Hopwood
 * Copyright (c) 2016 Pavol Rusnak
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

#ifndef __ADDRESS_H__
#define __ADDRESS_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "options.h"

size_t address_prefix_bytes_len(uint32_t address_type);
void address_write_prefix_bytes(uint32_t address_type, uint8_t *out);
bool address_check_prefix(const uint8_t *addr, uint32_t address_type);
#if USE_ETHEREUM
void ethereum_address_checksum(const uint8_t *addr, char *address, bool rskip60, uint32_t chain_id);
#endif
#if USE_HYCON
#include <string.h>
#include "base58.h"
#include "blake2b.h"
void hycon_address_checksum(const uint8_t* address_arr, const size_t address_arr_len, char *checksum, const size_t checksum_len);
void hycon_address_to_address_arr(const char* address, uint8_t* address_arr, size_t address_arr_len);
#endif

#endif
