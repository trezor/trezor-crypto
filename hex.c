/**
 * Copyright (c) 2016 Alex Beregszaszi
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

#include "hex.h"

static const char *hex_digits = "0123456789abcdef";

int hex_string(const uint8_t *data, int datalen, char *str, int strsize)
{
	int i, j;

	if (datalen * 2 > strsize) {
		return 0;
	}

	for (i = 0, j = 0; i < datalen; i++) {
		const uint8_t tmp = data[i];
		str[j++] = hex_digits[(tmp >> 4) & 0xf];
		str[j++] = hex_digits[tmp & 0xf];
	}

	return 1;
}

int hex_string_prefixed(const uint8_t *data, int datalen, char *str, int strsize)
{
	str[0] = '0';
	str[1] = 'x';
	return hex_string(data, datalen, str + 2, strsize - 2);
}
