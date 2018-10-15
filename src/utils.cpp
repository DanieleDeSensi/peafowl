/*
 * utils.c
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */
#include <peafowl/utils.h>
#include <string.h>
#include <sys/types.h>

uint8_t pfwl_v6_addresses_equal(struct in6_addr x, struct in6_addr y) {
  uint8_t i;
  for (i = 0; i < 16; i++) {
    if (x.s6_addr[i] != y.s6_addr[i])
      return 0;
  }
  return 1;
}

char *pfwl_strnstr(const char *haystack, const char *needle, size_t len) {
  int i;
  size_t needle_len;

  if (0 == (needle_len = strnlen(needle, len)))
    return (char *) haystack;

  for (i = 0; i <= (int) (len - needle_len); i++) {
    if ((haystack[0] == needle[0]) &&
        (0 == strncmp(haystack, needle, needle_len)))
      return (char *) haystack;

    haystack++;
  }
  return NULL;
}
