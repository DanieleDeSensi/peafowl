/*
 * utils.h
 *
 * =========================================================================
 * Copyright (c) 2012-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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

#ifndef UTILS_H_
#define UTILS_H_

#include <limits.h>
#include <netinet/in.h>
#include <strings.h>

#define PFWL_MAX_UINT_16 65535
#define PFWL_MAX_INT_32 4294967295
#define PFWL_TCP_MAX_IN_TRAVEL_DATA 2147483648 /** 2^31 **/

#define SET_BIT(val, bitIndex) val |= (1 << bitIndex)
#define CLEAR_BIT(val, bitIndex) val &= ~(1 << bitIndex)
#define TOGGLE_BIT(val, bitIndex) val ^= (1 << bitIndex)
#define BIT_IS_SET(val, bitIndex) (val & (1 << bitIndex))

#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b)                                                             \
  ((b) / CHAR_BIT) /** Gets the byte in which the b-th bit is located. **/
#define BITSET(a, b)                                                           \
  ((a)[BITSLOT(b)] |= BITMASK(b)) /** Sets in the mask a the b-th bit. **/
#define BITCLEAR(a, b)                                                         \
  ((a)[BITSLOT(b)] &= ~BITMASK(b)) /** Delete the b-th bit from the mask a.    \
                                    **/
#define BITTEST(a, b)                                                          \
  ((a)[BITSLOT(b)] &                                                           \
   BITMASK(b)) /** Tests if in the mask a the b-th bit is set. **/
#define BITNSLOTS(nb)                                                          \
  ((nb + CHAR_BIT - 1) / CHAR_BIT) /** Returns the number of chars that need   \
                                      to be used for an array of nb bits. **/

#define get_u8(X, O) (*(uint8_t *) (((uint8_t *) X) + O))
#define get_u16(X, O) (*(uint16_t *) (((uint8_t *) X) + O))
#define get_u32(X, O) (*(uint32_t *) (((uint8_t *) X) + O))
#define get_u64(X, O) (*(uint64_t *) (((uint8_t *) X) + O))
#define get_u128(X, O) (*(uint128_t *) (((uint8_t *) X) + O))

#define PFWL_MIN(x, y)                                                         \
  ({                                                                           \
    __typeof__(x) _x = (x);                                                    \
    __typeof__(y) _y = (y);                                                    \
    _x < _y ? _x : _y;                                                         \
  })

#ifdef __cplusplus
extern "C" {
#endif
uint8_t pfwl_v6_addresses_equal(struct in6_addr x, struct in6_addr y);
char *pfwl_strnstr(const char *haystack, const char *needle, size_t len);
#ifdef __cplusplus
}
#endif

#endif /* UTILS_H_ */
