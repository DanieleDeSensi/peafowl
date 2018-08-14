/*
 * utils.h
 *
 * Created on: 05/10/2012
 *
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
 *
 *  This file is part of Peafowl.
 *
 *  Peafowl is free software: you can redistribute it and/or
 *  modify it under the terms of the Lesser GNU General Public
 *  License as published by the Free Software Foundation, either
 *  version 3 of the License, or (at your option) any later version.

 *  Peafowl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  Lesser GNU General Public License for more details.
 *
 *  You should have received a copy of the Lesser GNU General Public
 *  License along with Peafowl.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================================================================
 */

#ifndef UTILS_H_
#define UTILS_H_

#include <limits.h>
#include <netinet/in.h>
#include <strings.h>

#define DPI_MAX_UINT_16 65535
#define DPI_MAX_INT_32 4294967295
#define DPI_TCP_MAX_IN_TRAVEL_DATA 2147483648 /** 2^31 **/

#define SET_BIT(val, bitIndex) val |= (1 << bitIndex)
#define CLEAR_BIT(val, bitIndex) val &= ~(1 << bitIndex)
#define TOGGLE_BIT(val, bitIndex) val ^= (1 << bitIndex)
#define BIT_IS_SET(val, bitIndex) (val & (1 << bitIndex))

#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b) \
  ((b) / CHAR_BIT) /** Gets the byte in which the b-th bit is located. **/
#define BITSET(a, b) \
  ((a)[BITSLOT(b)] |= BITMASK(b)) /** Sets in the mask a the b-th bit. **/
#define BITCLEAR(a, b)                                                      \
  ((a)[BITSLOT(b)] &= ~BITMASK(b)) /** Delete the b-th bit from the mask a. \
                                      **/
#define BITTEST(a, b) \
  ((a)[BITSLOT(b)] &  \
   BITMASK(b)) /** Tests if in the mask a the b-th bit is set. **/
#define BITNSLOTS(nb)                                                        \
  ((nb + CHAR_BIT - 1) / CHAR_BIT) /** Returns the number of chars that need \
                                      to be used for an array of nb bits. **/

#define get_u8(X, O) (*(uint8_t *)(((uint8_t *)X) + O))
#define get_u16(X, O) (*(uint16_t *)(((uint8_t *)X) + O))
#define get_u32(X, O) (*(uint32_t *)(((uint8_t *)X) + O))
#define get_u64(X, O) (*(uint64_t *)(((uint8_t *)X) + O))

#ifdef __cplusplus
extern "C" {
#endif
uint8_t dpi_v6_addresses_equal(struct in6_addr x, struct in6_addr y);
#ifdef __cplusplus
}
#endif

#endif /* UTILS_H_ */
