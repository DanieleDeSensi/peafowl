/*
 * bitcoin.c
 *
 * This protocol inspector is adapted from
 * the nDPI Mining dissector
 * (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/mining.c)
 *
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
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define pfwl_bitcoin_magic_1 0xD9B4BEF9
#define pfwl_bitcoin_magic_2 0xDAB5BFFA
#define pfwl_bitcoin_magic_3 0x0709110B
#define pfwl_bitcoin_magic_4 0xFEB4BEF9
#elif __BYTE_ORDER == __BIG_ENDIAN
#define pfwl_bitcoin_magic_1 0xF9BEB4D9
#define pfwl_bitcoin_magic_2 0xDAB5BFFA
#define pfwl_bitcoin_magic_3 0x0B110907
#define pfwl_bitcoin_magic_4 0xF9BEB4FE
#else
#error "Please fix <bits/endian.h>"
#endif

uint8_t check_bitcoin(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  if ((*((uint32_t *) app_data) == pfwl_bitcoin_magic_1 ||
       *((uint32_t *) app_data) == pfwl_bitcoin_magic_2 ||
       *((uint32_t *) app_data) == pfwl_bitcoin_magic_3 ||
       *((uint32_t *) app_data) == pfwl_bitcoin_magic_4)) {
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
