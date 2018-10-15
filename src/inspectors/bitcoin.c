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

uint8_t check_bitcoin(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  if ((pkt_info->l4.port_src == port_bitcoin ||
       pkt_info->l4.port_dst == port_bitcoin) &&
      (*((uint32_t *) app_data) == 0xD9B4BEF9 ||
       *((uint32_t *) app_data) == 0xDAB5BFFA ||
       *((uint32_t *) app_data) == 0x0709110B ||
       *((uint32_t *) app_data) == 0xFEB4BEF9)) {
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
