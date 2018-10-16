/*
 * dhcp.c
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
#define PFWL_DHCP_MAGIC_COOKIE 0x63538263
#define PFWL_DHCP_TYPE 0x0135
#elif __BYTE_ORDER == __BIG_ENDIAN
#define PFWL_DHCP_MAGIC_COOKIE 0x63825363
#define PFWL_DHCP_TYPE 0x3501
#else
#error "Please fix <bits/endian.h>"
#endif

uint8_t check_dhcp(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private) {
  if (data_length >= 244 && /** Minimum data_length. **/
      /** Ports check. **/
      ((pkt_info->l4.port_src == port_dhcp_1 &&
        pkt_info->l4.port_dst == port_dhcp_2) ||
       (pkt_info->l4.port_dst == port_dhcp_1 &&
        pkt_info->l4.port_src == port_dhcp_2)) &&
      /** Magic cookie. **/
      get_u32(app_data, 236) == PFWL_DHCP_MAGIC_COOKIE &&
      /**
       * First two bytes of DHCP message type.
       * Are the same for any DHCP message type.
       **/
      get_u16(app_data, 240) == PFWL_DHCP_TYPE) {
    return PFWL_PROTOCOL_MATCHES;
  } else {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
}
