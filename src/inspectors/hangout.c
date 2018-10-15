/*
 * hangout.c
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

static uint8_t is_hangout_udp_port(uint16_t port) {
  if ((port == port_hangout_19302) || (port == port_hangout_19303) ||
      (port == port_hangout_19304) || (port == port_hangout_19305) ||
      (port == port_hangout_19306) || (port == port_hangout_19307) ||
      (port == port_hangout_19308) || (port == port_hangout_19309))
    return 1;
  else
    return 0;
}

static uint8_t is_hangout_tcp_port(uint16_t port) {
  if ((port == port_hangout_19305) || (port == port_hangout_19306) ||
      (port == port_hangout_19307) || (port == port_hangout_19308) ||
      (port == port_hangout_19309))
    return 1;
  else
    return 0;
}

uint8_t check_hangout(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  if ((data_length > 24)) {
    if (((pkt_info->l4.protocol == IPPROTO_UDP) &&
         (is_hangout_udp_port(pkt_info->l4.port_src) ||
          is_hangout_udp_port(pkt_info->l4.port_dst))) ||
        ((pkt_info->l4.protocol == IPPROTO_TCP) &&
         (is_hangout_tcp_port(pkt_info->l4.port_src) ||
          is_hangout_tcp_port(pkt_info->l4.port_dst)))) {
      return PFWL_PROTOCOL_MATCHES;
    }
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
