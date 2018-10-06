/*
 * dhcpv6.c
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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
#include <peafowl/peafowl.h>
#include <peafowl/inspectors/inspectors.h>

uint8_t check_dhcpv6(const unsigned char* app_data, uint32_t data_length, pfwl_dissection_info_t* pkt_info,
                     pfwl_tracking_informations_t* tracking_info, pfwl_inspector_accuracy_t accuracy, uint8_t *required_fields) {
  if (pkt_info->protocol_l4 != IPPROTO_UDP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  if (data_length >= 4 &&
      ((pkt_info->port_src == port_dhcpv6_1 && pkt_info->port_dst == port_dhcpv6_2) ||
       (pkt_info->port_src == port_dhcpv6_2 && pkt_info->port_dst == port_dhcpv6_1)) &&
      (app_data)[0] >= 1 && (app_data)[0] <= 13) {
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
