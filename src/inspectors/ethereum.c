/*
 * ethereum.c
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
#include <peafowl/utils.h>

#include <string.h>

static int has_eth_method(const unsigned char *app_data, size_t data_length) {
  data_length =
      PFWL_MIN(3 + 6, data_length); // 6 because of '\"web3_, 3 because of ' : '
  return pfwl_strnstr((const char *) app_data + 8, "\"shh_",
                      data_length) || // 8 because of "method"
         pfwl_strnstr((const char *) app_data + 8, "\"db_", data_length) ||
         pfwl_strnstr((const char *) app_data + 8, "\"eth_", data_length) ||
         pfwl_strnstr((const char *) app_data + 8, "\"net_", data_length) ||
         pfwl_strnstr((const char *) app_data + 8, "\"web3_", data_length);
}

uint8_t check_ethereum(pfwl_state_t *state, const unsigned char *app_data,
                       size_t data_length, pfwl_dissection_info_t *pkt_info,
                       pfwl_flow_info_private_t *flow_info_private) {
  unsigned char *method_start;
  if ((pfwl_strnstr((const char *) app_data, "\"worker\"", data_length) &&
       pfwl_strnstr((const char *) app_data, "\"eth1.0\"", data_length)) ||
      ((method_start = (unsigned char *) pfwl_strnstr(
            (const char *) app_data, "\"method\"", data_length)) &&
       has_eth_method(method_start, data_length - (method_start - app_data)))) {
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
