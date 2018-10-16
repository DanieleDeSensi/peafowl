/**
 * skype.c
 *
 * Created on: 29/06/2016
 *
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
 *  Copyright (C) 2016, Lorenzo Mangani (lorenzo.mangani@gmail.com), QXIP BV
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

#include <stdio.h>
#include <string.h>

#define PFWL_DEBUG_SKYPE 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_SKYPE)                                                      \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

uint8_t check_skype(pfwl_state_t *state, const unsigned char *app_data,
                    size_t data_length, pfwl_dissection_info_t *pkt_info,
                    pfwl_flow_info_private_t *flow_info_private) {
  if (((data_length == 3) && ((app_data[2] & 0x0F) == 0x0d)) ||
      ((data_length >= 16) &&
       (app_data[0] != 0x30) /* Avoid invalid SNMP detection */
       && (app_data[2] == 0x02))) {
    return PFWL_PROTOCOL_MATCHES;
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
