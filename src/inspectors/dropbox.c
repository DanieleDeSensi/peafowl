/*
 * dropbox.c
 *
 * This protocol inspector is adapted from
 * the nDPI Dropbox dissector
 * (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/dropbox.c)
 *
 * Infos about Dropbox LAN sync protocol:
 * https://blogs.dropbox.com/tech/2015/10/inside-lan-sync/
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

static inline uint8_t lowCheck(const char *app_data, size_t data_length) {
  return pfwl_strnstr((const char *) app_data, "\"host_int\"", data_length) ? 1 : 0;
}

static inline uint8_t midCheck(const char *app_data, size_t data_length) {
  return pfwl_strnstr((const char *) app_data, "\"namespaces\"", data_length) ? 1 : 0;
}

static inline uint8_t highCheck(const char *app_data, size_t data_length) {
  return (pfwl_strnstr((const char *) app_data, "\"version\"", data_length) ? 1 : 0) &&
         (pfwl_strnstr((const char *) app_data, "\"port\"", data_length) ? 1 : 0);
}

static inline uint8_t hasDropboxFields(const char *app_data,
                                       size_t data_length,
                                       pfwl_dissector_accuracy_t accuracy) {
  switch (accuracy) {
  case PFWL_DISSECTOR_ACCURACY_LOW: {
    return lowCheck(app_data, data_length);
  } break;
  case PFWL_DISSECTOR_ACCURACY_MEDIUM: {
    return lowCheck(app_data, data_length) && midCheck(app_data, data_length);
  } break;
  case PFWL_DISSECTOR_ACCURACY_HIGH: {
    return lowCheck(app_data, data_length) && midCheck(app_data, data_length) && highCheck(app_data, data_length);
  } break;
  default: { return 0; }
  }
}

uint8_t check_dropbox(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  pfwl_dissector_accuracy_t accuracy =
      state->inspectors_accuracy[PFWL_PROTO_L7_DROPBOX];
  // Discovery
  if (pkt_info->l4.port_src == port_dropbox &&
      pkt_info->l4.port_dst == port_dropbox && data_length > 2 &&
      hasDropboxFields((const char *) app_data, data_length, accuracy)) {
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
