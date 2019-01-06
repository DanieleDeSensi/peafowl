/*
 * zcash.c
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
#include "../external/rapidjson/document.h"

using namespace rapidjson;

static bool isZcashMethod(const char *method, size_t methodLen) {
  if(methodLen < 2){
    return false;
  }
  return !strncmp(method, "z_" , methodLen);
}

uint8_t check_zcash(pfwl_state_t *state, const unsigned char *app_data,
                    size_t data_length, pfwl_dissection_info_t *pkt_info,
                    pfwl_flow_info_private_t *flow_info_private) {
  if(flow_info_private->info_public->protocols_l7_num){
    if(flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_JSON_RPC){
      pfwl_string_t method;
      if((!pfwl_field_string_get(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_METHOD, &method) &&
          isZcashMethod((const char*) method.value, method.length))){
        return PFWL_PROTOCOL_MATCHES;
      }
    }else if(BITTEST(flow_info_private->possible_matching_protocols, PFWL_PROTO_L7_JSON_RPC) &&
             flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_NOT_DETERMINED){
      // Could still become JSON-RPC
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    }
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
