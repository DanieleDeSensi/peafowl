/*
 * ethereum.c
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

#include <iostream>
#include <string.h>

using namespace rapidjson;

static bool isWorkerEth(Document* d){
  auto it = d->FindMember("worker");
  return it != d->MemberEnd() && !strcmp(it->value.GetString(), "eth1.0");
}

static int isEthMethod(const char *method, size_t methodLen) {
  if(methodLen < 5){
    return 0;
  }
  return !strncmp(method, "shh_" , 4) ||
         !strncmp(method, "db_"  , 3) ||
         !strncmp(method, "eth_" , 4) ||
         !strncmp(method, "net_" , 4) ||
         !strncmp(method, "web3_", 5);
}

uint8_t check_ethereum(pfwl_state_t *state, const unsigned char *app_data,
                       size_t data_length, pfwl_dissection_info_t *pkt_info,
                       pfwl_flow_info_private_t *flow_info_private) {
  if(flow_info_private->info_public->protocols_l7_num){
    if(flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_JSON_RPC){
      Document* d = static_cast<Document*>(flow_info_private->json_parser);
      assert(d);
      pfwl_string_t method;

      if((!pfwl_field_string_get(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_METHOD, &method) && isEthMethod((const char*) method.value, method.length)) ||
         isWorkerEth(d)){
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
