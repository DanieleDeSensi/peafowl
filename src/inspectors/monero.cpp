/*
 * monero.c
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

#include <string.h>

// https://moneroexamples.github.io/python-json-rpc/
static const char* moneroMethods[] = {
  "getbalance",
  "query_key",
  "get_payments",
  "getaddress",
  "incoming_transfers",
  "transfer",
  "getheight",
  "query_key",
  "mining_status",
  "getlastblockheader",
  "getblockheaderbyhash",
  "getblockheaderbyheight",
  "getblock",
  "get_info",
  "get_connections",
};

// https://github.com/xmrig/xmrig-proxy/blob/master/doc/STRATUM.md
static const char* moneroStratumMethods[] = {
  "login",
  "job",
  "submit",
  "keepalived"
};

static bool isMoneroMethod(const char *method, size_t methodLen) {
  size_t numMethods = sizeof(moneroMethods) / sizeof(moneroMethods[0]);
  for(size_t i = 0; i < numMethods; i++){
    if(!strncmp(method, moneroMethods[i], methodLen)){
       return true;
    }
  }
  return false;
}

static bool isMoneroStratumMethod(const char *method, size_t methodLen){
  size_t numMethods = sizeof(moneroStratumMethods) / sizeof(moneroStratumMethods[0]);
  for(size_t i = 0; i < numMethods; i++){
    if(!strncmp(method, moneroStratumMethods[i], methodLen)){
       return true;
    }
  }
  return false;
}
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define MONERO_MAGIC_COOKIE 0x28721586
#elif __BYTE_ORDER == __BIG_ENDIAN
#define MONERO_MAGIC_COOKIE 0x86157228
#else
#error "Please fix <bits/endian.h>"
#endif

uint8_t check_monero(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private) {
  // Magic number: https://github.com/monero-project/monero/blob/master/src/p2p/p2p_protocol_defs.h
  if (*((uint32_t *) app_data) == MONERO_MAGIC_COOKIE) {
    return PFWL_PROTOCOL_MATCHES;
  }else if(flow_info_private->info_public->protocols_l7_num){
    if(flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_JSON_RPC){
      pfwl_string_t method;
      if((!pfwl_field_string_get(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_METHOD, &method) &&
          (isMoneroMethod((const char*) method.value, method.length) || isMoneroStratumMethod((const char*) method.value, method.length)))){
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
