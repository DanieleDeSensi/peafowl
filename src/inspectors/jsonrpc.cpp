/*
 * jsonrpc.c
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

#include "../external/rapidjson/document.h"
#include "../external/rapidjson/error/en.h"

#include <iostream>
#include "../external/rapidjson/stringbuffer.h"
#include "../external/rapidjson/writer.h"

#define PFWL_DEBUG_DISS_JSONRPC 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_DISS_JSONRPC)                                               \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)


using namespace rapidjson;

bool hasField(Document& d, const char* field){
  auto it = d.FindMember(field);
  return it != d.MemberEnd();
}

const unsigned char* getFieldAsString(Document& d, pfwl_field_id_t fieldId, const char* field, int persistent, pfwl_flow_info_private_t* flow_info_private){
  auto it = d.FindMember(field);
  if(it != d.MemberEnd()){
    if(it->value.IsString() || it->value.IsNumber()){      
      return reinterpret_cast<const unsigned char*>(it->value.GetString());
    }else{
      if(persistent){
        size_t position = fieldId - PFWL_FIELDS_L7_JSON_RPC_FIRST - 1;
        StringBuffer* sb;
        if(!flow_info_private->json_stringbuffers[position]){
          sb = new StringBuffer();
          flow_info_private->json_stringbuffers[position] = static_cast<void*>(sb);
        }else{
          sb = static_cast<StringBuffer*>(flow_info_private->json_stringbuffers[position]);
          sb->Clear();
        }
        Writer<StringBuffer> writer(*sb);
        it->value.Accept(writer);
        return reinterpret_cast<const unsigned char*>(sb->GetString());
      }else{
        StringBuffer sb;
        Writer<StringBuffer> writer(sb);
        it->value.Accept(writer);
        return reinterpret_cast<const unsigned char*>(sb.GetString());
      }
    }
  }else{
    return NULL;
  }
}

void setIfPresent(Document& d, pfwl_field_t* fields, pfwl_field_id_t fieldId, const char* fieldName, pfwl_flow_info_private_t* flow_info_private){
  const unsigned char* fieldValue = getFieldAsString(d, fieldId, fieldName, 1, flow_info_private);
  if(fieldValue){
    pfwl_field_string_set(fields, fieldId, fieldValue, strlen((const char*) fieldValue));
  }
}

typedef enum{
  PFWL_JSONRPC_MSG_TYPE_REQUEST = 0,
  PFWL_JSONRPC_MSG_TYPE_RESPONSE,
  PFWL_JSONRPC_MSG_TYPE_NOTIFICATION,
  PFWL_JSONRPC_MSG_TYPE_NONE, /// Not jsonrpc
}pfwl_jsonrpc_msg_type_t;

static void jsonrpc_flow_cleaner(pfwl_flow_info_private_t *flow_info_private){
  for(size_t i = PFWL_FIELDS_L7_JSON_RPC_FIRST + 1; i < PFWL_FIELDS_L7_JSON_RPC_LAST; i++){
    size_t position = i - PFWL_FIELDS_L7_JSON_RPC_FIRST - 1;
    if(flow_info_private->json_stringbuffers[position]){
      delete static_cast<StringBuffer*>(flow_info_private->json_stringbuffers[position]);
    }
  }
  if(flow_info_private->json_parser){
    delete static_cast<Document*>(flow_info_private->json_parser);
  }
}

static bool isJsonCt(const pfwl_string_t& ct){
  return !strncmp(reinterpret_cast<const char*>(ct.value), "application/json-rpc"   , ct.length) ||
         !strncmp(reinterpret_cast<const char*>(ct.value), "application/json"       , ct.length) ||
         !strncmp(reinterpret_cast<const char*>(ct.value), "application/jsonrequest", ct.length);
}

typedef enum{
  JRPC_HTTP_MAYBE = 0,
  JRPC_HTTP_NO,
  JRPC_HTTP_MORE_DATA,
}JsonRpcOverHttpCheck;

JsonRpcOverHttpCheck check_jsonrpc_over_http(pfwl_dissection_info_t *pkt_info,
                                             pfwl_flow_info_private_t *flow_info_private,
                                             const unsigned char* &http_body,
                                             size_t& http_body_length){
  debug_print("%s", "Checking json over http\n");
  if(flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_HTTP){
    // Previous protocol was HTTP, let's check if it was carrying json stuff
    debug_print("%s", "Previous proto was HTTP\n");
    int64_t http_method;
    if(!pfwl_field_number_get(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_HTTP_METHOD, &http_method) &&
       http_method == HTTP_POST){
      debug_print("%s", "HTTP Method is POST\n");
      pfwl_string_t http_ct;
      if(!pfwl_http_get_header(pkt_info, "Content-Type", &http_ct) && isJsonCt(http_ct)){
        debug_print("%s", "HTTP content type was json\n");
        pfwl_string_t http_body_string;
        if(!pfwl_field_string_get(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_HTTP_BODY, &http_body_string)){
          debug_print("%s", "HTTP has body, checking if it is jsonrpc\n");
          http_body = http_body_string.value;
          http_body_length = http_body_string.length;
          return JRPC_HTTP_MAYBE;
        }else{
          debug_print("%s", "HTTP has not body\n");
          return JRPC_HTTP_NO;
        }
      }else{
        debug_print("%s", "HTTP content type was not json\n");
        return JRPC_HTTP_MORE_DATA;
      }
    }else{
      debug_print("%s", "HTTP method was not POST but may be POST in the future\n");
      return JRPC_HTTP_MORE_DATA;
    }
  }else if(BITTEST(flow_info_private->possible_matching_protocols, PFWL_PROTO_L7_HTTP) &&
           flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_NOT_DETERMINED){
    // Could still become HTTP
    debug_print("%s", "Previous proto may still be HTTP\n");
    return JRPC_HTTP_MORE_DATA;
  }else{
    debug_print("%s", "Previous proto was not HTTP\n");
    return JRPC_HTTP_NO;
  }
}

uint8_t check_jsonrpc(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  // TODO: Check if 'in-situ' parsing is faster (https://github.com/Tencent/rapidjson/blob/master/doc/dom.md)
  // TODO: Manage segmented jsons (some in stratum.pcap)
  Document* d = NULL;
  if(!flow_info_private->json_parser){
    d = new Document();
    flow_info_private->json_parser = static_cast<void*>(d);
    flow_info_private->flow_cleaners_dissectors[PFWL_PROTO_L7_JSON_RPC] = &jsonrpc_flow_cleaner;
  }else{
    d = static_cast<Document*>(flow_info_private->json_parser);
  }

  ParseResult ok = d->Parse<kParseNumbersAsStringsFlag>((const char*) app_data, data_length);
  if(!ok || !d->IsObject()){ 
    debug_print("%s\n", "It is not json-RPC");
    if(PFWL_DEBUG_DISS_JSONRPC)
      fprintf(stderr, "JSON parse error: %s (%lu)\n", GetParseError_En(ok.Code()), ok.Offset());
    // Check if JSON over HTTP
    const unsigned char* http_body;
    size_t http_body_length;
    switch(check_jsonrpc_over_http(pkt_info, flow_info_private, http_body, http_body_length)){
    case JRPC_HTTP_MAYBE:{
      app_data = http_body;
      data_length = http_body_length;
      ok = d->Parse<kParseNumbersAsStringsFlag>((const char*) app_data, data_length);
      if(!ok){
        debug_print("%s\n", "It is not json-RPC");
        if(PFWL_DEBUG_DISS_JSONRPC)
          fprintf(stderr, "JSON parse error: %s (%lu)\n", GetParseError_En(ok.Code()), ok.Offset());
        return PFWL_PROTOCOL_NO_MATCHES;
      }
    }break;
    case JRPC_HTTP_NO:{
      return PFWL_PROTOCOL_NO_MATCHES;
    }
    case JRPC_HTTP_MORE_DATA:{
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    }
    }
  }

  enum protocol_check_statuses to_return = PFWL_PROTOCOL_NO_MATCHES;
  uint8_t version = 0;
  pfwl_jsonrpc_msg_type_t type = PFWL_JSONRPC_MSG_TYPE_NONE;
  const unsigned char* jsonrpc = getFieldAsString(*d, PFWL_FIELDS_L7_NUM, "jsonrpc", 0, flow_info_private);
  bool hasId = false;

  //const char *id = NULL, *method = NULL, *params = NULL, *result = NULL, *error = NULL;
  if(jsonrpc && !strcmp((const char*) jsonrpc, "2.0")){
    debug_print("%s\n", "It seems JSON-RPC v2.0.");
    // JSON-RPC v2 check
    version = 2;
    hasId = hasField(*d, "id");
    if(hasField(*d, "method")){
      debug_print("%s\n", "Method field found.");
      if(hasId){
        debug_print("%s\n", "Id found, is a request.");
        type = PFWL_JSONRPC_MSG_TYPE_REQUEST;
      }else{
        debug_print("%s\n", "Id not found, is a notification.");
        type = PFWL_JSONRPC_MSG_TYPE_NOTIFICATION; // In 2.0 notifications are requests without id
      }
      to_return = PFWL_PROTOCOL_MATCHES;
    }else{
      if(hasId && (hasField(*d, "result") || hasField(*d, "error"))){
        debug_print("%s\n", "Result or error found, is a response.");
        type = PFWL_JSONRPC_MSG_TYPE_RESPONSE;
        to_return = PFWL_PROTOCOL_MATCHES;
      }
    }
  }else{
    // JSON-RPC v1 check
    debug_print("%s\n", "It seems JSON-RPC v1.0.");
    version = 1;
    hasId = hasField(*d, "id");
    if(hasId && hasField(*d, "method") && hasField(*d, "params")){
      debug_print("%s\n", "Id, method and params found, is a request.");
      type = PFWL_JSONRPC_MSG_TYPE_REQUEST;
      to_return = PFWL_PROTOCOL_MATCHES;
    }else{
      if(hasId && hasField(*d, "result") && hasField(*d, "error")){
        debug_print("%s\n", "Id, result and error found, is a response.");
        type = PFWL_JSONRPC_MSG_TYPE_RESPONSE;
        to_return = PFWL_PROTOCOL_MATCHES;
      }else if(hasId){
        debug_print("%s\n", "Id found, is a notification.");
        type = PFWL_JSONRPC_MSG_TYPE_NOTIFICATION;
        to_return = PFWL_PROTOCOL_MATCHES;
      }else{
        debug_print("%s\n", "Nothing found, it is not JSON-RPC.");
      }
    }
  }

  // Set any required field
  if(to_return == PFWL_PROTOCOL_MATCHES){
    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_JSON_RPC_VERSION)){
      pfwl_field_number_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_VERSION, version);
    }
    if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_JSON_RPC_MSG_TYPE)){
      pfwl_field_number_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_MSG_TYPE, type);
    }
    if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_JSON_RPC_ID)){
      setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_ID, "id", flow_info_private);
    }
    if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_JSON_RPC_METHOD)){
      setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_METHOD, "method", flow_info_private);
    }
    if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_JSON_RPC_PARAMS)){
      setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_PARAMS, "params", flow_info_private);
    }
    if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_JSON_RPC_RESULT)){
      setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_RESULT, "result", flow_info_private);
    }
    if(pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_JSON_RPC_ERROR)){
      setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_ERROR, "error", flow_info_private);
    }
    return PFWL_PROTOCOL_MATCHES;
  }else{
    return to_return;
  }
}
