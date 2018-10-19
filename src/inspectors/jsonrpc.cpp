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

using namespace rapidjson;

const char* getField(Document& d, const char* field){
  auto it = d.FindMember(field);
  if(it != d.MemberEnd()){
    if(it->value.IsNull()){
      return "null";
    }else{
      return it->value.GetString();
    }
  }else{
    return NULL;
  }
}

typedef enum{
  PFWL_JSONRPC_MSG_TYPE_REQUEST = 0,
  PFWL_JSONRPC_MSG_TYPE_RESPONSE,
  PFWL_JSONRPC_MSG_TYPE_NOTIFICATION,
  PFWL_JSONRPC_MSG_TYPE_NONE, /// Not jsonrpc
}pfwl_jsonrpc_msg_type_t;

void jsonrpc_delete_parser(void* parser){
  delete static_cast<Document*>(parser);
}

uint8_t check_jsonrpc(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  // TODO: Check if 'in-situ' parsing is faster (https://github.com/Tencent/rapidjson/blob/master/doc/dom.md)
  Document* d;
  if(!flow_info_private->json_parser){
    d = new Document();
    flow_info_private->json_parser = static_cast<void*>(d);
  }else{
    d = static_cast<Document*>(flow_info_private->json_parser);
  }
  if (d->Parse((const char*) app_data).HasParseError()) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }else{
    enum protocol_check_statuses to_return = PFWL_PROTOCOL_NO_MATCHES;
    uint8_t version = 0;
    pfwl_jsonrpc_msg_type_t type = PFWL_JSONRPC_MSG_TYPE_NONE;
    const char* jsonrpc = getField(*d, "jsonrpc");
    const char *id = NULL, *method = NULL, *params = NULL, *result = NULL, *error = NULL;
    if(jsonrpc && !strcmp(jsonrpc, "2.0")){
      // JSON-RPC v2 check
      version = 2;
      id = getField(*d, "id");
      method = getField(*d, "method");
      if(method){
        if(id){
          type = PFWL_JSONRPC_MSG_TYPE_REQUEST;
        }else{
          type = PFWL_JSONRPC_MSG_TYPE_NOTIFICATION; // In 2.0 notifications are requests without id
        }
        to_return = PFWL_PROTOCOL_MATCHES;
      }else{
        result = getField(*d, "result");
        error = getField(*d, "error");
        if(id && (result || error)){
          type = PFWL_JSONRPC_MSG_TYPE_RESPONSE;
          to_return = PFWL_PROTOCOL_MATCHES;
        }else if(id){
          type = PFWL_JSONRPC_MSG_TYPE_NOTIFICATION;
          to_return = PFWL_PROTOCOL_MATCHES;
        }
      }
    }else{
      // JSON-RPC v1 check
      version = 1;
      id = getField(*d, "id");
      method = getField(*d, "method");
      params = getField(*d, "params");
      if(id && method && params){
        type = PFWL_JSONRPC_MSG_TYPE_REQUEST;
        to_return = PFWL_PROTOCOL_MATCHES;
      }else{
        result = getField(*d, "result");
        error = getField(*d, "error");
        if(id && result && error){
          type = PFWL_JSONRPC_MSG_TYPE_RESPONSE;
          to_return = PFWL_PROTOCOL_MATCHES;
        }else if(id){
          type = PFWL_JSONRPC_MSG_TYPE_NOTIFICATION;
          to_return = PFWL_PROTOCOL_MATCHES;
        }
      }
    }
    if(to_return == PFWL_PROTOCOL_MATCHES){
      // Set any required field
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_VERSION)){
        pfwl_field_number_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_VERSION, version);
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_MSG_TYPE)){
        pfwl_field_number_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_MSG_TYPE, type);
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_ID) && id){
        pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_ID, (const unsigned char*) id, strlen(id));
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_METHOD) && method){
        pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_METHOD, (const unsigned char*) method, strlen(method));
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_PARAMS)){
        params = getField(*d, "params"); // may be omitted in 2.0
        if(params){
          pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_PARAMS, (const unsigned char*) params, strlen(params));
        }
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_RESULT) && result){
        pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_RESULT, (const unsigned char*) result, strlen(result));
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_ERROR) && error){
        pfwl_field_string_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_ERROR, (const unsigned char*) error, strlen(error));
      }
      return PFWL_PROTOCOL_MATCHES;
    }else{
      return to_return;
    }
  }
}
