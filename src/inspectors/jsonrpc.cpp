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

#include <iostream>
#include "../external/rapidjson/stringbuffer.h"
#include "../external/rapidjson/writer.h"


#define PFWL_DEBUG_DISS_JSONRPC 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_DISS_JSONRPC)                                                 \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)


using namespace rapidjson;

bool hasField(Document& d, const char* field){
  auto it = d.FindMember(field);
  return it != d.MemberEnd();
}

const unsigned char* getFieldAsString(Document& d, const char* field){
  auto it = d.FindMember(field);
  if(it != d.MemberEnd()){
    StringBuffer sb;
    Writer<StringBuffer> writer(sb);
    it->value.Accept(writer);
    return reinterpret_cast<const unsigned char*>(sb.GetString());
  }else{
    return NULL;
  }
}

void setIfPresent(Document& d, pfwl_field_t* fields, pfwl_field_id_t fieldId, const char* fieldName){
  const unsigned char* fieldValue = getFieldAsString(d, fieldName);
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
    debug_print("%s\n", "Error while parsing JSON, it is not json-rpc.");
    return PFWL_PROTOCOL_NO_MATCHES;
  }else{
    enum protocol_check_statuses to_return = PFWL_PROTOCOL_NO_MATCHES;
    uint8_t version = 0;
    pfwl_jsonrpc_msg_type_t type = PFWL_JSONRPC_MSG_TYPE_NONE;
    const unsigned char* jsonrpc = getFieldAsString(*d, "jsonrpc");
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
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_VERSION)){
        pfwl_field_number_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_VERSION, version);
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_MSG_TYPE)){
        pfwl_field_number_set(pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_MSG_TYPE, type);
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_ID)){
        setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_ID, "id");
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_METHOD)){
        setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_METHOD, "method");
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_PARAMS)){
        setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_PARAMS, "params");
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_RESULT)){
        setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_RESULT, "result");
      }
      if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_JSON_RPC_ERROR)){
        setIfPresent(*d, pkt_info->l7.protocol_fields, PFWL_FIELDS_L7_JSON_RPC_ERROR, "error");
      }
      return PFWL_PROTOCOL_MATCHES;
    }else{
      return to_return;
    }
  }
}
