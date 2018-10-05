/*
 * http.c
 *
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
 *
 *  This file is part of Peafowl.
 *
 *  Peafowl is free software: you can redistribute it and/or
 *  modify it under the terms of the Lesser GNU General Public
 *  License as published by the Free Software Foundation, either
 *  version 3 of the License, or (at your option) any later version.

 *  Peafowl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  Lesser GNU General Public License for more details.
 *
 *  You should have received a copy of the Lesser GNU General Public
 *  License along with Peafowl.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================================================================
 */

#include <peafowl/peafowl.h>
#include <peafowl/flow_table.h>
#include <peafowl/inspectors/http_parser_joyent.h>
#include <peafowl/inspectors/inspectors.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PFWL_DEBUG_HTTP 0

#define debug_print(fmt, ...)                              \
  do {                                                     \
    if (PFWL_DEBUG_HTTP) fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

/**
 * Manages the case in which an HTTP request/response is divided in more
 * segments.
 * @return 1 if the HTTP field of interest is complete, 0 if more segments are
 * needed, 2 if an error occurred.
 */
#ifndef PFWL_DEBUG
static
#endif
uint8_t pfwl_http_manage_pdu_reassembly(http_parser* parser,
                                    const char* at,
                                    size_t length,
                                    pfwl_http_internal_informations_t* infos) {
  if(infos->temp_buffer_dirty){
    free(infos->temp_buffer);
    infos->temp_buffer = NULL;
    infos->temp_buffer_size = 0;
    infos->temp_buffer_dirty = 0;
  }

  /**
   * If I have old data present, I have anyway to concatenate the new data.
   * Then, if copy==0, I can free the data after the use, otherwise I simply
   * return and I wait for other data.
   */
  if (infos->temp_buffer) {
    char* tmp = realloc(infos->temp_buffer, infos->temp_buffer_size + length);
    if (!tmp) {
      free(infos->temp_buffer);
      return 2;
    }
    infos->temp_buffer = tmp;
    memcpy(infos->temp_buffer + infos->temp_buffer_size, at, length);
    infos->temp_buffer_size += length;
  }

  if (parser->copy) {
    if (infos->temp_buffer == NULL) {
      infos->temp_buffer = malloc(length * sizeof(char));

      if (!infos->temp_buffer) return 2;
      memcpy(infos->temp_buffer, at, length);
      infos->temp_buffer_size = length;
    }
    return 0;
  }
  return 1;
}

#ifndef PFWL_DEBUG
static
#endif
int on_url(http_parser* parser, const char* at, size_t length) {
  pfwl_http_internal_informations_t* infos = (pfwl_http_internal_informations_t*) parser->data;

  parser->extracted_fields[PFWL_FIELDS_HTTP_VERSION_MAJOR].num = parser->http_major;
  parser->extracted_fields[PFWL_FIELDS_HTTP_VERSION_MINOR].num = parser->http_minor;
  parser->extracted_fields[PFWL_FIELDS_HTTP_MSG_TYPE].num = parser->type;
  if (parser->type == HTTP_REQUEST){
    parser->extracted_fields[PFWL_FIELDS_HTTP_METHOD].num = parser->method;
  }else{
    parser->extracted_fields[PFWL_FIELDS_HTTP_STATUS_CODE].num = parser->status_code;
  }

  const char* real_data = at;
  size_t real_length = length;
  uint8_t segmentation_result = pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
  if (segmentation_result == 0) {
    return 0;
  } else if (segmentation_result == 2) {
    return 1;
  } else if (infos->temp_buffer) {
    real_data = infos->temp_buffer;
    real_length = infos->temp_buffer_size;
    infos->temp_buffer_dirty = 1;
  }

  parser->extracted_fields[PFWL_FIELDS_HTTP_URL].str.s = real_data;
  parser->extracted_fields[PFWL_FIELDS_HTTP_URL].str.len = real_length;

  return 0;
}

static pfwl_fields_http field_to_enum(const char* fieldname, size_t fieldlen){
  //TODO Use UTHash
  if(!strncmp(fieldname, "Content-Type", fieldlen)){
    return PFWL_FIELDS_HTTP_CONTENT_TYPE;
  }else if (!strncmp(fieldname, "User-Agent", fieldlen)){
    return PFWL_FIELDS_HTTP_USER_AGENT;
  }

  return PFWL_FIELDS_HTTP_NUM;
}

#ifndef PFWL_DEBUG
static
#endif
int on_field(http_parser* parser, const char* at, size_t length) {
  pfwl_http_internal_informations_t* infos =
      (pfwl_http_internal_informations_t*)parser->data;
  parser->hdr_field = PFWL_FIELDS_HTTP_NUM;

  const char* real_data = at;
  size_t real_length = length;
  uint8_t segmentation_result = pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
  if (segmentation_result == 0) {
    return 0;
  } else if (segmentation_result == 2) {
    return 1;
  } else if (infos->temp_buffer) {
    real_data = infos->temp_buffer;
    real_length = infos->temp_buffer_size;
    infos->temp_buffer_dirty = 1;
  }

  pfwl_fields_http field = field_to_enum(real_data, real_length);
  if (field < PFWL_FIELDS_HTTP_NUM && parser->required_fields[field]) {
    parser->hdr_field = field;
  }
  return 0;
}

#ifndef PFWL_DEBUG
static
#endif
int on_value(http_parser* parser, const char* at, size_t length) {
  if (parser->hdr_field < PFWL_FIELDS_HTTP_NUM) {
    pfwl_http_internal_informations_t* infos = (pfwl_http_internal_informations_t*) parser->data;

    parser->extracted_fields[PFWL_FIELDS_HTTP_VERSION_MAJOR].num = parser->http_major;
    parser->extracted_fields[PFWL_FIELDS_HTTP_VERSION_MINOR].num = parser->http_minor;
    parser->extracted_fields[PFWL_FIELDS_HTTP_MSG_TYPE].num = parser->type;
    if (parser->type == HTTP_REQUEST){
      parser->extracted_fields[PFWL_FIELDS_HTTP_METHOD].num = parser->method;
    }else{
      parser->extracted_fields[PFWL_FIELDS_HTTP_STATUS_CODE].num = parser->status_code;
    }

    const char* real_data = at;
    size_t real_length = length;
    uint8_t segmentation_result = pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
    if (segmentation_result == 0) {
      return 0;
    } else if (segmentation_result == 2) {
      return 1;
    } else if (infos->temp_buffer) {
      real_data = infos->temp_buffer;
      real_length = infos->temp_buffer_size;
      infos->temp_buffer_dirty = 1;
    }

    parser->extracted_fields[parser->hdr_field].str.s = real_data;
    parser->extracted_fields[parser->hdr_field].str.len = real_length;

  }
  return 0;
}

#ifndef PFWL_DEBUG
static
#endif
int on_body(http_parser* parser, const char* at, size_t length) {
  pfwl_http_internal_informations_t* infos = (pfwl_http_internal_informations_t*) parser->data;

  parser->extracted_fields[PFWL_FIELDS_HTTP_VERSION_MAJOR].num = parser->http_major;
  parser->extracted_fields[PFWL_FIELDS_HTTP_VERSION_MINOR].num = parser->http_minor;
  parser->extracted_fields[PFWL_FIELDS_HTTP_MSG_TYPE].num = parser->type;
  if (parser->type == HTTP_REQUEST){
    parser->extracted_fields[PFWL_FIELDS_HTTP_METHOD].num = parser->method;
  }else{
    parser->extracted_fields[PFWL_FIELDS_HTTP_STATUS_CODE].num = parser->status_code;
  }

  const char* real_data = at;
  size_t real_length = length;
  uint8_t segmentation_result = pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
  if (segmentation_result == 0) {
    return 0;
  } else if (segmentation_result == 2) {
    return 1;
  } else if (infos->temp_buffer) {
    real_data = infos->temp_buffer;
    real_length = infos->temp_buffer_size;
    infos->temp_buffer_dirty = 1;
  }

  parser->extracted_fields[PFWL_FIELDS_HTTP_BODY].str.s = real_data;
  parser->extracted_fields[PFWL_FIELDS_HTTP_BODY].str.len = real_length;

  return 0;
}

/**
 * I decided to avoid the concept of subprotocol. This indeed can easily be
 * derived from host address so the user can include this identification
 * in its callback.
 */
uint8_t check_http(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t *required_fields) {
  if (pkt_info->protocol_l4 != IPPROTO_TCP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  debug_print("%s\n", "-------------------------------------------");
  debug_print("%s\n", "[http.c] Executing HTTP inspector...");

  http_parser* parser = &(tracking_info->http[pkt_info->direction]);

  /**
   * We assume that pfwl_tracking_informations_t is initialized to zero, so if
   * data is NULL
   * we know that it has not been initialized and we initialize it.
   */
  if (parser->data == NULL) {
    http_parser_init(parser, HTTP_BOTH);
    bzero(&(tracking_info->http_informations[pkt_info->direction]),
          sizeof(pfwl_http_internal_informations_t));

    parser->required_fields = required_fields;
    parser->extracted_fields = pkt_info->protocol_fields.http;
    parser->data = tracking_info->http_informations;
  }

  http_parser_settings x = {0};

  if (required_fields[PFWL_FIELDS_HTTP_URL])
    x.on_url = on_url;
  else
    x.on_url = 0;

  if (required_fields[PFWL_FIELDS_HTTP_BODY])
    x.on_body = on_body;
  else
    x.on_body = 0;

  if (required_fields[PFWL_FIELDS_HTTP_CONTENT_TYPE] || required_fields[PFWL_FIELDS_HTTP_USER_AGENT]) { // TODO Find a simpler way to check all Header fields
    x.on_header_field = on_field;
    x.on_header_value = on_value;
  } else {
    x.on_header_field = 0;
    x.on_header_value = 0;
  }

  x.on_headers_complete = 0;
  x.on_message_begin = 0;
  x.on_message_complete = 0;

  http_parser_execute(parser, &x, (const char*)app_data, data_length);

  if (parser->http_errno == HPE_OK) {
    debug_print("%s\n", "[http.c] HTTP matches");
    return PFWL_PROTOCOL_MATCHES;
  } else {
    debug_print("[http.c] HTTP doesn't matches. Error: %s\n",
                http_errno_description(parser->http_errno));
    /**
     * If the library didn't see the connection from the beginning,
     * the inspector is not aligned with the current state of the protocol
     * so we wait for new data, instead of returning a NO_MATCHES matches simply
     * because we didn't analyzed the connection from the beginning. For
     * example,
     * if we start looking the flow in the middle of a large file transfer,
     * the inspector is not able to determine if the flow is HTTP or not.
     * Therefore, in this case, we keep inspecting also the successive
     * packets. Anyway, after the maximum number of trials specified by the
     * user, if we still didn't found the protocol, the library will mark
     * the flow as unknown.
     */
    if (tracking_info->seen_syn == 0) {
      http_parser_init(parser, HTTP_BOTH);
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    } else {
      return PFWL_PROTOCOL_NO_MATCHES;
    }
  }
}
