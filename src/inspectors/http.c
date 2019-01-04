/*
 * http.c
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

#include <peafowl/flow_table.h>
#include <peafowl/inspectors/http_parser_joyent.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PFWL_DEBUG_HTTP 0

#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_HTTP)                                                       \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
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
    uint8_t
    pfwl_http_manage_pdu_reassembly(http_parser *parser, const char *at,
                                    size_t length,
                                    pfwl_http_internal_informations_t *infos) {
  if (infos->temp_buffer_dirty) {
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
    char *tmp = realloc(infos->temp_buffer, infos->temp_buffer_size + length);
    if (!tmp) {
      free(infos->temp_buffer);
      return 2;
    }
    infos->temp_buffer = (unsigned char *) tmp;
    memcpy(infos->temp_buffer + infos->temp_buffer_size, at, length);
    infos->temp_buffer_size += length;
  }

  if (parser->copy) {
    if (infos->temp_buffer == NULL) {
      infos->temp_buffer = malloc(length * sizeof(char));

      if (!infos->temp_buffer)
        return 2;
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
int on_url(http_parser *parser, const char *at, size_t length) {
  pfwl_http_internal_informations_t *infos =
      (pfwl_http_internal_informations_t *) parser->data;
  const unsigned char *real_data = (const unsigned char *) at;
  size_t real_length = length;
  uint8_t segmentation_result =
      pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
  if (segmentation_result == 0) {
    return 0;
  } else if (segmentation_result == 2) {
    return 1;
  } else if (infos->temp_buffer) {
    real_data = infos->temp_buffer;
    real_length = infos->temp_buffer_size;
    infos->temp_buffer_dirty = 1;
  }

  pfwl_field_string_set(parser->extracted_fields, PFWL_FIELDS_L7_HTTP_URL,
                        real_data, real_length);
  return 0;
}

#ifndef PFWL_DEBUG
static
#endif
    int
    on_field(http_parser *parser, const char *at, size_t length) {
  pfwl_http_internal_informations_t *infos =
      (pfwl_http_internal_informations_t *) parser->data;
  const unsigned char *real_data = (const unsigned char *) at;
  size_t real_length = length;
  uint8_t segmentation_result =
      pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
  if (segmentation_result == 0) {
    return 0;
  } else if (segmentation_result == 2) {
    return 1;
  } else if (infos->temp_buffer) {
    real_data = infos->temp_buffer;
    real_length = infos->temp_buffer_size;
    infos->temp_buffer_dirty = 1;
  }

  if (infos->headers_length == PFWL_HTTP_MAX_HEADERS) {
    return 1;
  }
  infos->headers[infos->headers_length].first.string.value = real_data;
  infos->headers[infos->headers_length].first.string.length = real_length;
  ++infos->headers_length;
  return 0;
}

#ifndef PFWL_DEBUG
static
#endif
    int
    on_value(http_parser *parser, const char *at, size_t length) {
  pfwl_http_internal_informations_t *infos =
      (pfwl_http_internal_informations_t *) parser->data;
  const unsigned char *real_data = (const unsigned char *) at;
  size_t real_length = length;
  uint8_t segmentation_result =
      pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
  if (segmentation_result == 0) {
    return 0;
  } else if (segmentation_result == 2) {
    return 1;
  } else if (infos->temp_buffer) {
    real_data = infos->temp_buffer;
    real_length = infos->temp_buffer_size;
    infos->temp_buffer_dirty = 1;
  }
  infos->headers[infos->headers_length - 1].second.string.value = real_data;
  infos->headers[infos->headers_length - 1].second.string.length = real_length;
  return 0;
}

#ifndef PFWL_DEBUG
static
#endif
    int
    on_body(http_parser *parser, const char *at, size_t length) {
  pfwl_http_internal_informations_t *infos =
      (pfwl_http_internal_informations_t *) parser->data;
  const unsigned char *real_data = (const unsigned char *) at;
  size_t real_length = length;
  uint8_t segmentation_result =
      pfwl_http_manage_pdu_reassembly(parser, at, length, infos);
  if (segmentation_result == 0) {
    return 0;
  } else if (segmentation_result == 2) {
    return 1;
  } else if (infos->temp_buffer) {
    real_data = infos->temp_buffer;
    real_length = infos->temp_buffer_size;
    infos->temp_buffer_dirty = 1;
  }

  pfwl_field_string_set(parser->extracted_fields, PFWL_FIELDS_L7_HTTP_BODY,
                        real_data, real_length);
  return 0;
}

/**
 * I decided to avoid the concept of subprotocol. This indeed can easily be
 * derived from host address so the user can include this identification
 * in its callback.
 */
uint8_t check_http(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private) {
  debug_print("%s\n", "-------------------------------------------");
  debug_print("%s\n", "[http.c] Executing HTTP inspector...");

  http_parser *parser = &(flow_info_private->http[pkt_info->l4.direction]);

  /**
   * We assume that pfwl_tracking_informations_t is initialized to zero, so if
   * data is NULL
   * we know that it has not been initialized and we initialize it.
   */
  if (parser->data == NULL) {
    http_parser_init(parser, HTTP_BOTH);
    bzero(&(flow_info_private->http_informations[pkt_info->l4.direction]),
          sizeof(pfwl_http_internal_informations_t));

    parser->extracted_fields = pkt_info->l7.protocol_fields;
    parser->data = flow_info_private->http_informations;
  }

  http_parser_settings x = {0};

  if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_HTTP_URL))
    x.on_url = on_url;
  else
    x.on_url = 0;

  if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_HTTP_BODY))
    x.on_body = on_body;
  else
    x.on_body = 0;

  if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_HTTP_HEADERS)) {
    x.on_header_field = on_field;
    x.on_header_value = on_value;
  } else {
    x.on_header_field = 0;
    x.on_header_value = 0;
  }

  x.on_headers_complete = 0;
  x.on_message_begin = 0;
  x.on_message_complete = 0;

  flow_info_private->http_informations->headers_length = 0;
  memset(flow_info_private->http_informations->headers, 0,
         sizeof(flow_info_private->http_informations->headers));

  http_parser_execute(parser, &x, (const char *) app_data, data_length);

  if (parser->http_errno == HPE_OK) {
    debug_print("%s\n", "[http.c] HTTP matches");
    pfwl_field_number_set(parser->extracted_fields,
                          PFWL_FIELDS_L7_HTTP_VERSION_MAJOR,
                          parser->http_major);
    pfwl_field_number_set(parser->extracted_fields,
                          PFWL_FIELDS_L7_HTTP_VERSION_MINOR,
                          parser->http_minor);
    pfwl_field_number_set(parser->extracted_fields,
                          PFWL_FIELDS_L7_HTTP_MSG_TYPE, parser->type);
    if (parser->type == HTTP_REQUEST) {
      pfwl_field_number_set(parser->extracted_fields,
                            PFWL_FIELDS_L7_HTTP_METHOD, parser->method);
    } else {
      pfwl_field_number_set(parser->extracted_fields,
                            PFWL_FIELDS_L7_HTTP_STATUS_CODE,
                            parser->status_code);
    }
    if (flow_info_private->http_informations->headers_length) {
      parser->extracted_fields[PFWL_FIELDS_L7_HTTP_HEADERS].present = 1;
      parser->extracted_fields[PFWL_FIELDS_L7_HTTP_HEADERS].mmap.values =
          flow_info_private->http_informations->headers;
      parser->extracted_fields[PFWL_FIELDS_L7_HTTP_HEADERS].mmap.length =
          flow_info_private->http_informations->headers_length;
    }
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
    if (flow_info_private->seen_syn == 0) {
      parser->data = NULL; // To force http_parser_init at next iteration
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    } else {
      return PFWL_PROTOCOL_NO_MATCHES;
    }
  }
}
