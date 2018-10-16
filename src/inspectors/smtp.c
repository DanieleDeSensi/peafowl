/*
 * smtp.c
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
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#include <stdio.h>
#include <string.h>

#define PFWL_DEBUG_SMTP 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_SMTP)                                                       \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

#define PFWL_SMTP_NUM_MESSAGES_TO_MATCH 3

#define PFWL_SMTP_NUM_RESPONSES 22

#define PFWL_SMTP_MAX_RESPONSE_LENGTH 3
static const char *const responses[PFWL_SMTP_NUM_RESPONSES] = {
    "500", "501", "502", "503", "504", "550", "551", "552",
    "553", "554", "211", "214", "220", "221", "250", "251",
    "252", "354", "421", "450", "451", "452"};

#define PFWL_SMTP_NUM_REQUESTS 11
#define PFWL_SMTP_MAX_REQUEST_LENGTH 5
static const char *const requests[PFWL_SMTP_NUM_REQUESTS] = {
    "EHLO ", "EXPN ", "HELO ", "HELP ", "MAIL ", "DATA ",
    "RCPT ", "RSET ", "NOOP ", "QUIT ", "VRFY "};

uint8_t check_smtp(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private) {
  uint8_t i;
  if (data_length < PFWL_SMTP_MAX_RESPONSE_LENGTH) {
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

  if (data_length >= PFWL_SMTP_MAX_RESPONSE_LENGTH) {
    for (i = 0; i < PFWL_SMTP_NUM_RESPONSES; i++) {
      if (strncasecmp((const char *) app_data, responses[i],
                      PFWL_SMTP_MAX_RESPONSE_LENGTH) == 0) {
        if (++flow_info_private->num_smtp_matched_messages ==
            PFWL_SMTP_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  if (data_length >= PFWL_SMTP_MAX_REQUEST_LENGTH) {
    for (i = 0; i < PFWL_SMTP_NUM_REQUESTS; i++) {
      if (strncasecmp((const char *) app_data, requests[i],
                      PFWL_SMTP_MAX_REQUEST_LENGTH) == 0) {
        if (++flow_info_private->num_smtp_matched_messages ==
            PFWL_SMTP_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
