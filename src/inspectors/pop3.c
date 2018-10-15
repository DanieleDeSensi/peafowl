/*
 * pop3.c
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

#define PFWL_DEBUG_POP3 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_POP3)                                                       \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

#define PFWL_POP3_NUM_MESSAGES_TO_MATCH 3
#define PFWL_POP3_MIN_MESSAGE_LENGTH 3

#define PFWL_POP3_NUM_LEN3_MSGS 2
static const char *const length_3_msgs[PFWL_POP3_NUM_LEN3_MSGS] = {"+OK",
                                                                   "TOP"};

#define PFWL_POP3_NUM_LEN4_MSGS 13
static const char *const length_4_msgs[PFWL_POP3_NUM_LEN4_MSGS] = {
    "USER", "PASS", "QUIT", "STAT", "LIST", "RETR", "DELE",
    "NOOP", "RSET", "QUIT", "APOP", "UIDL", "-ERR"};

uint8_t check_pop3(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private) {
  uint8_t i;
  if (data_length < PFWL_POP3_MIN_MESSAGE_LENGTH) {
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

  if (data_length >= 3) {
    for (i = 0; i < PFWL_POP3_NUM_LEN3_MSGS; i++) {
      if (strncasecmp((const char *) app_data, length_3_msgs[i], 3) == 0) {
        if (++flow_info_private->num_pop3_matched_messages ==
            PFWL_POP3_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  if (data_length >= 4) {
    for (i = 0; i < PFWL_POP3_NUM_LEN4_MSGS; i++) {
      if (strncasecmp((const char *) app_data, length_4_msgs[i], 4) == 0) {
        if (++flow_info_private->num_pop3_matched_messages ==
            PFWL_POP3_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
