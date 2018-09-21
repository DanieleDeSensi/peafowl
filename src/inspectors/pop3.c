/**
 * pop3.c
 *
 * Created on: 22/11/2012
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
#include <peafowl/inspectors/inspectors.h>

#include <stdio.h>
#include <string.h>

#define PFWL_DEBUG_POP3 0
#define debug_print(fmt, ...)                              \
  do {                                                     \
    if (PFWL_DEBUG_POP3) fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

#define PFWL_POP3_NUM_MESSAGES_TO_MATCH 3
#define PFWL_POP3_MIN_MESSAGE_LENGTH 3

#define PFWL_POP3_NUM_LEN3_MSGS 2
static const char* const length_3_msgs[PFWL_POP3_NUM_LEN3_MSGS] = {"+OK", "TOP"};

#define PFWL_POP3_NUM_LEN4_MSGS 13
static const char* const length_4_msgs[PFWL_POP3_NUM_LEN4_MSGS] = {
    "USER", "PASS", "QUIT", "STAT", "LIST", "RETR", "DELE",
    "NOOP", "RSET", "QUIT", "APOP", "UIDL", "-ERR"};

uint8_t check_pop3(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t) {
  if (pkt->l4prot != IPPROTO_TCP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  uint8_t i;
  if (data_length < PFWL_POP3_MIN_MESSAGE_LENGTH) {
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

  if (data_length >= 3) {
    for (i = 0; i < PFWL_POP3_NUM_LEN3_MSGS; i++) {
      if (strncasecmp((const char*)app_data, length_3_msgs[i], 3) == 0) {
        if (++t->num_pop3_matched_messages == PFWL_POP3_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  if (data_length >= 4) {
    for (i = 0; i < PFWL_POP3_NUM_LEN4_MSGS; i++) {
      if (strncasecmp((const char*)app_data, length_4_msgs[i], 4) == 0) {
        if (++t->num_pop3_matched_messages == PFWL_POP3_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
