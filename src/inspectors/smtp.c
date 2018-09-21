/**
 * smtp.c
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

#define PFWL_DEBUG_SMTP 0
#define debug_print(fmt, ...)                              \
  do {                                                     \
    if (PFWL_DEBUG_SMTP) fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

#define PFWL_SMTP_NUM_MESSAGES_TO_MATCH 3

#define PFWL_SMTP_NUM_RESPONSES 22

#define PFWL_SMTP_MAX_RESPONSE_LENGTH 3
static const char* const responses[PFWL_SMTP_NUM_RESPONSES] = {
    "500", "501", "502", "503", "504", "550", "551", "552",
    "553", "554", "211", "214", "220", "221", "250", "251",
    "252", "354", "421", "450", "451", "452"};

#define PFWL_SMTP_NUM_REQUESTS 11
#define PFWL_SMTP_MAX_REQUEST_LENGTH 5
static const char* const requests[PFWL_SMTP_NUM_REQUESTS] = {
    "EHLO ", "EXPN ", "HELO ", "HELP ", "MAIL ", "DATA ",
    "RCPT ", "RSET ", "NOOP ", "QUIT ", "VRFY "};

uint8_t check_smtp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t) {
  if (pkt->l4prot != IPPROTO_TCP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  uint8_t i;
  if (data_length < PFWL_SMTP_MAX_RESPONSE_LENGTH) {
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

  if (data_length >= PFWL_SMTP_MAX_RESPONSE_LENGTH) {
    for (i = 0; i < PFWL_SMTP_NUM_RESPONSES; i++) {
      if (strncasecmp((const char*)app_data, responses[i],
                      PFWL_SMTP_MAX_RESPONSE_LENGTH) == 0) {
        if (++t->num_smtp_matched_messages == PFWL_SMTP_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  if (data_length >= PFWL_SMTP_MAX_REQUEST_LENGTH) {
    for (i = 0; i < PFWL_SMTP_NUM_REQUESTS; i++) {
      if (strncasecmp((const char*)app_data, requests[i],
                      PFWL_SMTP_MAX_REQUEST_LENGTH) == 0) {
        if (++t->num_smtp_matched_messages == PFWL_SMTP_NUM_MESSAGES_TO_MATCH) {
          return PFWL_PROTOCOL_MATCHES;
        } else
          return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
