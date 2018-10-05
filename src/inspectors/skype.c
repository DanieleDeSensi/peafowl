/**
 * skype.c
 *
 * Created on: 29/06/2016
 *
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
 *  Copyright (C) 2016, Lorenzo Mangani (lorenzo.mangani@gmail.com), QXIP BV
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
#include <peafowl/inspectors/inspectors.h>

#include <stdio.h>
#include <string.h>

#define PFWL_DEBUG_SKYPE 0
#define debug_print(fmt, ...)                               \
  do {                                                      \
    if (PFWL_DEBUG_SKYPE) fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

uint8_t check_skype(const unsigned char* app_data, uint32_t data_length, pfwl_identification_result_t* pkt_info,
                    pfwl_tracking_informations_t* tracking_info, pfwl_inspector_accuracy_t accuracy, uint8_t *required_fields) {
  if (pkt_info->protocol_l4 != IPPROTO_UDP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  if (((data_length == 3) && ((app_data[2] & 0x0F) == 0x0d)) ||
      ((data_length >= 16) &&
       (app_data[0] != 0x30) /* Avoid invalid SNMP detection */
       && (app_data[2] == 0x02))) {
    return PFWL_PROTOCOL_MATCHES;
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
