/*
 * whatsapp.c
 *
 * This protocol inspector is adapted from
 * the nDPI WhatsApp dissector (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/whatsapp.c)
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
#include <peafowl/inspectors/inspectors.h>

static uint8_t whatsapp_sequence[] = {
    0x45, 0x44, 0x0, 0x01, 0x0, 0x0, 0x02, 0x08,
    0x0, 0x57, 0x41, 0x02, 0x0, 0x0, 0x0
 };

#define MIN(x, y) ({	       \
      __typeof__ (x) _x = (x); \
      __typeof__ (y) _y = (y); \
      _x < _y ? _x : _y;       \
})

uint8_t check_whatsapp(const unsigned char* app_data, uint32_t data_length, pfwl_identification_result_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info, pfwl_inspector_accuracy_t accuracy, uint8_t *required_fields){
  if(tracking_info->whatsapp_matched_sequence < sizeof(whatsapp_sequence)) {
    if(memcmp(app_data, &whatsapp_sequence[tracking_info->whatsapp_matched_sequence], 
      MIN(sizeof(whatsapp_sequence) - tracking_info->whatsapp_matched_sequence, data_length))) {
      return PFWL_PROTOCOL_NO_MATCHES;
    } else {
      tracking_info->whatsapp_matched_sequence += data_length;
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    }
  } else {
    return PFWL_PROTOCOL_MATCHES;
  }
}
