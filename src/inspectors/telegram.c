/*
 * telegram.c
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
#include <peafowl/inspectors/inspectors.h>

uint8_t check_telegram(dpi_library_state_t* state, dpi_pkt_infos_t* pkt,
                      const unsigned char* app_data, uint32_t data_length,
                      dpi_tracking_informations_t* t){
  if (!data_length) {
    return DPI_PROTOCOL_MORE_DATA_NEEDED;
  } 

  if (pkt->l4prot != IPPROTO_TCP) {
    return DPI_PROTOCOL_NO_MATCHES;
  }

  if (data_length > 56) {
    uint16_t dport = ntohs(pkt->dstport);

    if (app_data[0] == 0xef && (dport == 443 || dport == 80 || dport == 25)) {
      if (app_data[1] == 0x7f || app_data[1]*4 <= data_length - 1) {
        return DPI_PROTOCOL_MATCHES;
      }
      return DPI_PROTOCOL_MORE_DATA_NEEDED;
    }
  } 
  return DPI_PROTOCOL_NO_MATCHES;
}
