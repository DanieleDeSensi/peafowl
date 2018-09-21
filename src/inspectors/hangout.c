/*
 * hangout.c
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

static uint8_t is_hangout_udp_port(uint16_t port) {
  if((port == port_hangout_19302) || 
     (port == port_hangout_19303) || 
     (port == port_hangout_19304) || 
     (port == port_hangout_19305) || 
     (port == port_hangout_19306) || 
     (port == port_hangout_19307) || 
     (port == port_hangout_19308) || 
     (port == port_hangout_19309))
    return 1;
  else
    return 0;
}

static uint8_t is_hangout_tcp_port(uint16_t port) {
  if((port == port_hangout_19305) || 
     (port == port_hangout_19306) || 
     (port == port_hangout_19307) || 
     (port == port_hangout_19308) || 
     (port == port_hangout_19309))
    return 1;
  else
    return 0;
}

uint8_t check_hangout(pfwl_state_t* state, pfwl_pkt_infos_t* pkt,
                      const unsigned char* app_data, uint32_t data_length,
                      pfwl_tracking_informations_t* t){
  if((data_length > 24)) {
    if(
       ((pkt->l4prot == IPPROTO_UDP) && (is_hangout_udp_port(pkt->srcport) || is_hangout_udp_port(pkt->dstport)))
       ||
       ((pkt->l4prot == IPPROTO_TCP) && (is_hangout_tcp_port(pkt->srcport) || is_hangout_tcp_port(pkt->dstport)))) {
      return PFWL_PROTOCOL_MATCHES;
    }
  }
  
  return PFWL_PROTOCOL_NO_MATCHES;
}