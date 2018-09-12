/*
 * dns.c
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

#define FMASK 0x8000

struct dns_header {
  u_int16_t tr_id;
  u_int16_t flags;
  u_int16_t quest_count;
  u_int16_t answ_count;
  u_int16_t auth_rrs;
  u_int16_t add_rrs;
} __attribute__((packed));


/**
   return n bit from position p of number x 
**/
static inline uint8_t getbits(uint16_t x, int p, int n)
{
  return (x >> (p+1-n)) & ~(~0 << n);
}


uint8_t check_dns(dpi_library_state_t* state, dpi_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  dpi_tracking_informations_t* t) {
  /* Check standard DNS port (53) */
  if ((pkt->dstport == port_dns || pkt->srcport == port_dns) &&
      data_length >= 12) {

    int is_name_server = 0, is_auth_server = 0, uint8_t rcode;
    struct dns_header *dns_header = (struct dns_header*)(app_data);    
    
    /**
       QR == 0 is a QUERY
    **/
    if((dns_header->flags & FMASK) == 0) {
      /* QDCOUNT = 1 && ANCOUNT = 0 && NSCOUNT = 0 && ARCOUNT = 0 */
      if(dns_header->quest_count == 1 &&
	 dns_header->answ_count == 0 &&
	 dns_header->auth_rrs == 0 &&
	 dns_header->add_rrs == 0) {
	  is_name_server = 1;
	  /* TODO: extract name server */
	  ++t->dns_stage;
      }
      else
	return DPI_PROTOCOL_NO_MATCHES;
    }
    /**
       QR == 1 is a RESPONSE 
    **/
    if((dns_header->flags & FMASK) == 1) {
      /* Check the RCODE value */
      rcode = getbits(dns_header->flags, 3, 4);
      switch(rcode) {
      case 0: break;
      case 1: break;
      case 2: break;
      case 3: break;
      case 4: break;
      case 5: break;
      }
      /** QDCOUNT = 1 **/
      if(dns_header->quest_count == 1) {
	/* TODO: extract name server from Queries */
	if(dns_header->answ_count == 0 && dns_header->auth_rrs == 0) {
	  ++t->dns_stage;
	}
	else if(dns_header->answ_count == 0 && dns_header->auth_rrs >= 1) {
	  /* TODO: extract name server and primary name server from Authority server */
	  is_auth_server = 1;
	  ++t->dns_stage;
	}
	else if(dns_header->answ_count >= 1 && dns_header->auth_rrs == 0) {
	  /* TODO: extract name server from Answer server */
	  /* TODO check TYPE to extract IP address or CNAME of Answer server */
	  is_name_server = 1;
	  ++t->dns_stage;
	}
	else {
	  /* TODO: extract name server from Answer server */
	  /* TODO check TYPE to extract IP address or CNAME of Answer server */
	  /* TODO: extract name server and primary name server from Authority server */
	  is_name_server = 1; is_auth_server = 1;
	  ++t->dns_stage;
	}
	if (t->dns_stage >= 2) {
	  return DPI_PROTOCOL_MATCHES;
	} else {
	  return DPI_PROTOCOL_MORE_DATA_NEEDED;
	}
      }
      /** QDCOUNT cannot be 0 for DNS **/
      return DPI_PROTOCOL_NO_MATCHES;
    }
    return DPI_PROTOCOL_NO_MATCHES;
  }
}
