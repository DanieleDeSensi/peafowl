/*
 * dns.c
 *
 * =========================================================================
 *  Copyright (C) 2012-2018, Daniele De Sensi (d.desensi.software@gmail.com)
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

#define FMASK 0x8000

typedef enum{
  NO_ERR = 0, // No Error
  FMT_ERR,    // Format Error on query
  SRV_FAIL,   // Server Failure (unable to process query)
  NAME_ERR,   // Name Error (meaningful for auth serv answer)
  NOT_IMPL,   // Not Implemented
  REFUSED,    // Refused Operation from name server
} dns_rcode;

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
static inline uint8_t getBits(uint16_t x, int p, int n)
{
  return (x >> (p+1-n)) & ~(~0 << n);
}

/**
   Check if pkt is QUERY
 **/
static uint8_t isQuery(struct dns_header *dns_header)
{
  /* QDCOUNT >= 1 && ANCOUNT = 0 && NSCOUNT = 0 && ARCOUNT = 0 */
  if(dns_header->quest_count >= 1 &&
     dns_header->answ_count == 0 &&
     dns_header->auth_rrs == 0)
    return 0;
  else
    return -1;
}

/**
   Check if pkt is ANSWER
 **/
static uint8_t isAnswer(struct dns_header *dns_header, uint8_t *is_name_server, uint8_t *is_auth_server)

{
  uint8_t rcode, ret = -1;
  /* Check the RCODE value */
  rcode = getBits(dns_header->flags, 3, 4);
  switch(rcode) {
    /* TODO */
  case 0: break;
  case 1: break;
  case 2: break;
  case 3: break;
  case 4: break;
  case 5: break;
  }
  /** QDCOUNT = 1 **/
  if(dns_header->quest_count == 1) {
    /* ANCOUNT = 0 && NSCOUNT = 0 */
    if(dns_header->answ_count == 0 && dns_header->auth_rrs == 0) {
      *is_name_server = 1;
      ret = 0;
    }
    /* ANCOUNT = 0 && NSCOUNT = 1 */
    else if(dns_header->answ_count == 0 && dns_header->auth_rrs >= 1) {
      *is_auth_server = 1;
      ret = 0;
    }
    /* ANCOUNT = 1 && NSCOUNT = 0 */
    else if(dns_header->answ_count >= 1 && dns_header->auth_rrs == 0) {
      *is_name_server = 1;
      ret = 0;
    }
    /* ANCOUNT = 1 && NSCOUNT = 1 */
    else {
      *is_name_server = 1;
      *is_auth_server = 1;
      ret = 0;
    }
  }
  return ret;
}


uint8_t check_dns(dpi_library_state_t* state, dpi_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  dpi_tracking_informations_t* t)
{
  // check param
  if(!state || !app_data || !pkt || !t)
    return DPI_PROTOCOL_NO_MATCHES;
  if(!data_length)
    return DPI_PROTOCOL_MORE_DATA_NEEDED;
  
  /* DNS port (53) */
  if((pkt->dstport == port_dns || pkt->srcport == port_dns) &&
     data_length >= 12) {

    uint8_t is_valid = -1;
    uint8_t is_name_server = 0, is_auth_server = 0;
    dpi_inspector_accuracy accuracy_type;
    struct dns_header* dns_header = (struct dns_header*)(app_data);
    dpi_dns_internal_information_t* dns_info = &t->dns_informations;
    pfwl_field_t* extracted_fields_dns = t->extracted_fields.dns;

    // pointer to beginning of queries section
    const unsigned char* pq = app_data + sizeof(struct dns_header);

    // init
    memset(&(t->dns_informations), 0, sizeof(t->dns_informations));
    accuracy_type = state->inspectors_accuracy[DPI_PROTOCOL_DNS];

    // set to host byte order
    dns_header->tr_id = ntohs(dns_header->tr_id);
    dns_header->flags = ntohs(dns_header->flags);
    dns_header->quest_count = ntohs(dns_header->quest_count);
    dns_header->answ_count = ntohs(dns_header->answ_count);
    dns_header->auth_rrs = ntohs(dns_header->auth_rrs);
    dns_header->add_rrs = ntohs(dns_header->add_rrs);
    
    /**
       QR == 0 is a QUERY
    **/
    if((dns_header->flags & FMASK) == 0x0000) {
      // check isQuery
      (isQuery(dns_header) != 0) ? (is_valid = 0) : (is_valid = 1);
      /** check accuracy type for fields parsing **/
      if(accuracy_type == DPI_INSPECTOR_ACCURACY_HIGH) {
	// check name server field
	if(pfwl_protocol_field_required(state, DPI_PROTOCOL_DNS, DPI_FIELDS_DNS_NAME_SRV)) {
	  dns_info->name_server = &(extracted_fields_dns[DPI_FIELDS_DNS_NAME_SRV]);
	  const char* temp = (const char*)(pq + 1);
	  char* r = strchr((const char*)pq + 1, '\0');
	  dns_info->name_server->s = temp;
	  dns_info->name_server->len = r - temp;
	}
      }
    }
    /**
       QR == 1 is an ANSWER
    **/
    if((dns_header->flags & FMASK) == 0x8000) {
      // check isAnswer
      (isAnswer(dns_header,
		&is_name_server,
		&is_auth_server) != 0) ? (is_valid = 0) : (is_valid = 1);
      /** check accuracy type for fields parsing **/
      if(accuracy_type == DPI_INSPECTOR_ACCURACY_HIGH) {	
	// check name server
	if(pfwl_protocol_field_required(state, DPI_PROTOCOL_DNS, DPI_FIELDS_DNS_NAME_SRV) && is_name_server) {
	  /* TODO extraction fields */
	}
	// check auth server
	if(pfwl_protocol_field_required(state, DPI_PROTOCOL_DNS, DPI_FIELDS_DNS_NAME_SRV) && is_auth_server) {
	  /* TODO extraction fields */
	}
      }
    }
    if(!is_valid)
      return DPI_PROTOCOL_NO_MATCHES;
    return DPI_PROTOCOL_MATCHES;
  }
  return DPI_PROTOCOL_NO_MATCHES;
}


pfwl_field_t* get_extracted_fields_dns(dpi_tracking_informations_t* t){
  return t->extracted_fields.dns;
}
