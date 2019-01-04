/*
 * dns.c
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 * Copyright (c) 2018-2019 Michele Campus (michelecampus5@gmail.com)
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

#define FMASK 0x8000
#define QUERY 0
#define ANSWER 1

typedef enum {
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  WKS = 11,
  PTR = 12,
  MX = 15,
  TXT = 16,
  AAAA = 28,
  SVR = 33,
  NAPRT = 35,
  DNSKEY = 48,
} dns_aType;

typedef enum {
  NO_ERR = 0, // No Error
  FMT_ERR,    // Format Error on query
  SRV_FAIL,   // Server Failure (unable to process query)
  NAME_ERR,   // Name Error (meaningful for auth serv answer)
  NOT_IMPL,   // Not Implemented
  REFUSED,    // Refused Operation from name server
} dns_rCode;

struct dns_header {
  u_int16_t tr_id;
  u_int16_t flags;
  u_int16_t quest_count;
  u_int16_t answ_count;
  u_int16_t auth_rrs;
  u_int16_t add_rrs;
} __attribute__((packed));

/**
   #param uint16_t
   #param int
   #param int
   @return n bit from position p of number x
**/
static inline uint8_t getBits(uint16_t x, uint p, uint n) {
  return (x >> (p + 1 - n)) & ~(~0 << n);
}

/**
   #param const unsigned char*
   @return the length of the pointer name server
**/
uint16_t get_NS_len(const unsigned char *p) {
  const unsigned char *q = p;
  /**
     Note:
     In some cases we need a trick to determine the name server and its length
     i.e. .a.ns.joker == [01] 61 [02] 6e 73 [05] 6a 6f 6b 65 72
   **/
  do {
    q += (*q + 1); // move the pointer of *q value +1
  } while ((*q != 0xc0) && (*q != 0x00));

  return (uint16_t)(q - p);
}

/**
   Check if pkt is QUERY
   #param struct dns_header*
   @return 0 if is query -1 else
**/
static uint8_t isQuery(struct dns_header *dns_header) {
  /* QDCOUNT >= 1 && ANCOUNT = 0 && NSCOUNT = 0 && ARCOUNT = 0 */
  if (dns_header->quest_count >= 1 && dns_header->answ_count == 0 &&
      dns_header->auth_rrs == 0)
    return 0;
  else
    return -1;
}

/**
   Check if pkt is RESPONSE
   #param struct dns_header*
   #param uint8_t *
   #param uint8_t *
   #param pfwl_dns_internal_information_t*
   @return 0 if is response -1 else
 **/
static uint8_t isResponse(struct dns_header *dns_header,
                          uint8_t *is_name_server, uint8_t *is_auth_server,
                          pfwl_dns_internal_information_t *dns_info)

{
  uint8_t rcode, ret = -1;
  /* Check the RCODE value */
  rcode = getBits(dns_header->flags, 3, 4);
  switch (rcode) {
  case 0:
    dns_info->rCode = NO_ERR;
    break;
  case 1:
    dns_info->rCode = FMT_ERR;
    break;
  case 2:
    dns_info->rCode = SRV_FAIL;
    break;
  case 3:
    dns_info->rCode = NAME_ERR;
    break;
  case 4:
    dns_info->rCode = NOT_IMPL;
    break;
  case 5:
    dns_info->rCode = REFUSED;
    break;
  }
  /** QDCOUNT = 1 **/
  if (dns_header->quest_count == 1) {
    /* ANCOUNT >= 1 && NSCOUNT >= 1 */
    if (dns_header->answ_count >= 1 && dns_header->auth_rrs >= 1) {
      *is_name_server = 1;
      *is_auth_server = 1;
      ret = 0;
    }
    /* ANCOUNT = 0 && NSCOUNT >= 1 */
    else if (dns_header->answ_count == 0 && dns_header->auth_rrs >= 1) {
      *is_auth_server = 1;
      ret = 0;
    }
    /* ANCOUNT >= 1 && NSCOUNT = 0 */
    else if (dns_header->answ_count >= 1 && dns_header->auth_rrs == 0) {
      *is_name_server = 1;
      ret = 0;
    }
    /**
       Note:
       ANCOUNT = 0 && NSCOUNT = 0
       means the name server is already extracted
       from the corresponding query
    **/
  }
  return ret;
}

uint8_t check_dns(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
  pfwl_dissector_accuracy_t accuracy =
      state->inspectors_accuracy[PFWL_PROTO_L7_DNS];
  // check param
  if (!app_data)
    return PFWL_PROTOCOL_NO_MATCHES;
  if (!data_length)
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;

  /* DNS port (53) */
  if ((pkt_info->l4.port_dst == port_dns ||
       pkt_info->l4.port_src == port_dns) &&
      data_length >= 12) {
    uint8_t is_valid = -1;
    uint8_t is_name_server = 0, is_auth_server = 0;
    struct dns_header *dns_header = (struct dns_header *) (app_data);
    pfwl_dns_internal_information_t *dns_info =
        &flow_info_private->dns_informations;
    pfwl_field_t *extracted_fields = pkt_info->l7.protocol_fields;

    // pointer to beginning of queries section
    const unsigned char *pq = app_data + sizeof(struct dns_header);

    // init
    memset(&(flow_info_private->dns_informations), 0,
           sizeof(flow_info_private->dns_informations));

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
    if ((dns_header->flags & FMASK) == 0x0000) {
      // check isQuery
      (isQuery(dns_header) != 0) ? (is_valid = 0) : (is_valid = 1);
      // set QTYPE
      if (is_valid)
        dns_info->Type = QUERY;

      /** check accuracy type for fields parsing **/
      if (accuracy == PFWL_DISSECTOR_ACCURACY_HIGH && is_valid) {
        // check name server field
          if (pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_DNS_NAME_SRV)) {
            const unsigned char* temp = (const unsigned char*)(pq + 1);
            const char* r = strchr((const char*)pq + 1, '\0');
            pfwl_field_string_set(extracted_fields, PFWL_FIELDS_L7_DNS_NAME_SRV,
                                  temp, (const unsigned char*)r - temp);
          }
      }
    }
    /**
       QR == 1 is a RESPONSE
    **/
    if ((dns_header->flags & FMASK) == 0x8000) {
      // check isAnswer
      (isResponse(dns_header, &is_name_server, &is_auth_server, dns_info) !=
       0) ?
          (is_valid = 0) :
          (is_valid = 1);
      // set QTYPE
      if (is_valid)
        dns_info->Type = ANSWER;

      /** check accuracy type for fields parsing **/
      if (accuracy == PFWL_DISSECTOR_ACCURACY_HIGH && is_valid) {
        // sfhift of Query section
        const unsigned char *temp = (const unsigned char *) (pq);
        char *r = strchr((const char *) pq, '\0');
        pq += ((const unsigned char *) r - temp + 1) +
              4; // end of Name + Type(2) + Class(2)

        // check name server IP
        if (pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_DNS_NS_IP_1) && is_name_server) {
          /**
         Note:
         In case of answer count > 1, we consider (for now) only the first two
      sections
      **/
          uint8_t i = 0;
          do {
            // Answer section
            if (*pq == 0xc0)
              pq += 2; // Name is just a pointer of Name in query section

            // Answer Type
            uint16_t type = pq[1] + (pq[0] << 8);
            dns_info->aType = type;

            pq += 8; // TYPE(2) + CLASS(2) + TTL(4)
            uint16_t data_len = pq[1] + (pq[0] << 8);
            pq += 2; // shift data length(2)

            // update s and len for the field
            if (dns_info->aType != CNAME) {
              pfwl_field_string_set(extracted_fields,
                                    PFWL_FIELDS_L7_DNS_NS_IP_1 + i, pq,
                                    data_len);
            }
            // decrement number of answer sections found
            --dns_header->answ_count;
            i++;
            pq += data_len;
          } while (dns_header->answ_count > 0 && i < 2);
        }
        // check auth server
        if (pfwl_protocol_field_required(state, flow_info_private,PFWL_FIELDS_L7_DNS_AUTH_SRV) && is_auth_server) {
          /* /\** No Answer field(s) present: skip the query section and point
           * to Authority fields **\/ */
          /* if(!is_name_server) pq +=
           * (extracted_fields_dns[PFWL_FIELDS_DNS_NAME_SRV].len + 4); */

          /** Answer field(s) present: skip all these sections **/
          if (is_name_server) {
            while (dns_header->answ_count) {
              pq += 10; // NPTR(2) + TYPE(2) + CLASS(2) + TTL(4)
              uint16_t data_len = pq[1] + (pq[0] << 8);
              pq += 2; // Data LEN(2)
              pq += data_len;
              --dns_header->answ_count;
            }
          }
          /* PARSE AUTHORITY FIELDS */
          if (*pq == 0xc0)
            pq += 2; // Name is just a pointer of Name in query section

          // Auth Type
          uint16_t type = pq[1] + (pq[0] << 8);
          dns_info->authType = type;

          pq += 8; // TYPE(2) + CLASS(2) + TTL(4)
          uint16_t data_len = pq[1] + (pq[0] << 8);
          pq += 2; // Data LEN(2)

          if (type == SOA) {
            pfwl_field_string_set(extracted_fields, PFWL_FIELDS_L7_DNS_AUTH_SRV,
                                  pq + 1, get_NS_len(pq));
          } else {
            pfwl_field_string_set(extracted_fields, PFWL_FIELDS_L7_DNS_AUTH_SRV,
                                  pq, data_len);
          }
        }
      }
    }
    if (!is_valid)
      return PFWL_PROTOCOL_NO_MATCHES;
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
