/*
 * fields.h
 *
 *  Created on: 23/09/2012
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

#ifndef FIELDS_H_
#define FIELDS_H_

typedef struct {
  const char* s;
  size_t len;
} pfwl_field_t;

/* SIP field */
typedef enum{
  PFWL_FIELDS_SIP_REQUEST_URI = 0,
  PFWL_FIELDS_SIP_METHOD,
  PFWL_FIELDS_SIP_CALLID,
  PFWL_FIELDS_SIP_REASON,
  PFWL_FIELDS_SIP_RTCPXR_CALLID,
  PFWL_FIELDS_SIP_CSEQ,
  PFWL_FIELDS_SIP_CSEQ_METHOD_STRING,
  PFWL_FIELDS_SIP_VIA,
  PFWL_FIELDS_SIP_CONTACT_URI,
  PFWL_FIELDS_SIP_RURI_USER,
  PFWL_FIELDS_SIP_RURI_DOMAIN,
  PFWL_FIELDS_SIP_FROM_USER,
  PFWL_FIELDS_SIP_FROM_DOMAIN,
  PFWL_FIELDS_SIP_TO_USER,
  PFWL_FIELDS_SIP_TO_DOMAIN,
  PFWL_FIELDS_SIP_PAI_USER,
  PFWL_FIELDS_SIP_PAI_DOMAIN,
  PFWL_FIELDS_SIP_PID_URI,
  PFWL_FIELDS_SIP_FROM_URI,
  PFWL_FIELDS_SIP_TO_URI,
  PFWL_FIELDS_SIP_RURI_URI,
  PFWL_FIELDS_SIP_TO_TAG,
  PFWL_FIELDS_SIP_FROM_TAG,
  PFWL_FIELDS_SIP_NUM,          // This must be the last
}pfwl_fields_sip;

/* DNS field */
typedef enum{
  PFWL_FIELDS_DNS_NAME_SRV = 0, // Server name
  PFWL_FIELDS_DNS_NS_IP_1,      // Server name IP address
  PFWL_FIELDS_DNS_NS_IP_2,      // Server name IP address
  PFWL_FIELDS_DNS_AUTH_SRV,     // Authority name
  PFWL_FIELDS_DNS_NUM,          // This must be the last
}pfwl_fields_dns;

typedef struct pfwl_tracking_informations pfwl_tracking_informations_t;
typedef pfwl_field_t* (*pfwl_get_extracted_fields_callback)(pfwl_tracking_informations_t*);

// SIP
pfwl_field_t* get_extracted_fields_sip(pfwl_tracking_informations_t*);
// DNS
pfwl_field_t* get_extracted_fields_dns(pfwl_tracking_informations_t*);

#endif /* FIELDS_H_ */
