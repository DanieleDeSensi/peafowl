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
  DPI_FIELDS_SIP_REQUEST_URI = 0,
  DPI_FIELDS_SIP_METHOD,
  DPI_FIELDS_SIP_CALLID,
  DPI_FIELDS_SIP_REASON,
  DPI_FIELDS_SIP_RTCPXR_CALLID,
  DPI_FIELDS_SIP_CSEQ,
  DPI_FIELDS_SIP_CSEQ_METHOD_STRING,
  DPI_FIELDS_SIP_VIA,
  DPI_FIELDS_SIP_CONTACT_URI,
  DPI_FIELDS_SIP_RURI_USER,
  DPI_FIELDS_SIP_RURI_DOMAIN,
  DPI_FIELDS_SIP_FROM_USER,
  DPI_FIELDS_SIP_FROM_DOMAIN,
  DPI_FIELDS_SIP_TO_USER,
  DPI_FIELDS_SIP_TO_DOMAIN,
  DPI_FIELDS_SIP_PAI_USER,
  DPI_FIELDS_SIP_PAI_DOMAIN,
  DPI_FIELDS_SIP_PID_URI,
  DPI_FIELDS_SIP_FROM_URI,
  DPI_FIELDS_SIP_TO_URI,
  DPI_FIELDS_SIP_RURI_URI,
  DPI_FIELDS_SIP_TO_TAG,
  DPI_FIELDS_SIP_FROM_TAG,
  DPI_FIELDS_SIP_NUM, // This must be the last
}pfwl_fields_sip;

/* DNS field */
typedef enum{
  DPI_FIELDS_DNS_NAME_SRV = 0, // Server name
  DPI_FIELDS_DNS_AUTH_SRV,     // Authority name
  DPI_FIELDS_DNS_RPLY_CODE,    // Reply Code (only for answer)
  DPI_FIELDS_DNS_NUM, // This must be the last
}pfwl_fields_dns;

typedef struct dpi_tracking_informations dpi_tracking_informations_t;
typedef pfwl_field_t* (*pfwl_get_extracted_fields_callback)(dpi_tracking_informations_t*);

// SIP
pfwl_field_t* get_extracted_fields_sip(dpi_tracking_informations_t*);
// DNS
pfwl_field_t* get_extracted_fields_dns(dpi_tracking_informations_t*);

#endif /* FIELDS_H_ */
