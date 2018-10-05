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

#include <peafowl/inspectors/http_parser_joyent.h>

/**
 * A string as represented by peafowl.
 **/
typedef struct {
  const char* s; ///< The string of bytes extracted by peafowl. ATTENTION: It could be not \0 terminated.
  size_t len;    ///< The length of the string.
} pfwl_string_t;

/**
 * A generic field extracted by peafowl.
 **/
typedef union pfwl_field{
  pfwl_string_t str;
  uint32_t num;
}pfwl_field_t;

/** SIP field **/
typedef enum{
  PFWL_FIELDS_SIP_REQUEST_URI = 0, ///< [STRING]
  PFWL_FIELDS_SIP_METHOD,          ///< [STRING]
  PFWL_FIELDS_SIP_CALLID,          ///< [STRING]
  PFWL_FIELDS_SIP_REASON,          ///< [STRING]
  PFWL_FIELDS_SIP_RTCPXR_CALLID,   ///< [STRING]
  PFWL_FIELDS_SIP_CSEQ,            ///< [STRING]
  PFWL_FIELDS_SIP_CSEQ_METHOD_STRING, ///< [STRING]
  PFWL_FIELDS_SIP_VIA,          ///< [STRING]
  PFWL_FIELDS_SIP_CONTACT_URI,  ///< [STRING]
  PFWL_FIELDS_SIP_RURI_USER,    ///< [STRING]
  PFWL_FIELDS_SIP_RURI_DOMAIN,  ///< [STRING]
  PFWL_FIELDS_SIP_FROM_USER,    ///< [STRING]
  PFWL_FIELDS_SIP_FROM_DOMAIN,  ///< [STRING]
  PFWL_FIELDS_SIP_TO_USER,      ///< [STRING]
  PFWL_FIELDS_SIP_TO_DOMAIN,    ///< [STRING]
  PFWL_FIELDS_SIP_PAI_USER,     ///< [STRING]
  PFWL_FIELDS_SIP_PAI_DOMAIN,   ///< [STRING]
  PFWL_FIELDS_SIP_PID_URI,      ///< [STRING]
  PFWL_FIELDS_SIP_FROM_URI,     ///< [STRING]
  PFWL_FIELDS_SIP_TO_URI,       ///< [STRING]
  PFWL_FIELDS_SIP_RURI_URI,     ///< [STRING]
  PFWL_FIELDS_SIP_TO_TAG,       ///< [STRING]
  PFWL_FIELDS_SIP_FROM_TAG,     ///< [STRING]
  PFWL_FIELDS_SIP_NUM,          ///< Dummy value to indicate number of fields. Must be the last field specified.
}pfwl_fields_sip;

/** DNS field **/
typedef enum{
  PFWL_FIELDS_DNS_NAME_SRV = 0, ///< Server name [STRING]
  PFWL_FIELDS_DNS_NS_IP_1,      ///< Server name IP address [STRING]
  PFWL_FIELDS_DNS_NS_IP_2,      ///< Server name IP address [STRING]
  PFWL_FIELDS_DNS_AUTH_SRV,     ///< Authority name [STRING]
  PFWL_FIELDS_DNS_NUM,          ///< Dummy value to indicate number of fields. Must be the last field specified.
}pfwl_fields_dns;

/** SSL field **/
typedef enum{
  PFWL_FIELDS_SSL_CERTIFICATE = 0, ///< Server name [STRING]
  PFWL_FIELDS_SSL_NUM,             ///< Dummy value to indicate number of fields. Must be the last field specified.
}pfwl_fields_ssl;

/** HTTP field **/
typedef enum{
  PFWL_FIELDS_HTTP_VERSION_MAJOR = 0,  ///< HTTP Version - Major [NUM]
  PFWL_FIELDS_HTTP_VERSION_MINOR,      ///< HTTP Version - Minor [NUM]
  PFWL_FIELDS_HTTP_METHOD,             ///< HTTP Method. Please check against pfwl_http_methods_t [NUM]
  PFWL_FIELDS_HTTP_STATUS_CODE,        ///< HTTP Status code [NUM]
  PFWL_FIELDS_HTTP_MSG_TYPE,           ///< HTTP request or response. Please check againts pfwl_http_message_type_t enumeration [NUM]
  PFWL_FIELDS_HTTP_BODY,               ///< HTTP Body            [STRING]
  PFWL_FIELDS_HTTP_URL,                ///< HTTP URL             [STRING]
  PFWL_FIELDS_HTTP_USER_AGENT,         ///< HTTP User agent      [STRING]
  PFWL_FIELDS_HTTP_CONTENT_TYPE,       ///< HTTP Content TYpe    [STRING]
  PFWL_FIELDS_HTTP_NUM,                ///< Dummy value to indicate number of fields. Must be the last field specified.
}pfwl_fields_http;

typedef enum pfwl_http_message_type {
  PFWL_HTTP_REQUEST = HTTP_REQUEST,
  PFWL_HTTP_RESPONSE = HTTP_RESPONSE
}pfwl_http_message_type_t;

typedef enum pfwl_http_methods {
#define XX(num, name, string) PFWL_HTTP_##name = num,
  HTTP_METHOD_MAP(XX)
#undef XX
}pfwl_http_methods_t;


typedef struct pfwl_tracking_informations pfwl_tracking_informations_t;

#endif /* FIELDS_H_ */
