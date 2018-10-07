/*
 * fields.h
 *
 * =========================================================================
 * Copyright (c) 2012-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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

typedef enum{
  /** SIP field **/
  PFWL_FIELDS_SIP_FIRST = 0,          ///< Dummy value to indicate first SIP field
  PFWL_FIELDS_SIP_REQUEST_URI = PFWL_FIELDS_SIP_FIRST,    ///< [STRING]
  PFWL_FIELDS_SIP_METHOD,             ///< [STRING]
  PFWL_FIELDS_SIP_CALLID,             ///< [STRING]
  PFWL_FIELDS_SIP_REASON,             ///< [STRING]
  PFWL_FIELDS_SIP_RTCPXR_CALLID,      ///< [STRING]
  PFWL_FIELDS_SIP_CSEQ,               ///< [STRING]
  PFWL_FIELDS_SIP_CSEQ_METHOD_STRING, ///< [STRING]
  PFWL_FIELDS_SIP_VIA,                ///< [STRING]
  PFWL_FIELDS_SIP_CONTACT_URI,        ///< [STRING]
  PFWL_FIELDS_SIP_RURI_USER,          ///< [STRING]
  PFWL_FIELDS_SIP_RURI_DOMAIN,        ///< [STRING]
  PFWL_FIELDS_SIP_FROM_USER,          ///< [STRING]
  PFWL_FIELDS_SIP_FROM_DOMAIN,        ///< [STRING]
  PFWL_FIELDS_SIP_TO_USER,            ///< [STRING]
  PFWL_FIELDS_SIP_TO_DOMAIN,          ///< [STRING]
  PFWL_FIELDS_SIP_PAI_USER,           ///< [STRING]
  PFWL_FIELDS_SIP_PAI_DOMAIN,         ///< [STRING]
  PFWL_FIELDS_SIP_PID_URI,            ///< [STRING]
  PFWL_FIELDS_SIP_FROM_URI,           ///< [STRING]
  PFWL_FIELDS_SIP_TO_URI,             ///< [STRING]
  PFWL_FIELDS_SIP_RURI_URI,           ///< [STRING]
  PFWL_FIELDS_SIP_TO_TAG,             ///< [STRING]
  PFWL_FIELDS_SIP_FROM_TAG,           ///< [STRING]
  PFWL_FIELDS_SIP_LAST,               ///< Dummy value to indicate last SIP field
  /** DNS field **/
  PFWL_FIELDS_DNS_FIRST,              ///< Dummy value to indicate first DNS field
  PFWL_FIELDS_DNS_NAME_SRV = PFWL_FIELDS_DNS_FIRST, ///< Server name [STRING]
  PFWL_FIELDS_DNS_NS_IP_1,            ///< Server name IP address [STRING]
  PFWL_FIELDS_DNS_NS_IP_2,            ///< Server name IP address [STRING]
  PFWL_FIELDS_DNS_AUTH_SRV,           ///< Authority name [STRING]
  PFWL_FIELDS_DNS_LAST,               ///< Dummy value to indicate last DNS field
  /** SSL field **/
  PFWL_FIELDS_SSL_FIRST,              ///< Dummy value to indicate first SSL field
  PFWL_FIELDS_SSL_CERTIFICATE = PFWL_FIELDS_SSL_FIRST,  ///< Server name [STRING]
  PFWL_FIELDS_SSL_LAST,               ///< Dummy value to indicate last SSL field
  /** HTTP field **/
  PFWL_FIELDS_HTTP_FIRST,             ///< Dummy value to indicate first HTTP field
  PFWL_FIELDS_HTTP_VERSION_MAJOR = PFWL_FIELDS_HTTP_FIRST,     ///< HTTP Version - Major [NUM]
  PFWL_FIELDS_HTTP_VERSION_MINOR,     ///< HTTP Version - Minor [NUM]
  PFWL_FIELDS_HTTP_METHOD,            ///< HTTP Method. Please check against pfwl_http_methods_t [NUM]
  PFWL_FIELDS_HTTP_STATUS_CODE,       ///< HTTP Status code [NUM]
  PFWL_FIELDS_HTTP_MSG_TYPE,          ///< HTTP request or response. Please check againts pfwl_http_message_type_t enumeration [NUM]
  PFWL_FIELDS_HTTP_BODY,              ///< HTTP Body            [STRING]
  PFWL_FIELDS_HTTP_URL,               ///< HTTP URL             [STRING]
  PFWL_FIELDS_HTTP_USER_AGENT,        ///< HTTP User agent      [STRING]
  PFWL_FIELDS_HTTP_CONTENT_TYPE,      ///< HTTP Content Type    [STRING]
  PFWL_FIELDS_HTTP_HOST,      ///< HTTP Host    [STRING]
  PFWL_FIELDS_HTTP_LAST,              ///< Dummy value to indicate last HTTP field
  /** **/
  PFWL_FIELDS_NUM,                    ///< Dummy value to indicate number of fields. Must be the last field specified.
}pfwl_field_id_t;

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
