/**
 * sip.c
 *
 * Created on: 29/06/2016
 *
 * This dissector is adapted from captagent SIP dissector
 (https://github.com/sipcapture/captagent).
 *
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
 *  Copyright (C) 2016, Lorenzo Mangani (lorenzo.mangani@gmail.com), QXIP BV
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

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define SIP_REQUEST 1
#define SIP_REPLY 2

#define INVITE_METHOD "INVITE"
#define ACK_METHOD "ACK"
#define CANCEL_METHOD "CANCEL"
#define BYE_METHOD "BYE"
#define INFO_METHOD "INFO"
#define REGISTER_METHOD "REGISTER"
#define SUBSCRIBE_METHOD "SUBSCRIBE"
#define NOTIFY_METHOD "NOTIFY"
#define MESSAGE_METHOD "MESSAGE"
#define OPTIONS_METHOD "OPTIONS"
#define PRACK_METHOD "PRACK"
#define UPDATE_METHOD "UPDATE"
#define REFER_METHOD "REFER"
#define PUBLISH_METHOD "PUBLISH"
#define NOTIFY_METHOD "NOTIFY"
#define OPTIONS_METHOD "OPTIONS"
#define ACK_METHOD "ACK"
#define UNKNOWN_METHOD "UNKNOWN"
#define RESPONSE_METHOD "RESPONSE"
#define SERVICE_METHOD "SERVICE"

#define SIP_VERSION "SIP/2.0"
#define SIP_VERSION_LEN 7

#define INVITE_LEN 6
#define CANCEL_LEN 6
#define ACK_LEN 3
#define BYE_LEN 3
#define INFO_LEN 4
#define REGISTER_LEN 8
#define SUBSCRIBE_LEN 9
#define NOTIFY_LEN 6
#define MESSAGE_LEN 7
#define OPTIONS_LEN 7
#define PRACK_LEN 5
#define UPDATE_LEN 6
#define REFER_LEN 5
#define PUBLISH_LEN 7
#define UAC_LEN 10
#define RESPONSE_LEN 8
#define SERVICE_LEN 7

#define TO_LEN 2
#define PAI_LEN 19
#define FROM_LEN 4
#define EXPIRE_LEN 6
#define CALLID_LEN 7
#define CSEQ_LEN 4
#define VIA_LEN 3
#define PROXY_AUTH_LEN 19
#define WWW_AUTH_LEN 16
#define CONTACT_LEN 7
#define CONTENTLENGTH_LEN 14
#define CONTENTTYPE_LEN 12
#define USERAGENT_LEN 10
#define AUTHORIZATION_LEN 13
#define PPREFERREDIDENTITY_LEN 20
#define PASSERTEDIDENTITY_LEN 19

#define P_NGCP_CALLER_INFO_LEN 18
#define P_NGCP_CALLEE_INFO_LEN 18

#define XOIP_LEN 5
#define PRTPSTAT_LEN 10
#define XRTPSTAT_LEN 10
#define XRTPSTATISTICS_LEN 16
#define XSIEMENSRTPSTAT_LEN 19
#define XNGRTPSTAT_LEN 15
#define RTPRXTXSTAT_LEN 10

/* define for rtp stats type */
#define XRTPSTAT_TYPE 1
#define XRTPSTATISTICS_TYPE 2
#define PRTPSTAT_TYPE 3
#define RTPRXSTAT_TYPE 4
#define RTPTXSTAT_TYPE 5
#define XSIEMENSRTPSTATS_TYPE 6
#define XNGRTPSTATS_TYPE 7

#define RTCPXR_VQSESSIONREPORT_LEN 15
#define RTCPXR_CALLID_LEN 6
#define RTCPXR_SESSIONDESC_LEN 11
#define RTCPXR_JITTERBUFFER_LEN 12
#define RTCPXR_PACKETLOSS_LEN 10
#define RTCPXR_BURSTGAPLOSS_LEN 12
#define RTCPXR_DELAY_LEN 5
#define RTCPXR_QUALITYEST_LEN 10

#define CALL_CANCEL_TERMINATION 1
#define CALL_BYE_TERMINATION 2
#define CALL_MOVED_TERMINATION 3
#define CALL_BUSY_TERMINATION 4
#define CALL_AUTH_TERMINATION 5
#define CALL_4XX_TERMINATION 5
#define CALL_5XX_TERMINATION 6
#define CALL_6XX_TERMINATION 7

#define REGISTRATION_200_TERMINATION 1
#define REGISTRATION_AUTH_TERMINATION 2
#define REGISTRATION_4XX_TERMINATION 3
#define REGISTRATION_5XX_TERMINATION 4
#define REGISTRATION_6XX_TERMINATION 5

uint8_t getUser(pfwl_field_t *user, pfwl_field_t *domain, const char *s,
                int len) {
  enum state {
    URI_BEGIN,
    URI_USER,
    URI_PARAM,
    URI_PASSWORD,
    URI_HOST_IPV6,
    URI_HOST,
    URI_HOST_END,
    URI_END,
    URI_OFF
  };

  enum state st;
  int first_offset = 0, host_offset = 0;
  unsigned int i;
  uint8_t foundUser = 0, foundHost = 0, foundAtValue = 0;
  st = URI_BEGIN;
  // host_end_offset = len;

  for (i = 0; i < len; i++) {
    switch (st) {
      case URI_BEGIN:

        if (s[i] == ':') {
          first_offset = i;
          st = URI_USER;
        }
        break;

      case URI_USER:
        // user_offset = i;
        if (s[i] == '@') {
          host_offset = i;
          st = URI_HOST;
          user->s = s + (first_offset + 1);
          user->len = (i - first_offset - 1);
          foundUser = 1;
          foundAtValue = 1;
        } else if (s[i] == ':') {
          st = URI_PASSWORD;
          user->s = s + (first_offset + 1);
          user->len = (i - first_offset - 1);
          foundUser = 1;
        } else if (s[i] == ';' || s[i] == '?' || s[i] == '&') {
          user->s = s + (first_offset + 1);
          user->len = (i - first_offset - 1);
          st = URI_PARAM;
          foundUser = 1;
        }
        break;

      case URI_PASSWORD:
        // password_offset = i;
        if (s[i] == '@') {
          host_offset = i;
          st = URI_HOST;
          foundAtValue = 1;
        }
        break;

      case URI_PARAM:
        if (s[i] == '@') {
          host_offset = i;
          st = URI_HOST;
          foundAtValue = 1;
        }
        if (s[i] == '>') st = URI_HOST_END;
        break;

      case URI_HOST:
        if (s[i] == '[')
          st = URI_HOST_IPV6;
        else if (s[i] == ':' || s[i] == '>' || s[i] == ';' || s[i] == ' ') {
          st = URI_HOST_END;
          domain->s = s + host_offset + 1;
          domain->len = (i - host_offset - 1);
          foundHost = 1;
        }
        break;

      case URI_HOST_IPV6:
        if (s[i] == ']') {
          domain->s = s + host_offset + 1;
          domain->len = (i - host_offset - 1);
          foundHost = 1;
          st = URI_HOST_END;
        }
        break;

      case URI_HOST_END:
        st = URI_END;
        break;

      default:
        i = len;
        break;
    }
  }

  if (st == URI_BEGIN) {
    return 0;
  }

  if (foundUser == 0)
    user->len = 0;
  else if (foundAtValue == 0 && foundUser == 1) {
    domain->s = user->s;
    domain->len = user->len;

    /*and after set to 0 */
    user->len = 0;
  }
  if (foundUser == 0 && foundHost == 0) {
    domain->s = s + first_offset + 1;
    domain->len = (len - first_offset);
  }

  return 1;
}

uint8_t set_hname(pfwl_field_t *hname, int len, const char *s) {
  const char *end;

  if (hname->len > 0) {
    return 0;
  }

  end = s + len;
  for (; s < end; s++) {
    len--;
    if ((*s != ' ') && (*s != ':') && (*s != '\t')) {
      len--;
      break;
    }
  }

  hname->s = s;
  hname->len = len;
  return 1;
}

uint8_t getTag(pfwl_field_t *hname, const char *uri, int len) {
  enum state { ST_TAG, ST_END, ST_OFF };

  enum state st;
  int first_offset = 0, last_offset = 0, i;

  st = ST_TAG;
  last_offset = len;

  for (i = 0; i < len; i++) {
    switch (st) {
      case ST_TAG:
        if (((i + 4) < len) && (uri[i] == 't' || uri[i] == 'T') &&
            (uri[i + 2] == 'g' || uri[i + 2] == 'G') && uri[i + 3] == '=') {
          first_offset = i + 4;
          st = ST_END;
        }
        break;

      case ST_END:
        last_offset = i;
        if (uri[i] == ';') st = ST_OFF;
        break;

      default:
        break;
    }
  }

  if (st == ST_TAG) {
    return 0;
  }

  if ((last_offset - first_offset) < 5) return 0;

  set_hname(hname, (last_offset - first_offset), uri + first_offset);
  return 1;
}

int isValidIp4Address(pfwl_field_t *mip) {
  int result = 0;
  char ipAddress[17];
  struct sockaddr_in sa;

  if (mip->s == NULL || mip->len > 16) return 0;
  snprintf(ipAddress, 17, "%.*s", (int)mip->len, mip->s);

  result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
  return result != 0;
}

int parseSdpCLine(pfwl_sip_miprtcp_t *mp, const unsigned char *data,
                  size_t len) {
  enum state { ST_NETTYPE, ST_ADDRTYPE, ST_CONNECTIONADRESS, ST_END };

  /* c=IN IP4 224.2.17.12 */

  enum state st;
  int last_offset = 0, i;

  st = ST_NETTYPE;
  last_offset = 0;

  for (i = 0; i < len; i++) {
    switch (st) {
      case ST_NETTYPE:
        if (data[i] == ' ') {
          st = ST_ADDRTYPE;
          last_offset = i;
        }
        break;

      case ST_ADDRTYPE:
        if (data[i] == ' ') {
          st = ST_CONNECTIONADRESS;
          last_offset = i;
        }

        break;
      case ST_CONNECTIONADRESS:
        mp->media_ip.s = (char *)data + last_offset + 1;
        mp->media_ip.len = len - last_offset - 3;
        if (mp->rtcp_ip.len == 0) {
          mp->rtcp_ip.len = mp->media_ip.len;
          mp->rtcp_ip.s = mp->media_ip.s;
        }
        st = ST_END;
        break;

      default:
        break;
    }
  }

  return 1;
}

int parseSdpMLine(pfwl_sip_miprtcp_t *mp, const unsigned char *data,
                  size_t len) {
  enum state { ST_TYPE, ST_PORT, ST_AVP, ST_CODEC, ST_END };

  enum state st;
  int last_offset = 0, i;

  st = ST_TYPE;
  last_offset = 0;

  for (i = 0; i < len; i++) {
    switch (st) {
      case ST_TYPE:
        if (data[i] == ' ') {
          st = ST_PORT;
          last_offset = i;
        }
        break;

      case ST_PORT:
        if (data[i] == ' ') {
          st = ST_AVP;
          mp->media_port = atoi((char *)data + last_offset);
          if (mp->rtcp_port == 0) mp->rtcp_port = mp->media_port + 1;
          last_offset = i;
        }
        break;

      case ST_AVP:
        if (data[i] == ' ') {
          st = ST_CODEC;
          last_offset = i;
        }
        break;

      case ST_CODEC:
        if (data[i] == ' ') {
          st = ST_END;
          mp->prio_codec = atoi((char *)data + last_offset);
          last_offset = i;
          return 1;
        }
        break;

      default:
        break;
    }
  }

  return 1;
}

int parseSdpALine(pfwl_sip_miprtcp_t *mp, const unsigned char *data,
                  size_t len) {
  enum state { ST_START, ST_PROTO, ST_TYPE, ST_IP, ST_END };

  enum state st;
  int last_offset = 0, i;

  st = ST_START;
  last_offset = 0;

  for (i = 0; i < len; i++) {
    switch (st) {
      case ST_START:
        if (data[i] == ' ') {
          mp->rtcp_port = atoi((char *)data);
          st = ST_PROTO;
          last_offset = i;
        }
        break;

      case ST_PROTO:
        if (data[i] == ' ') {
          st = ST_TYPE;
          last_offset = i;
        }
        break;

      case ST_TYPE:
        if (data[i] == ' ') {
          st = ST_IP;
          last_offset = i;
        }
        break;

      case ST_IP:
        st = ST_END;
        mp->rtcp_ip.s = (const char *)data + last_offset + 1;
        mp->rtcp_ip.len = len - last_offset - 3;
        st = ST_END;
        return 1;

        break;

      default:
        break;
    }
  }

  return 1;
}

int parseSdpARtpMapLine(pfwl_sip_codecmap_t *cp, const unsigned char *data,
                        size_t len) {
  enum state { ST_START, ST_NAME, ST_RATE, ST_END };

  enum state st;
  int last_offset = 0, i;

  st = ST_START;
  last_offset = 0;

  for (i = 0; i < len; i++) {
    switch (st) {
      case ST_START:
        if (data[i] == ' ') {
          cp->id = atoi((char *)data);
          st = ST_NAME;
          last_offset = i;
        }
        break;

      case ST_NAME:
        if (data[i] == '/') {
          st = ST_RATE;
          snprintf(cp->name, sizeof(cp->name), "%.*s", (i - last_offset) - 1,
                   data + last_offset + 1);
          last_offset = i;
        }
        break;

      case ST_RATE:
        st = ST_END;
        cp->rate = atoi((char *)data + last_offset + 1);
        return 0;
      default:
        break;
    }
  }
  return 1;
}

int addMediaObject(pfwl_sip_miprtcpstatic_t *mp, pfwl_field_t *mediaIp,
                   int mediaPort, pfwl_field_t *rtcpIp, int rtcpPort) {
  mp->media_ip_len =
      snprintf(mp->media_ip_s, 30, "%.*s", (int)mediaIp->len, mediaIp->s);
  mp->rtcp_ip_len =
      snprintf(mp->rtcp_ip_s, 30, "%.*s", (int)rtcpIp->len, rtcpIp->s);
  mp->media_port = mediaPort;
  mp->rtcp_port = rtcpPort > 0 ? rtcpPort : (mediaPort + 1);

  return 1;
}

int parseSdp(const unsigned char *body, pfwl_sip_internal_information_t *psip,
             int contentLength) {
  const unsigned char *c, *tmp;
  int offset, last_offset;

  c = body;
  last_offset = 0;
  offset = 0;
  pfwl_sip_miprtcpstatic_t *mp = NULL;
  pfwl_sip_codecmap_t *cdm = NULL;
  int i = 0;
  int mline = 0, cline = 0;
  pfwl_sip_miprtcp_t tmpmp, tmpport;

  /* memset */
  for (i = 0; i < PFWL_SIP_MAX_MEDIA_HOSTS; i++) {
    memset(&psip->mrp[i], 0, sizeof(pfwl_sip_miprtcpstatic_t));
    mp = &psip->mrp[i];
    mp->media_ip_s[0] = '\0';
    mp->rtcp_ip_s[0] = '\0';
    mp->rtcp_ip_len = 0;
    mp->media_ip_len = 0;
    mp->media_port = 0;
    mp->rtcp_port = 0;
    mp->prio_codec = -1;
    /*********/
    cdm = &psip->cdm[i];
    cdm->id = -1;
  }

  psip->cdm_count = 0;
  psip->mrp_size = 0;

  // LERR("PARSE SDP: [%.*s] BEFORE [%d], CL: [%d]", psip->callId.len,
  // psip->callId.s, psip->mrp_size, contentLength);
  // m=audio 3000 RTP/AVP 8 0 18 101
  // m=image 49170 udptl t38

  memset(&tmpmp, 0, sizeof(pfwl_sip_miprtcp_t));

  for (; *c; c++) {
    /* END MESSAGE and START BODY */
    if (*c == '\r' && *(c + 1) == '\n') { /* end of this line */
      //*c = '\0';
      last_offset = offset;
      offset = (c + 2) - body;

      if (contentLength < offset) break;

      tmp = (const unsigned char *)(body + last_offset);
      if (strlen((const char *)tmp) < 4) continue;

      /* c=IN IP4 10.0.0.1 */
      if ((*tmp == 'c' && *(tmp + 1) == '=')) {
        if (cline == 0) {
          parseSdpCLine(&tmpmp, tmp + 2, (offset - last_offset - 2));
          cline++;
        }
      }
      /* a=rtcp:53020 IN IP4 126.16.64.4 */
      else if ((*tmp == 'a' && *(tmp + 1) == '=') &&
               !memcmp(tmp + 2, "rtcp:", 5)) {
        parseSdpALine(&tmpmp, tmp + 7, (offset - last_offset - 7));
      }
    }
  }

  if (tmpmp.media_ip.len == 0 || !isValidIp4Address(&tmpmp.media_ip) ||
      !strncmp(tmpmp.media_ip.s, "0.0.0.0", 7)) {
    return -1;
  }

  /* let do it for rtcp */
  if (tmpmp.rtcp_ip.len == 0) {
    tmpmp.rtcp_ip.len = tmpmp.media_ip.len;
    tmpmp.rtcp_ip.s = tmpmp.media_ip.s;
  }

  // miprtcpstatic_t

  c = body;
  last_offset = 0;
  offset = 0;

  for (; *c; c++) {
    /* END MESSAGE and START BODY */
    if (*c == '\r' && *(c + 1) == '\n') { /* end of this line */
      //*c = '\0';
      last_offset = offset;
      offset = (c + 2) - body;

      if (contentLength < offset) {
        // LERR("OFFSET [%.*s] out of range: Orig [%d] vs Of:[%d], Last [%d]",
        // psip->callId.len, psip->callId.s, contentLength, offset,
        // last_offset);
        break;
      }

      tmp = (body + last_offset);

      if (psip->mrp_size >= PFWL_SIP_MAX_MEDIA_HOSTS) {
        return -1;
      }

      if (strlen((const char *)tmp) < 4) continue;

      /* m=audio 3000 RTP/AVP 8 0 18 101 */
      if ((*tmp == 'm' && *(tmp + 1) == '=')) {
        memset(&tmpport, 0, sizeof(pfwl_sip_miprtcp_t));

        parseSdpMLine(&tmpport, tmp + 2, (offset - last_offset - 2));
        mline++;

        addMediaObject(&psip->mrp[psip->mrp_size], &tmpmp.media_ip,
                       tmpport.media_port, &tmpmp.rtcp_ip, tmpmp.rtcp_port);
        psip->mrp_size++;
      }
      /* a=rtcp:53020 IN IP4 126.16.64.4 */
      else if ((*tmp == 'a' && *(tmp + 1) == '=') &&
               !memcmp(tmp + 2, "rtpmap:", 7)) {
        if (psip->cdm_count >= PFWL_SIP_MAX_MEDIA_HOSTS) break;
        cdm = &psip->cdm[psip->cdm_count];
        parseSdpARtpMapLine(cdm, tmp + 9, (offset - last_offset - 7));
        psip->cdm_count++;
      }
    }

    if (psip->mrp_size >= PFWL_SIP_MAX_MEDIA_HOSTS) break;
  }

  return 1;
}

int parseVQRtcpXR(const unsigned char *body,
                  pfwl_sip_internal_information_t *psip,
                  pfwl_library_state_t* state,
                  pfwl_field_t* extracted_fields_sip) {
  const unsigned char *c, *tmp;
  int offset, last_offset;

  c = body;
  last_offset = 0;
  offset = 0;

  for (; *c; c++) {
    /* END MESSAGE and START BODY */
    if (*c == '\r' && *(c + 1) == '\n') { /* end of this line */
      //*c = '\0';
      last_offset = offset;
      offset = (c + 2) - body;
      tmp = (body + last_offset);

      if (strlen((const char *)tmp) < 4) continue;

      /* CallID: */
      if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_RTCPXR_CALLID)){
        if (*tmp == 'C' && *(tmp + 4) == 'I' &&
            *(tmp + RTCPXR_CALLID_LEN) == ':') {
          set_hname(&(extracted_fields_sip[PFWL_FIELDS_SIP_RTCPXR_CALLID]),
                    (offset - last_offset - RTCPXR_CALLID_LEN),
                    (const char *)tmp + RTCPXR_CALLID_LEN);
          break;
        }
      }
    }
  }

  return 1;
}

pfwl_sip_method_t getMethodType(const char *s, size_t len) {
  if ((*s == 'I' || *s == 'i') && !memcmp(s, INVITE_METHOD, INVITE_LEN)) {
    return INVITE;
  } else if ((*s == 'A' || *s == 'a') && !memcmp(s, ACK_METHOD, ACK_LEN)) {
    return ACK;
  } else if ((*s == 'R' || *s == 'r') &&
             !memcmp(s, REGISTER_METHOD, REGISTER_LEN)) {
    return REGISTER;
  } else if ((*s == 'B' || *s == 'b') && !memcmp(s, BYE_METHOD, BYE_LEN)) {
    return BYE;
  } else if ((*s == 'C' || *s == 'c') &&
             !memcmp(s, CANCEL_METHOD, CANCEL_LEN)) {
    return CANCEL;
  } else if ((*s == 'P' || *s == 'p') && !memcmp(s, PRACK_METHOD, PRACK_LEN)) {
    return PRACK;
  } else if ((*s == 'O' || *s == 'o') &&
             !memcmp(s, OPTIONS_METHOD, OPTIONS_LEN)) {
    return OPTIONS;
  } else if ((*s == 'U' || *s == 'u') &&
             !memcmp(s, UPDATE_METHOD, UPDATE_LEN)) {
    return UPDATE;
  } else if ((*s == 'R' || *s == 'r') && !memcmp(s, REFER_METHOD, REFER_LEN)) {
    return REFER;
  } else if ((*s == 'I' || *s == 'i') && !memcmp(s, INFO_METHOD, INFO_LEN)) {
    return INFO;
  } else if ((*s == 'P' || *s == 'p') &&
             !memcmp(s, PUBLISH_METHOD, PUBLISH_LEN)) {
    return PUBLISH;
  } else if ((*s == 'S' || *s == 's') &&
             !memcmp(s, SUBSCRIBE_METHOD, SUBSCRIBE_LEN)) {
    return SUBSCRIBE;
  } else if ((*s == 'M' || *s == 'm') &&
             !memcmp(s, MESSAGE_METHOD, MESSAGE_LEN)) {
    return MESSAGE;
  } else if ((*s == 'N' || *s == 'n') &&
             !memcmp(s, NOTIFY_METHOD, NOTIFY_LEN)) {
    return NOTIFY;
  } else if ((*s == 'R' || *s == 'r') &&
             !memcmp(s, RESPONSE_METHOD, RESPONSE_LEN)) {
    return RESPONSE;
  } else if ((*s == 'S' || *s == 's') &&
             !memcmp(s, SERVICE_METHOD, SERVICE_LEN)) {
    return SERVICE;
  } else {
    return UNKNOWN;
  }
}

uint8_t splitCSeq(pfwl_sip_internal_information_t *sipStruct, const char *s,
                  size_t len, pfwl_field_t* extracted_fields_sip) {
  char *pch;
  int mylen;

  if ((pch = strchr(s, ' ')) != NULL) {
    mylen = pch - s + 1;

    pch++;

    pfwl_field_t* cSeqMethodString = &(extracted_fields_sip[PFWL_FIELDS_SIP_CSEQ_METHOD_STRING]);
    cSeqMethodString->s = pch;
    cSeqMethodString->len = (len - mylen);

    sipStruct->cSeqMethod = getMethodType(pch++, (len - mylen));
    sipStruct->cSeqNumber = atoi(s);

    return 1;
  }
  return 0;
}

int light_parse_message(const unsigned char *app_data, uint32_t data_length,
                        pfwl_sip_internal_information_t *psip,
                        pfwl_library_state_t* state,
                        pfwl_field_t* extracted_fields_sip) {
  unsigned int new_len = data_length;
  int header_offset = 0;

  psip->contentLength = 0;

  if (data_length <= 2) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  int offset = 0, last_offset = 0;
  const unsigned char *c, *tmp;

  c = app_data;

  for (; *c && c - app_data < new_len; c++) {
    /* END of Request line and START of all other headers */
    if (*c == '\r' && *(c + 1) == '\n') { /* end of this line */

      last_offset = offset;
      offset = (c + 2) - app_data;

      tmp = (app_data + last_offset);

      /* BODY */
      if ((offset - last_offset) == 2) {
        psip->len = offset;

        if (psip->contentLength > 0) {
          psip->len += psip->contentLength;
        }

        break;
      }

      if ((*tmp == 'i' && *(tmp + 1) == ':') ||
          ((*tmp == 'C' || *tmp == 'c') &&
           (*(tmp + 5) == 'I' || *(tmp + 5) == 'i') &&
           *(tmp + CALLID_LEN) == ':')) {
        if (*(tmp + 1) == ':')
          header_offset = 1;
        else
          header_offset = CALLID_LEN;

        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_CALLID)){
          pfwl_field_t* callId =  &(extracted_fields_sip[PFWL_FIELDS_SIP_CALLID]);
          set_hname(callId, (offset - last_offset - CALLID_LEN),
                    (const char *)tmp + CALLID_LEN);
        }
        continue;
      } else if ((*tmp == 'l' && *(tmp + 1) == ':') ||
                 ((*tmp == 'C' || *tmp == 'c') &&
                  (*(tmp + 8) == 'L' || *(tmp + 8) == 'l') &&
                  *(tmp + CONTENTLENGTH_LEN) == ':')) {
        if (*(tmp + 1) == ':')
          header_offset = 1;
        else
          header_offset = CONTENTLENGTH_LEN;

        psip->contentLength = atoi((const char *)tmp + header_offset + 1);
        continue;
      }
    }
  }
  if (!psip->len) {
    return PFWL_PROTOCOL_NO_MATCHES;
  } else {
    return PFWL_PROTOCOL_MATCHES;
  }
}

uint8_t parse_message(const unsigned char *app_data, uint32_t data_length,
                      pfwl_sip_internal_information_t *sip_info,
                      pfwl_inspector_accuracy type,
                      pfwl_field_t* extracted_fields_sip,
                      pfwl_library_state_t* state) {
  int header_offset = 0;
  const char *pch, *ped;
  // uint8_t allowRequest = 0;
  uint8_t allowPai = 0;
  uint8_t parseVIA = 0;
  uint8_t parseContact = 0;

  if (data_length <= 2) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  int offset = 0, last_offset = 0;
  const unsigned char *c;
  const char *tmp;

  c = app_data;

  /* Request/Response line */
  for (; *c && c - app_data < data_length; c++) {
    if (*c == '\n' && *(c - 1) == '\r') {
      offset = (c + 1) - app_data;
      break;
    }
  }

  if (offset == 0) {
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

  sip_info->responseCode = 0;

  tmp = (const char *)app_data;

  if (!memcmp("SIP/2.0 ", tmp, 8)) {
    // Extract Response code's reason
    const char *reason = tmp + 12;
    for (; *reason; reason++) {
      if (*reason == '\n' && *(reason - 1) == '\r') {
        break;
      }
    }
    // TODO: Check if reason/responsecode are valid!
    sip_info->responseCode = atoi((const char *)tmp + 8);
    sip_info->isRequest = 0;

    if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_REASON)){
      pfwl_field_t* reasonField = &(extracted_fields_sip[PFWL_FIELDS_SIP_REASON]);
      reasonField->s = tmp + 12;
      reasonField->len = reason - (tmp + 13);
    }
  } else {
    sip_info->isRequest = 1;

    if (!memcmp(tmp, INVITE_METHOD, INVITE_LEN)) {
      sip_info->methodType = INVITE;
      // allowRequest =    ;
      allowPai = 1;
    } else if (!memcmp(tmp, ACK_METHOD, ACK_LEN))
      sip_info->methodType = ACK;
    else if (!memcmp(tmp, BYE_METHOD, BYE_LEN))
      sip_info->methodType = BYE;
    else if (!memcmp(tmp, CANCEL_METHOD, CANCEL_LEN))
      sip_info->methodType = CANCEL;
    else if (!memcmp(tmp, OPTIONS_METHOD, OPTIONS_LEN))
      sip_info->methodType = OPTIONS;
    else if (!memcmp(tmp, REGISTER_METHOD, REGISTER_LEN))
      sip_info->methodType = REGISTER;
    else if (!memcmp(tmp, PRACK_METHOD, PRACK_LEN))
      sip_info->methodType = PRACK;
    else if (!memcmp(tmp, SUBSCRIBE_METHOD, SUBSCRIBE_LEN))
      sip_info->methodType = SUBSCRIBE;
    else if (!memcmp(tmp, NOTIFY_METHOD, NOTIFY_LEN))
      sip_info->methodType = NOTIFY;
    else if (!memcmp(tmp, PUBLISH_METHOD, PUBLISH_LEN)) {
      sip_info->methodType = PUBLISH;
      /* we need via and contact */
      if (type == PFWL_INSPECTOR_ACCURACY_HIGH) {
        parseVIA = 1;
        parseContact = 1;
        // allowRequest = 1;
      }

    } else if (!memcmp(tmp, INFO_METHOD, INFO_LEN))
      sip_info->methodType = INFO;
    else if (!memcmp(tmp, REFER_METHOD, REFER_LEN))
      sip_info->methodType = REFER;
    else if (!memcmp(tmp, MESSAGE_METHOD, MESSAGE_LEN))
      sip_info->methodType = MESSAGE;
    else if (!memcmp(tmp, UPDATE_METHOD, UPDATE_LEN))
      sip_info->methodType = UPDATE;
    else {
      return PFWL_PROTOCOL_NO_MATCHES;
    }

    if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_METHOD) ||
       pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_REQUEST_URI) ||
       pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_RURI_USER) ||
       pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_RURI_DOMAIN)){
      if ((pch = strchr(tmp + 1, ' ')) != NULL) {
        pfwl_field_t* methodString = &(extracted_fields_sip[PFWL_FIELDS_SIP_METHOD]);
        methodString->s = tmp;
        methodString->len = (pch - tmp);

        if ((ped = strchr(pch + 1, ' ')) != NULL) {
          pfwl_field_t* requestURI = &(extracted_fields_sip[PFWL_FIELDS_SIP_REQUEST_URI]);
          requestURI->s = pch + 1;
          requestURI->len = (ped - pch - 1);
          /* extract user */
          pfwl_field_t* ruriUser = &(extracted_fields_sip[PFWL_FIELDS_SIP_RURI_USER]);
          pfwl_field_t* ruriDomain = &(extracted_fields_sip[PFWL_FIELDS_SIP_RURI_DOMAIN]);
          getUser(ruriUser, ruriDomain,
                  requestURI->s, requestURI->len);
        }
      }
    }
  }

  c = app_data + offset;
  int contentLength = 0;

  for (; *c && c - app_data < data_length; c++) {
    /* END of Request line and START of all other headers */
    if (*c == '\r' && *(c + 1) == '\n') { /* end of this line */

      last_offset = offset;
      offset = (c + 2) - app_data;

      tmp = ((const char *)app_data + last_offset);

      /* BODY */
      if (contentLength > 0 && (offset - last_offset) == 2) {
        if (sip_info->hasSdp) {
          parseSdp(c, sip_info, contentLength);
        } else if (sip_info->hasVqRtcpXR) {
          parseVQRtcpXR(c, sip_info, state, extracted_fields_sip);
        }
        break;
      }

      if ((*tmp == 'i' && *(tmp + 1) == ':') ||
          ((*tmp == 'C' || *tmp == 'c') &&
           (*(tmp + 5) == 'I' || *(tmp + 5) == 'i') &&
           *(tmp + CALLID_LEN) == ':')) {
        if (*(tmp + 1) == ':')
          header_offset = 1;
        else
          header_offset = CALLID_LEN;
        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_CALLID)){
          pfwl_field_t* callId = &(extracted_fields_sip[PFWL_FIELDS_SIP_CALLID]);
          set_hname(callId, (offset - last_offset - CALLID_LEN),
                  tmp + CALLID_LEN);
        }
        continue;
      }
      /* Content-Length */
      if ((*tmp == 'l' && *(tmp + 1) == ':') ||
          ((*tmp == 'C' || *tmp == 'c') &&
           (*(tmp + 8) == 'L' || *(tmp + 8) == 'l') &&
           *(tmp + CONTENTLENGTH_LEN) == ':')) {
        if (*(tmp + 1) == ':')
          header_offset = 1;
        else
          header_offset = CONTENTLENGTH_LEN;

        contentLength = atoi(tmp + header_offset + 1);
        continue;
      } else if ((*tmp == 'C' || *tmp == 'c') &&
                 (*(tmp + 1) == 'S' || *(tmp + 1) == 's') &&
                 *(tmp + CSEQ_LEN) == ':') {                    
        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_CSEQ) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_CSEQ_METHOD_STRING)){
          pfwl_field_t* cSeq = &(extracted_fields_sip[PFWL_FIELDS_SIP_CSEQ]);
          set_hname(cSeq, (offset - last_offset - CSEQ_LEN),
                      tmp + CSEQ_LEN);
          splitCSeq(sip_info, cSeq->s, cSeq->len, extracted_fields_sip);
        }
      }
      /* content type  Content-Type: application/sdp  CONTENTTYPE_LEN */
      else if (((*tmp == 'C' || *tmp == 'c') && (*(tmp + 7) == '-') &&
                (*(tmp + 8) == 't' || *(tmp + 8) == 'T') &&
                *(tmp + CONTENTTYPE_LEN) == ':')) {
        if (*(tmp + CONTENTTYPE_LEN + 1) == ' ')
          header_offset = 1;
        else
          header_offset = 0;

        if (!strncmp((tmp + CONTENTTYPE_LEN + 13 + header_offset), "vq-rtcpxr",
                     9)) {
          sip_info->hasVqRtcpXR = 1;
        } else if (!memcmp((tmp + CONTENTTYPE_LEN + 13 + header_offset), "sdp",
                           3)) {
          sip_info->hasSdp = 1;
        } else if (!memcmp((tmp + CONTENTTYPE_LEN + header_offset + 1),
                           "multipart/mixed", 15)) {
          sip_info->hasSdp = 1;
        }

        continue;
      } else if (parseVIA && ((*tmp == 'V' || *tmp == 'v') &&
                              (*(tmp + 1) == 'i' || *(tmp + 1) == 'i') &&
                              *(tmp + VIA_LEN) == ':')) {
        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_VIA)){
          pfwl_field_t* via = &(extracted_fields_sip[PFWL_FIELDS_SIP_VIA]);
          set_hname(via, (offset - last_offset - VIA_LEN),
                  tmp + VIA_LEN);
        }
        continue;
      } else if (parseContact && ((*tmp == 'm' && *(tmp + 1) == ':') ||
                                  ((*tmp == 'C' || *tmp == 'c') &&
                                   (*(tmp + 5) == 'C' || *(tmp + 5) == 'c') &&
                                   *(tmp + CONTACT_LEN) == ':'))) {
        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_CONTACT_URI)){
          pfwl_field_t* contactURI = &(extracted_fields_sip[PFWL_FIELDS_SIP_CONTACT_URI]);

          if (*(tmp + 1) == ':')
            header_offset = 1;
          else
            header_offset = CONTACT_LEN;

          set_hname(contactURI, (offset - last_offset - header_offset),
                    tmp + header_offset);
        }
        continue;
      } else if ((*tmp == 'f' && *(tmp + 1) == ':') ||
                 ((*tmp == 'F' || *tmp == 'f') &&
                  (*(tmp + 3) == 'M' || *(tmp + 3) == 'm') &&
                  *(tmp + FROM_LEN) == ':')) {
        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_FROM_URI) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_FROM_TAG) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_FROM_USER) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_FROM_DOMAIN)){
          pfwl_field_t* fromURI = &(extracted_fields_sip[PFWL_FIELDS_SIP_FROM_URI]);
          pfwl_field_t* fromTag = &(extracted_fields_sip[PFWL_FIELDS_SIP_FROM_TAG]);
          pfwl_field_t* fromUser = &(extracted_fields_sip[PFWL_FIELDS_SIP_FROM_USER]);
          pfwl_field_t* fromDomain = &(extracted_fields_sip[PFWL_FIELDS_SIP_FROM_DOMAIN]);
          if (*(tmp + 1) == ':')
            header_offset = 1;
          else
            header_offset = FROM_LEN;
          set_hname(fromURI, (offset - last_offset - FROM_LEN),
                    tmp + FROM_LEN);

          if (!fromURI->len == 0 &&
              getTag(fromTag, fromURI->s,
                     fromURI->len)) {
          }
          /* extract user */
          getUser(fromUser, fromDomain, fromURI->s,
                  fromURI->len);
        }

        continue;
      } else if ((*tmp == 't' && *(tmp + 1) == ':') ||
                 ((*tmp == 'T' || *tmp == 't') && *(tmp + TO_LEN) == ':')) {

        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_TO_URI) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_TO_TAG) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_TO_USER) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_TO_DOMAIN)){
          pfwl_field_t* toURI = &(extracted_fields_sip[PFWL_FIELDS_SIP_TO_URI]);
          pfwl_field_t* toTag = &(extracted_fields_sip[PFWL_FIELDS_SIP_TO_TAG]);
          pfwl_field_t* toUser = &(extracted_fields_sip[PFWL_FIELDS_SIP_TO_USER]);
          pfwl_field_t* toDomain = &(extracted_fields_sip[PFWL_FIELDS_SIP_TO_DOMAIN]);
          if (*(tmp + 1) == ':')
            header_offset = 1;
          else
            header_offset = TO_LEN;

          if (set_hname(toURI, (offset - last_offset - header_offset),
                        tmp + header_offset)) {
            if (!toURI->len == 0 &&
                getTag(toTag, toURI->s, toURI->len)) {
            }
            /* extract user */
            getUser(toUser, toDomain, toURI->s, toURI->len);
          }
        }
        continue;
      }

      if (allowPai) {
        if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_PID_URI) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_PAI_USER) ||
           pfwl_protocol_field_required(state, PFWL_PROTOCOL_SIP, PFWL_FIELDS_SIP_PAI_DOMAIN)){
          pfwl_field_t* pidURI = &(extracted_fields_sip[PFWL_FIELDS_SIP_PID_URI]);
          pfwl_field_t* paiUser = &(extracted_fields_sip[PFWL_FIELDS_SIP_PAI_USER]);
          pfwl_field_t* paiDomain = &(extracted_fields_sip[PFWL_FIELDS_SIP_PAI_DOMAIN]);
          if (((*tmp == 'P' || *tmp == 'p') &&
               (*(tmp + 2) == 'P' || *(tmp + 2) == 'p') &&
               (*(tmp + 13) == 'i' || *(tmp + 13) == 'I') &&
               *(tmp + PPREFERREDIDENTITY_LEN) == ':')) {
            set_hname(pidURI,
                      (offset - last_offset - PPREFERREDIDENTITY_LEN),
                      tmp + PPREFERREDIDENTITY_LEN);

            /* extract user */
            getUser(paiUser, paiDomain, pidURI->s, pidURI->len);

            continue;
          } else if (((*tmp == 'P' || *tmp == 'p') &&
                      (*(tmp + 2) == 'A' || *(tmp + 2) == 'a') &&
                      (*(tmp + 13) == 'i' || *(tmp + 13) == 'I') &&
                      *(tmp + PASSERTEDIDENTITY_LEN) == ':')) {
            set_hname(pidURI,
                      (offset - last_offset - PASSERTEDIDENTITY_LEN),
                      tmp + PASSERTEDIDENTITY_LEN);

            /* extract user */
            getUser(paiUser, paiDomain, pidURI->s, pidURI->len);

            continue;
          }
        }
      }
    }
  }
  return PFWL_PROTOCOL_MATCHES;
}

uint8_t parse_packet(const unsigned char *app_data, uint32_t data_length,
                     pfwl_sip_internal_information_t *sip_info,
                     pfwl_inspector_accuracy type,
                     pfwl_field_t* extracted_fields_sip,
                     pfwl_library_state_t *state) {
  uint8_t r = 0;
  if (type == PFWL_INSPECTOR_ACCURACY_LOW) {
    r = light_parse_message(app_data, data_length, sip_info, state, extracted_fields_sip);
  } else {
    r = parse_message(app_data, data_length, sip_info, type, extracted_fields_sip, state);
  }
  /* TODO: To be ported
  if(r == PFWL_PROTOCOL_MATCHES && sip_info->hasVqRtcpXR) {
      msg->rcinfo.correlation_id.s = sip_info->rtcpxr_callid.s;
      msg->rcinfo.correlation_id.len = sip_info->rtcpxr_callid.len;
  }
  */
  return r;
}

uint8_t check_sip(pfwl_library_state_t *state, pfwl_pkt_infos_t *pkt,
                  const unsigned char *app_data, uint32_t data_length,
                  pfwl_tracking_informations_t *t) {
  if (!data_length) {
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }
  memset(&(t->sip_informations), 0, sizeof(t->sip_informations));
  /* check if this is real SIP */
  if (!isalpha(app_data[0])) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  // TODO: TO be ported
  // msg->rcinfo.proto_type = PROTO_SIP;

  uint8_t r = parse_packet(app_data, data_length, &t->sip_informations,
                           state->inspectors_accuracy[PFWL_PROTOCOL_SIP],
                           t->extracted_fields.sip, state);
  return r;
}

pfwl_field_t* get_extracted_fields_sip(pfwl_tracking_informations_t* t){
  return t->extracted_fields.sip;
}
