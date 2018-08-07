/**
 * sip.c
 *
 * Created on: 29/06/2016
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

#include "inspectors.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#define SIP_REQUEST 1
#define SIP_REPLY   2

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
#define	 XRTPSTAT_TYPE 1
#define	 XRTPSTATISTICS_TYPE 2
#define	 PRTPSTAT_TYPE 3
#define	 RTPRXSTAT_TYPE 4
#define	 RTPTXSTAT_TYPE 5
#define	 XSIEMENSRTPSTATS_TYPE 6
#define	 XNGRTPSTATS_TYPE 7

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

u_int8_t dpi_sip_activate_callbacks(
               dpi_library_state_t* state,
               dpi_sip_callbacks_t* callbacks,
               void* user_data)
{
    if(state){
        BITSET(state->protocols_to_inspect, DPI_PROTOCOL_SIP);
        BITSET(state->active_callbacks, DPI_PROTOCOL_SIP);
        state->sip_callbacks_user_data=user_data;
        state->sip_callbacks=callbacks;
        return DPI_STATE_UPDATE_SUCCESS;
    }else{
        return DPI_STATE_UPDATE_FAILURE;
    }
}

u_int8_t dpi_sip_disable_callbacks(dpi_library_state_t* state)
{
    if(state){
        BITCLEAR(state->active_callbacks, DPI_PROTOCOL_SIP);
        state->sip_callbacks=NULL;
        state->sip_callbacks_user_data=NULL;
        return DPI_STATE_UPDATE_SUCCESS;
    }else{
        return DPI_STATE_UPDATE_FAILURE;
    }
}


u_int8_t parse_message(const unsigned char* app_data, u_int32_t data_length,
                  dpi_sip_internal_information_t *sip_info, unsigned int type)
{
    int header_offset = 0;
    const char *pch, *ped;
    //u_int8_t allowRequest = 0;
    u_int8_t allowPai = 0;
    u_int8_t parseVIA = 0;
    u_int8_t parseContact = 0;

    if (data_length <= 2){
        return DPI_PROTOCOL_NO_MATCHES;
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

    if(offset == 0){
        return DPI_PROTOCOL_MORE_DATA_NEEDED;
    }

    sip_info->responseCode = 0;

    tmp = (const char*) app_data;

    if (!memcmp ("SIP/2.0 ", tmp, 8)) {
        sip_info->responseCode = atoi((const char*) tmp + 8);
        sip_info->isRequest = 0;

        // Extract Response code's reason
        const char *reason = tmp + 12;
        for (; *reason; reason++) {
            if (*reason == '\n' && *(reason - 1) == '\r') {
                break;
            }
        }

        sip_info->reason = tmp + 12;
        sip_info->reason_len = reason - (tmp + 13);
    } else {
        sip_info->isRequest = 1;

        if (!memcmp (tmp, INVITE_METHOD, INVITE_LEN)) {
            sip_info->methodType = INVITE;
            //allowRequest =    ;
            allowPai = 1;
        }
        else if (!memcmp (tmp, ACK_METHOD, ACK_LEN))
            sip_info->methodType = ACK;
        else if (!memcmp (tmp, BYE_METHOD, BYE_LEN))
            sip_info->methodType = BYE;
        else if (!memcmp (tmp, CANCEL_METHOD, CANCEL_LEN))
            sip_info->methodType = CANCEL;
        else if (!memcmp (tmp, OPTIONS_METHOD, OPTIONS_LEN))
            sip_info->methodType = OPTIONS;
        else if (!memcmp (tmp, REGISTER_METHOD, REGISTER_LEN))
            sip_info->methodType = REGISTER;
        else if (!memcmp (tmp, PRACK_METHOD, PRACK_LEN))
            sip_info->methodType = PRACK;
        else if (!memcmp (tmp, SUBSCRIBE_METHOD, SUBSCRIBE_LEN))
            sip_info->methodType = SUBSCRIBE;
        else if (!memcmp (tmp, NOTIFY_METHOD, NOTIFY_LEN))
            sip_info->methodType = NOTIFY;
        else if (!memcmp (tmp, PUBLISH_METHOD, PUBLISH_LEN)) {
            sip_info->methodType = PUBLISH;
            /* we need via and contact */
            if (type == 2) {
                parseVIA = 1;
                parseContact = 1;
                //allowRequest = 1;
            }

        }
        else if (!memcmp (tmp, INFO_METHOD, INFO_LEN))
            sip_info->methodType = INFO;
        else if (!memcmp (tmp, REFER_METHOD, REFER_LEN))
            sip_info->methodType = REFER;
        else if (!memcmp (tmp, MESSAGE_METHOD, MESSAGE_LEN))
            sip_info->methodType = MESSAGE;
        else if (!memcmp (tmp, UPDATE_METHOD, UPDATE_LEN))
            sip_info->methodType = UPDATE;
        else {
            return DPI_PROTOCOL_NO_MATCHES;
        }

        if ((pch = strchr (tmp + 1, ' ')) != NULL) {

            sip_info->methodString = tmp;
            sip_info->methodString_len = (pch - tmp);

            if ((ped = strchr(pch + 1, ' ')) != NULL) {
                sip_info->requestURI = pch + 1;
                sip_info->requestURI_len = (ped - pch - 1);
                /* extract user */
                //getUser (&sip_info->ruriUser, &sip_info->ruriDomain, sip_info->requestURI.s, sip_info->requestURI.len); // TODO: Porting to be done
            }
        }
    }

    c = app_data + offset;
    int contentLength = 0;

    for (; *c && c - app_data < data_length; c++) {

        /* END of Request line and START of all other headers */
        if (*c == '\r' && *(c + 1) == '\n') {	/* end of this line */

            last_offset = offset;
            offset = (c + 2) - app_data;

            tmp = ((const char*) app_data + last_offset);

            /* BODY */
            if (contentLength > 0 && (offset - last_offset) == 2) {
                if (sip_info->hasSdp) {
                    //parseSdp (c, sip_info, contentLength); // TODO: Porting to be done
                }
                else if (sip_info->hasVqRtcpXR) {
                    //parseVQRtcpXR (c, sip_info); // TODO: Porting to be done
                }
                break;
            }

            if ((*tmp == 'i' && *(tmp + 1) == ':')
                    || ((*tmp == 'C' || *tmp == 'c')
                        && (*(tmp + 5) == 'I' || *(tmp + 5) == 'i')
                        && *(tmp + CALLID_LEN) == ':')) {

                if (*(tmp + 1) == ':')
                    header_offset = 1;
                else
                    header_offset = CALLID_LEN;
                //set_hname (&sip_info->callId, (offset - last_offset - CALLID_LEN), tmp + CALLID_LEN); // TODO: Porting to be done
                continue;
            }
            /* Content-Length */
            if ((*tmp == 'l' && *(tmp + 1) == ':')
                    || ((*tmp == 'C' || *tmp == 'c')
                        && (*(tmp + 8) == 'L' || *(tmp + 8) == 'l')
                        && *(tmp + CONTENTLENGTH_LEN) == ':')) {

                if (*(tmp + 1) == ':')
                    header_offset = 1;
                else
                    header_offset = CONTENTLENGTH_LEN;

                contentLength = atoi (tmp + header_offset + 1);
                continue;
            }
            else if ((*tmp == 'C' || *tmp == 'c')
                     && (*(tmp + 1) == 'S' || *(tmp + 1) == 's')
                     && *(tmp + CSEQ_LEN) == ':') {

                //set_hname (&sip_info->cSeq, (offset - last_offset - CSEQ_LEN), tmp + CSEQ_LEN); // TODO: Porting to be done
                //splitCSeq (sip_info, sip_info->cSeq.s, sip_info->cSeq.len); // TODO: Porting to be done
            }
            /* content type  Content-Type: application/sdp  CONTENTTYPE_LEN */
            else if (((*tmp == 'C' || *tmp == 'c') && (*(tmp + 7) == '-')
                      && (*(tmp + 8) == 't' || *(tmp + 8) == 'T')
                      && *(tmp + CONTENTTYPE_LEN) == ':')) {

                if (*(tmp + CONTENTTYPE_LEN + 1) == ' ')
                    header_offset = 1;
                else
                    header_offset = 0;

                if (!strncmp ((tmp + CONTENTTYPE_LEN + 13 + header_offset), "vq-rtcpxr", 9)) {
                    sip_info->hasVqRtcpXR = 1;
                }
                else if (!memcmp ((tmp + CONTENTTYPE_LEN + 13 + header_offset), "sdp", 3)) {
                    sip_info->hasSdp = 1;
                }
                else if (!memcmp ((tmp+CONTENTTYPE_LEN + header_offset + 1), "multipart/mixed", 15)) {
                    sip_info->hasSdp = 1;
                }

                continue;
            }
            else if (parseVIA && ((*tmp == 'V' || *tmp == 'v')
                                  && (*(tmp + 1) == 'i' || *(tmp + 1) == 'i')
                                  && *(tmp + VIA_LEN) == ':')) {
                //set_hname (&sip_info->via, (offset - last_offset - VIA_LEN), tmp + VIA_LEN); // TODO: Porting to be done
                continue;
            }
            else if (parseContact && ((*tmp == 'm' && *(tmp + 1) == ':') || ((*tmp == 'C' || *tmp == 'c')
                                                                             && (*(tmp + 5) == 'C' || *(tmp + 5) == 'c')
                                                                             && *(tmp + CONTACT_LEN) == ':'))) {
                if (*(tmp + 1) == ':')
                    header_offset = 1;
                else
                    header_offset = CONTACT_LEN;

                //set_hname (&sip_info->contactURI, (offset - last_offset - header_offset), tmp + header_offset); // TODO: Porting to be done
                continue;
            }
            else if ((*tmp == 'f' && *(tmp + 1) == ':')
                     || ((*tmp == 'F' || *tmp == 'f')
                         && (*(tmp + 3) == 'M' || *(tmp + 3) == 'm')
                         && *(tmp + FROM_LEN) == ':')) {
                if (*(tmp + 1) == ':')
                    header_offset = 1;
                else
                    header_offset = FROM_LEN;
                //set_hname (&sip_info->fromURI, (offset - last_offset - FROM_LEN), tmp + FROM_LEN); // TODO: Porting to be done
                sip_info->hasFrom = 1;

                //TODO: Porting to be done
#if 0
                if (!sip_info->fromURI_len == 0 && getTag (&sip_info->fromTag, sip_info->fromURI, sip_info->fromURI_len)) {
                    sip_info->hasFromTag = 1;
                }
#endif
                /* extract user */
                //getUser (&sip_info->fromUser, &sip_info->fromDomain, sip_info->fromURI.s, sip_info->fromURI.len); // TODO: Porting to be done

                continue;
            }
            else if ((*tmp == 't' && *(tmp + 1) == ':')
                     || ((*tmp == 'T' || *tmp == 't')
                         && *(tmp + TO_LEN) == ':')) {

                if (*(tmp + 1) == ':')
                    header_offset = 1;
                else
                    header_offset = TO_LEN;
                /// TODO: Porting to be done
#if 0
                if (set_hname (&sip_info->toURI, (offset - last_offset - header_offset), tmp + header_offset)) {
                    sip_info->hasTo = 1;
                    if (!sip_info->toURI.len == 0 && getTag (&sip_info->toTag, sip_info->toURI.s, sip_info->toURI.len)) {
                        sip_info->hasToTag = 1;
                    }
                    /* extract user */
                    getUser (&sip_info->toUser, &sip_info->toDomain, sip_info->toURI.s, sip_info->toURI.len);
                }
#endif
                continue;
            }


            if (allowPai) {

                if (((*tmp == 'P' || *tmp == 'p')
                     && (*(tmp + 2) == 'P' || *(tmp + 2) == 'p')
                     && (*(tmp + 13) == 'i' || *(tmp + 13) == 'I')
                     && *(tmp + PPREFERREDIDENTITY_LEN) == ':')) {

                    //set_hname (&sip_info->pidURI, (offset - last_offset - PPREFERREDIDENTITY_LEN), tmp + PPREFERREDIDENTITY_LEN); // TODO: Porting to be done
                    sip_info->hasPid = 1;

                    /* extract user */
                    //getUser (&sip_info->paiUser, &sip_info->paiDomain, sip_info->pidURI.s, sip_info->pidURI.len); // TODO: Porting to be done

                    continue;
                }
                else if (((*tmp == 'P' || *tmp == 'p')
                          && (*(tmp + 2) == 'A' || *(tmp + 2) == 'a')
                          && (*(tmp + 13) == 'i' || *(tmp + 13) == 'I')
                          && *(tmp + PASSERTEDIDENTITY_LEN) == ':')) {

                    //set_hname (&sip_info->pidURI, (offset - last_offset - PASSERTEDIDENTITY_LEN), tmp + PASSERTEDIDENTITY_LEN); // TODO: Porting to be done
                    sip_info->hasPid = 1;

                    /* extract user */
                    //getUser (&sip_info->paiUser, &sip_info->paiDomain, sip_info->pidURI.s, sip_info->pidURI.len); // TODO: Porting to be done

                    continue;
                }
            }
        }
    }

    return DPI_PROTOCOL_MATCHES;
}


u_int8_t parse_packet(const unsigned char* app_data,
                 u_int32_t data_length, dpi_sip_internal_information_t *sip_info,
                 unsigned int type) {
    u_int8_t r = parse_message(app_data, data_length,  sip_info, type);
    /* TODO: To be ported
    if(r == DPI_PROTOCOL_MATCHES && sip_info->hasVqRtcpXR) {
        msg->rcinfo.correlation_id.s = sip_info->rtcpxr_callid.s;
        msg->rcinfo.correlation_id.len = sip_info->rtcpxr_callid.len;
    }
    */
    return r;
}

u_int8_t invoke_callbacks_sip(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* tracking)
{
    u_int8_t ret=check_sip(state, pkt, app_data, data_length, tracking);
    if(ret==DPI_PROTOCOL_NO_MATCHES){
        return DPI_PROTOCOL_ERROR;
    }else{
        return DPI_PROTOCOL_MATCHES;
    }
}


u_int8_t check_sip(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data,
                   u_int32_t data_length, dpi_tracking_informations_t* t){
    if(!data_length){
        return DPI_PROTOCOL_MORE_DATA_NEEDED;
    }
    memset(&(t->sip_informations), 0, sizeof(t->sip_informations));
    /* check if this is real SIP */
    if(!isalpha(app_data[0])){
        return DPI_PROTOCOL_NO_MATCHES;
    }

    //TODO: TO be ported
    //msg->rcinfo.proto_type = PROTO_SIP;

    u_int8_t r = parse_packet(app_data, data_length, &t->sip_informations, 2);

    // Callbacks
    if((dpi_sip_callbacks_t*)state->sip_callbacks && r == DPI_PROTOCOL_MATCHES){
        if(t->sip_informations.requestURI_len){
            if(((dpi_sip_callbacks_t*)state->sip_callbacks)->requestURI_cb){
                (((dpi_sip_callbacks_t*)state->sip_callbacks)->requestURI_cb)(t->sip_informations.requestURI, t->sip_informations.requestURI_len);
                t->sip_informations.requestURI_len = 0; // TODO Ugly fix. This is done because requestURI is not copied and the data inside it gets corrupted. We set to 0 to avoid further readings. However, all the strings we want to keep in the flow data should be allocated and copied.
            }
        }
    }

    return r;
}

