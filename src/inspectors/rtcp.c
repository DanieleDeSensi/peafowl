/**
 * rtcp.c
 *
 * Created on: 15/10/2018
 *
 * =========================================================================
 *  Copyright (C) 2012-2019, Daniele De Sensi (d.desensi.software@gmail.com)
 *  Copyright (C) 2018-2019, Michele Campus (michelecampus5@gmail.com)
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

#include <peafowl/peafowl.h>
#include <peafowl/inspectors/inspectors.h>

#include <stdio.h>
#include <string.h>

#define PFWL_DEBUG_RTP 0
#define debug_print(fmt, ...)                              \
  do {                                                     \
    if (PFWL_DEBUG_RTP) fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

#define SIZE 4
typedef enum {
    RTCP_SENDER    = 200,
    RTCP_RECEIVER  = 201,
    RTCP_SRC_DESCR = 202,
    RTCP_BYE       = 203,
}RTCPpayloadType;

struct rtcp_header {
    //TOD
}__attribute__((packed));

static int8_t is_valid_payload_type(uint8_t PT)
{
    switch(PT) {
    case RTCP_SENDER:
    case RTCP_RECEIVER:
    case RTCP_SRC_DESCR:
    case RTCP_BYE:
        return PT;
    default:
        return -1;
    }
}


uint8_t check_rtcp(pfwl_state_t* state, const unsigned char* app_data, size_t data_length, pfwl_dissection_info_t* pkt_info,
                   pfwl_flow_info_private_t* flow_info_private)
{
    pfwl_dissector_accuracy_t accuracy = state->inspectors_accuracy[PFWL_PROTO_L7_RTCP];

    /* if(data_length < 2 || */
    /*    ntohs(pkt_info->l4.port_dst) <= 1024 || */
    /*    ntohs(pkt_info->l4.port_src) <= 1024) { */
    /*     return PFWL_PROTOCOL_NO_MATCHES; */
    /* } */

    /* if(data_length >= 12) { */
    /*     if((app_data[0] & 0xFF) == 0x80 || (app_data[0] & 0xFF) == 0xA0) { /\* RTP magic byte[1] *\/ */
    /*         int8_t pType = 0; */
    /*         struct rtp_header *rtp = (struct rtp_header*) app_data; */

    /*         if(rtp->version == 2) { // check Version */
    /*             if(rtp->marker == 0 || rtp->marker == 1) { // check Marker */
    /*                 pType = is_valid_payload_type(rtp->pType); // check Payload Type */
    /*                 if(pType != -1) { */
    /*                     if(accuracy == PFWL_DISSECTOR_ACCURACY_HIGH) { */
    /*                         // TODO extract fields */
    /*                     } */
    /*                     else return PFWL_PROTOCOL_MATCHES; */
    /*                 } */
    /*                 else return PFWL_PROTOCOL_NO_MATCHES; */
    /*             } */
    /*         } */
    /*     } */
    /*     else return PFWL_PROTOCOL_MORE_DATA_NEEDED; */
    /* } */
    /* return PFWL_PROTOCOL_NO_MATCHES; */
}
