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


typedef enum {
    RTCP_SENDER    = 200,
    RTCP_RECEIVER  = 201,
    RTCP_SRC_DESCR = 202,
    RTCP_BYE       = 203,
    RTCP_APP       = 204,
}RTCPpayloadType;


struct rtcp_header {
#if __BYTE_ORDER == __BIG_ENDIAN
	uint8_t version:2;
	uint8_t padding:1;
	uint8_t rc:5;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t rc:5;
	uint8_t padding:1;
	uint8_t version:2;
#endif
    uint8_t pType;
	uint16_t length;

}__attribute__((packed));

#define rtcp_header_get_length(head) ntohs((head)->length)


static int8_t is_valid_payload_type(uint8_t PT)
{
    switch(PT) {
    case RTCP_SENDER:
    case RTCP_RECEIVER:
    case RTCP_SRC_DESCR:
    case RTCP_BYE:
    case RTCP_APP:
        return PT;
    default:
        return -1;
    }
}


uint8_t check_rtcp(pfwl_state_t* state, const unsigned char* app_data, size_t data_length, pfwl_dissection_info_t* pkt_info,
                   pfwl_flow_info_private_t* flow_info_private)
{
    pfwl_dissector_accuracy_t accuracy = state->inspectors_accuracy[PFWL_PROTO_L7_RTCP];

    if(data_length < 4 ||
       ntohs(pkt_info->l4.port_dst) <= 1024 ||
       ntohs(pkt_info->l4.port_src) <= 1024) {
        return PFWL_PROTOCOL_NO_MATCHES;
    }

    if(data_length >= 4) {
        int8_t pType = 0;
        struct rtcp_header *rtcp = (struct rtcp_header*) app_data;

        if(rtcp->version == 2) { // check Version
            pType = is_valid_payload_type(rtcp->pType); // check Payload Type
            if(pType != -1) {
                if(accuracy == PFWL_DISSECTOR_ACCURACY_HIGH) {
                    // TODO extract fields
                }
                else return PFWL_PROTOCOL_MATCHES;
            }
            else return PFWL_PROTOCOL_NO_MATCHES;
        }
    }
    return PFWL_PROTOCOL_NO_MATCHES;
}
