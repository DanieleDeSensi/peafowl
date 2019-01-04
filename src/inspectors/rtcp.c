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

#define RTCP_HDR_SIZE 4

/**
   RTCP Structures
**/
typedef enum {
    RTCP_SENDER    = 200,
    RTCP_RECEIVER  = 201,
    RTCP_SRC_DESCR = 202,
    RTCP_BYE       = 203,
    RTCP_APP       = 204,
}RTCPpayloadType;

/**
   SDES Types
**/
typedef enum {
    END = 0,
    CNAME,
    NAME,
    EMAIL,
    PHONE,
    LOC,
    TOOL,
    NOTE,
    PRIV,
}SDESTypes;

/* RTCP Header */
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


/* Sender Info */
typedef struct _sender_info
{
	uint32_t ntp_timestamp_msw;
	uint32_t ntp_timestamp_lsw;
	uint32_t rtp_timestamp;
	uint32_t senders_packet_count;
	uint32_t senders_octet_count;
} sender_info_t;

/* Report Block */
typedef struct _report_block
{
	uint32_t identifier;
	uint32_t fl_cnpl;
	uint32_t ext_high_seq_num_rec;
	uint32_t interarrival_jitter;
	uint32_t lsr;
	uint32_t delay_lsr;
} report_block_t;

/* Sender Report */
typedef struct _rtcp_sr
{
    struct rtcp_header header;
	uint32_t ssrc;
	sender_info_t si;
	report_block_t rb[1];
} rtcp_sr_t;

/* Receiver Report */
typedef struct _rtcp_rr
{
    struct rtcp_header header;
	uint32_t ssrc;
	report_block_t rb[1];
} rtcp_rr_t;

/* Source Descrption Items*/
typedef struct _rtcp_sdes_item
{
	uint8_t type;
	uint8_t len;
	char content[1];
} rtcp_sdes_item_t;

/* Source Descrption */
typedef struct _rtcp_sdes_t
{
    struct rtcp_header header;
	uint32_t csrc;
	rtcp_sdes_item_t item[1];
} rtcp_sdes_t;

/* Goodbye */
/* typedef struct _rtcp_bye */
/* { */
/*     struct rtcp_header header; */
/* 	uint32_t ssrc[1]; */
/* } rtcp_bye_t; */

/* Application Specific */
/* typedef struct _rtcp_app */
/* { */
/*     struct rtcp_header header; */
/* 	uint32_t ssrc; */
/* 	char name[4]; */
/* } rtcp_app_t; */

/** ************************************ **/

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

// LOW CHECK
static int low_check(struct rtcp_header* rtcp)
{
    int8_t pType = 0;
    if(rtcp->version == 2) { // check Version
        pType = is_valid_payload_type(rtcp->pType); // check Payload Type
        if(pType != -1) {
            return PFWL_PROTOCOL_MATCHES;
        }
    }
    return PFWL_PROTOCOL_NO_MATCHES;
}

// HIGH CHECK (for field extraction)
static int high_check(struct rtcp_header* rtcp, pfwl_state_t* state,
                      int data_length, pfwl_dissection_info_t* pkt_info,
                      pfwl_flow_info_private_t* flow_info_private)
{
    int ret;
    int total = data_length;

    ret = low_check(rtcp);
    if(ret == PFWL_PROTOCOL_MATCHES) {
        pfwl_field_t *extracted_fields = pkt_info->l7.protocol_fields;

        while(rtcp) {

            switch(rtcp->pType) {

            /* Sender Report */
            case RTCP_SENDER: {

                rtcp_sr_t *sr = (rtcp_sr_t*)rtcp;
                /**
                 *  Extract all the Sender fields
                 **/
                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                   pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_SSRC)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_SSRC,
                                          (int64_t) ntohl(sr->ssrc));
                }

                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                   pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_TIME_MSW)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_TIME_MSW,
                                          (int64_t) ntohl(sr->si.ntp_timestamp_msw));
                }

                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                   pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_TIME_LSW)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_TIME_LSW,
                                          (int64_t) ntohl(sr->si.ntp_timestamp_lsw));
                }

                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                   pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_TIME_RTP)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_TIME_RTP,
                                          (int64_t) ntohl(sr->si.rtp_timestamp));
                }

                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                   pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_PKT_COUNT)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_PKT_COUNT,
                                          (int64_t) ntohl(sr->si.senders_packet_count));
                }

                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                   pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_OCT_COUNT)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_OCT_COUNT,
                                          (int64_t) ntohl(sr->si.senders_octet_count));
                }

                if(sr->header.rc > 0) {
                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ID)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_ID,
                                              (int64_t) ntohl(sr->rb[0].identifier));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_FLCNPL)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_FLCNPL,
                                              (int64_t) ntohl(sr->rb[0].fl_cnpl));
                    }
                    
                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_EXT_SEQN_RCV)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_EXT_SEQN_RCV,
                                              (int64_t) ntohl(sr->rb[0].ext_high_seq_num_rec));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_INT_JITTER)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_INT_JITTER,
                                              (int64_t) ntohl(sr->rb[0].interarrival_jitter));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_LSR)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_LSR,
                                              (int64_t) ntohl(sr->rb[0].lsr));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_ALL) || 
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SENDER_DELAY_LSR)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SENDER_DELAY_LSR,
                                              (int64_t) ntohl(sr->rb[0].delay_lsr));
                    }
                }
                break;
            }

            /* Receiver Report */
            case RTCP_RECEIVER: {

                rtcp_rr_t *rr = (rtcp_rr_t*)rtcp;
                /**
                   Extract all the Receiver fields
                **/
                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL) ||
                   pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_SSRC)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_SSRC,
                      (int64_t) ntohl(rr->ssrc));
                }
                
                if(rr->header.rc > 0) {
                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL) ||
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ID)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_ID,
                                              (int64_t) ntohl(rr->rb[0].identifier));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL) ||
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_FLCNPL)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_FLCNPL,
                                              (int64_t) ntohl(rr->rb[0].fl_cnpl));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL) ||
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_EXT_SEQN_RCV)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_EXT_SEQN_RCV,
                                              (int64_t) ntohl(rr->rb[0].ext_high_seq_num_rec));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL) ||
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_INT_JITTER)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_INT_JITTER,
                                              (int64_t) ntohl(rr->rb[0].interarrival_jitter));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL) ||
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_LSR)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_LSR,
                                              (int64_t) ntohl(rr->rb[0].lsr));
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL) ||
                       pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_RECEIVER_DELAY_LSR)) {
                        pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_DELAY_LSR,
                                              (int64_t) ntohl(rr->rb[0].delay_lsr));
                    }
                }
                break;
            }

            /* Source Description */
            case RTCP_SRC_DESCR: {

                int items;
                rtcp_sdes_t *sdes = (rtcp_sdes_t*)rtcp;
                rtcp_sdes_item_t *end = (rtcp_sdes_item_t *)((uint32_t *)rtcp + ntohs(rtcp->length) + 1);
                rtcp_sdes_item_t *rsp, *rspn; // actual and next items

                rsp = &sdes->item[0];
                if(rsp >= end) break;

                if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SDES_CSRC)) {
                    pfwl_field_number_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SDES_CSRC,
                                          (int64_t) ntohl(sdes->csrc));
                }

                for(items = 0; rsp->type; rsp = rspn ) {
                    rspn = (rtcp_sdes_item_t *)((char*)rsp+rsp->len+2);

                    if(rspn >= end) {
                        rsp = rspn;
                        break;
                    }

                    if(pfwl_protocol_field_required(state, flow_info_private, PFWL_FIELDS_L7_RTCP_SDES_TEXT)) {
                        const unsigned char* text = (const unsigned char*) rsp->content;
                        pfwl_field_string_set(extracted_fields, PFWL_FIELDS_L7_RTCP_SDES_TEXT,
                                              text, rsp->len);
                    }
                    items++;
                }
                break;
            }

            /* Goodbye */
            case RTCP_BYE: {
                /* TODO */
                break;
            }
            /* Application Specific */
            case RTCP_APP: {
                /* TODO */
                break;
            }

            /*** WRONG case ***/
            default: return PFWL_PROTOCOL_NO_MATCHES;

            } // switch

            int length = ntohs(rtcp->length);
            if(length == 0) {
                break;
            }

            total -= ntohs((rtcp->length) *4) + RTCP_HDR_SIZE;
            if(total <= 0)
                // End of RTCP packet
                break;
            rtcp = (struct rtcp_header *)((uint32_t*)rtcp + length + 1);
        } // while
    }
    return ret;
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
        struct rtcp_header* rtcp = (struct rtcp_header*) app_data;

        if(accuracy < PFWL_DISSECTOR_ACCURACY_HIGH) {
            return low_check(rtcp);
        } else {
            // check packet and extract fields if needed
            return high_check(rtcp, state, (int) data_length, pkt_info, flow_info_private);
        }
    }
    return PFWL_PROTOCOL_NO_MATCHES;
}
