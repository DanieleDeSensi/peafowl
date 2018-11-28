/*
 * rtp_extraction.c
 *
 * Given a .pcap file, extracts the RTP Payload Time, Sequence Number, Timestamp
 *                                      and Syncronization Source Identifier
 *
 * Created on: 16/10/2018
 *
 * ===============================================================================
 * Copyright (c) 2018-2019, Michele Campus (michelecampus5@gmail.com)
 * Copyright (c) 2012-2019, Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
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
 * ===============================================================================
 */


#include <peafowl/peafowl.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

int main(int argc, char** argv){

  if(argc != 2){
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }
  char* pcap_filename=argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pfwl_state_t* state = pfwl_init();
  pcap_t *handle = pcap_open_offline(pcap_filename, errbuf);

  if(handle == NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
    return (2);
  }

  const u_char* packet;
  struct pcap_pkthdr header;

  /**
   * Select ALL fileds to export from SENDER and RECEIVER
   **/
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_RTCP_SENDER_ALL);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_RTCP_RECEIVER_ALL);
  /**
   * Select fields for Source Description
   **/
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_RTCP_SDES_CSRC);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_RTCP_SDES_TEXT);

  pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(pcap_datalink(handle));

  while((packet = pcap_next(handle, &header)) != NULL){
    pfwl_dissection_info_t r;
    if(pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), dlt, &r) >= PFWL_STATUS_OK){
        pfwl_string_t field;
        int64_t extracted_value;

      /* ************************ */
      /*** SENDER fields output ***/
      /* ************************ */
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_SSRC, &extracted_value)){
          printf("Sender SSRC: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_TIME_MSW, &extracted_value)){
          printf("NTP Timestamp MSW detected: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_TIME_LSW, &extracted_value)){
          printf("NTP Timestamp LSW detected: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_TIME_RTP, &extracted_value)){
          printf("RTP Timestamp detected: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_PKT_COUNT, &extracted_value)){
          printf("Packet Count detected: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_OCT_COUNT, &extracted_value)){
          printf("Octet detected: %li\n", extracted_value);
      }
      /* If RC block is present */
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_ID, &extracted_value)){
          printf("Sender Report count -->");
          printf("\n\t Identifier: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_FLCNPL, &extracted_value)){
          printf("\n\t SSRC content (Fraction Lost + Cumulative Num Pkt) : %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_EXT_SEQN_RCV, &extracted_value)){
          printf("\n\t Ext High Seq Num: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_INT_JITTER, &extracted_value)){
          printf("\n\t Inter Jitter: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_LSR, &extracted_value)){
          printf("\n\t Last SR timestamp: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SENDER_DELAY_LSR, &extracted_value)){
          printf("\n\t Delay since SR timestamp: %li\n\n", extracted_value);
      }
      /* ************************** */
      /*** RECEIVER fields output ***/
      /* ************************** */
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_SSRC, &extracted_value)){
          printf("Sender SSRC: %li\n", extracted_value);
      }
      /* If RC block is present */
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_ID, &extracted_value)){
          printf("Receiver Report count -->");
          printf("\n\t Identifier: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_FLCNPL, &extracted_value)){
          printf("\n\t SSRC content (Fraction Lost + Cumulative Num Pkt) : %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_EXT_SEQN_RCV, &extracted_value)){
          printf("\n\t Ext High Seq Num: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_INT_JITTER, &extracted_value)){
          printf("\n\t Inter Jitter: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_LSR, &extracted_value)){
          printf("\n\t Last SR timestamp: %li\n", extracted_value);
      }
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_RECEIVER_DELAY_LSR, &extracted_value)){
          printf("\n\t Delay since SR timestamp: %li\n\n", extracted_value);
      }
      /* ************************************ */
      /*** SOURCE DESCRIPTION fields output ***/
      /* ************************************ */
      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SDES_CSRC, &extracted_value)){
          printf("\n\t CSRC (Identifier): %li\n", extracted_value);
      }

      if(r.l7.protocol == PFWL_PROTO_L7_RTCP &&
         !pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_RTCP_SDES_TEXT, &field)){
          printf("SDES Items\n");
          printf("\n\t Text: %.*s\n\n", (int) field.length, field.value);
      }
    }
  }
  return 0;
}
