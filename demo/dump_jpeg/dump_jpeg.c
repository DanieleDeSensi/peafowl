/**
 * demo_jpeg.c
 *
 * This demo application dumps on the disk all the jpeg images carried by HTTP packets
 * captured from a .pcap file or from the network.
 * Each dump file is named: "dump_test/[srcIP]:[srcPort]_to_[dstIP]:[dstPort]_at_[timestamp].jpeg
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define MAX_FILENAME_SIZE 128

void flow_delete_cb(void* flow_specific_user_data){
  if(flow_specific_user_data){
    fclose((FILE*) flow_specific_user_data);
  }
}

int main(int argc, char** argv){
  if(argc!=2){
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }

  pfwl_state_t *state = pfwl_init();
  pfwl_set_flow_cleaner_callback(state, &flow_delete_cb);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_HTTP_HEADERS);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_HTTP_BODY);

  pcap_t *handle; /* Session handle */
  struct pcap_pkthdr header; /* The header that pcap gives us */
  const u_char *packet; /* The actual packet */

  char errbuf[PCAP_ERRBUF_SIZE];
  bzero(errbuf, PCAP_ERRBUF_SIZE);
  printf("Open offline.\n");
  handle = pcap_open_offline(argv[1], errbuf);
  if(!handle){
    bzero(errbuf, PCAP_ERRBUF_SIZE);
    printf("Open live %s.\n", argv[1]);
    handle=pcap_open_live(argv[1],  65535, 1, 1000, errbuf);
  }

  if(handle==NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
    return (2);
  }

  pcap_setnonblock(handle, 0, errbuf);

  /* Grab a packet */
  while((packet = pcap_next(handle, &header)) != NULL){
    pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(pcap_datalink(handle));
    pfwl_dissection_info_t r;
    if(pfwl_dissect_from_L2(state,(const u_char*) packet, header.caplen, time(NULL), dlt, &r) >= PFWL_STATUS_OK){
      if(r.l7.protocol == PFWL_PROTO_L7_HTTP){
        pfwl_string_t field;
        if((*r.flow_info.udata == NULL) &&
           !pfwl_http_get_header(&r, "Content-Type", &field) &&
           (strncmp((char*) field.value, "image/jpeg", field.length) == 0)){
          struct in_addr src, dst;
          src.s_addr = r.l3.addr_src.ipv4;
          dst.s_addr = r.l3.addr_dst.ipv4;
          char src_string[64];
          strcpy(src_string, inet_ntoa(src));
          char dst_string[64];
          strcpy(dst_string, inet_ntoa(dst));

          char filename[MAX_FILENAME_SIZE];
          sprintf(filename, "%s:%"PRIu16"_to_%s:%"PRIu16"_at_%ld.jpeg", src_string, ntohs(r.l4.port_src), dst_string, ntohs(r.l4.port_dst), time(NULL));

          u_int32_t j=0;
          /** File already exists. **/
          while(access(filename, F_OK)!=-1){
            sprintf(filename, "%s:%"PRIu16"_to_%s:%"PRIu16"_at_%ld_%d.jpeg", src_string, ntohs(r.l4.port_src), dst_string, ntohs(r.l4.port_dst), time(NULL), ++j);
          }
          *r.flow_info.udata = fopen(filename, "w");
          assert(*r.flow_info.udata);
        }

        if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_HTTP_BODY, &field) && *r.flow_info.udata){
          u_int32_t i;
          for(i = 0; i < field.length; ++i)
            fputc(field.value[i], ((FILE*) *r.flow_info.udata));

          fclose(((FILE*) *r.flow_info.udata));
          *r.flow_info.udata = NULL;
        }
      }
    }
  }
  /* And close the session */
  pcap_close(handle);

  pfwl_terminate(state);
  return 0;
}
