/*
 * flows_summary.c
 *
 * Given a .pcap file, prints summary information about the contained flows.
 *
 * Created on: 05/01/2019
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

static void print_header(){
  printf("#Id\tThreadId\tAddressSrc\tAddressDst\tPortSrc\tPortDst\t"
         "ProtoL2\tProtoL3\tProtoL4\tProtosL7\t"
         "Packets(DirA|DirB)\tBytes(DirA|DirB)\tPacketsL7(DirA|DirB)\tBytesL7(DirA|DirB)\t"
         "TimestampFirst(DirA|DirB)\tTimestampLast(DirA|DirB)\n");
}

static const char* convert_address(pfwl_ip_addr_t address, pfwl_protocol_l3_t l3prot, char* buf, size_t buf_size){
  if(l3prot == PFWL_PROTO_L3_IPV4){
    struct in_addr a;
    a.s_addr = address.ipv4;
    return inet_ntop(AF_INET, (void*) &a, buf, buf_size);
  }else{
    return inet_ntop(AF_INET6, (void*) &(address.ipv6), buf, buf_size);
  }
}

static char protocols_tmp[2048];
static const char* convert_l7_protocols(pfwl_flow_info_t* flow_info){
  protocols_tmp[0] = 0;
  for(size_t i = 0; i < flow_info->protocols_l7_num; i++){
    strcat(protocols_tmp, pfwl_get_L7_protocol_name(flow_info->protocols_l7[i]));
    if(i != flow_info->protocols_l7_num - 1){
      strcat(protocols_tmp, ",");
    }
  }
  return protocols_tmp;
}

static char tmp_srcaddr[64], tmp_dstaddr[64];
void summarizer(pfwl_flow_info_t* flow_info){
  printf("%"PRIu64"\t%"PRIu16"\t%s\t%s\t%"PRIu16"\t%"PRIu16"\t"
         "%s\t%s\t%s\t%s\t"
         "%"PRIu64"|%"PRIu64"\t%"PRIu64"|%"PRIu64"\t%"PRIu64"|%"PRIu64"\t%"PRIu64"|%"PRIu64"\t"
         "%"PRIu32"|%"PRIu32"\t%"PRIu32"|%"PRIu32"\n",
         flow_info->id,
         flow_info->thread_id,
         convert_address(flow_info->addr_src, flow_info->protocol_l3, tmp_srcaddr, sizeof(tmp_srcaddr)),
         convert_address(flow_info->addr_dst, flow_info->protocol_l3, tmp_dstaddr, sizeof(tmp_dstaddr)),
         ntohs(flow_info->port_src),
         ntohs(flow_info->port_dst),
         pfwl_get_L2_protocol_name(flow_info->protocol_l2),
         pfwl_get_L3_protocol_name(flow_info->protocol_l3),
         pfwl_get_L4_protocol_name(flow_info->protocol_l4),
         convert_l7_protocols(flow_info),
         flow_info->num_packets[0], flow_info->num_packets[1],
         flow_info->num_bytes[0], flow_info->num_bytes[1],
         flow_info->num_packets_l7[0], flow_info->num_packets_l7[1],
         flow_info->num_bytes_l7[0], flow_info->num_bytes_l7[1],
         flow_info->timestamp_first[0], flow_info->timestamp_first[1],
         flow_info->timestamp_last[0], flow_info->timestamp_last[1]
         );
}

int main(int argc, char** argv){
  if(argc != 2){
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }
  char* pcap_filename = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  const u_char* packet;
  uint32_t protocols[PFWL_PROTO_L7_NUM];
  struct pcap_pkthdr header;
  memset(protocols, 0, sizeof(protocols));
  uint32_t unknown = 0;

  pcap_t *handle = pcap_open_offline(pcap_filename, errbuf);
  if(handle == NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
    return (2);
  }

  pfwl_state_t* state = pfwl_init();
  pfwl_set_flow_termination_callback(state, &summarizer);
  print_header();
  pfwl_dissection_info_t r;
  pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(pcap_datalink(handle));
  while((packet = pcap_next(handle, &header)) != NULL){
    if(pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), dlt, &r) >= PFWL_STATUS_OK){
      if(r.l4.protocol == IPPROTO_TCP || r.l4.protocol == IPPROTO_UDP){
        if(r.l7.protocol < PFWL_PROTO_L7_NUM){
          ++protocols[r.l7.protocol];
        }else{
          ++unknown;
        }
      }else{
        ++unknown;
      }
    }
  }
  pfwl_terminate(state);

  if (unknown > 0) printf("Unknown packets: %"PRIu32"\n", unknown);
  for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
    if(protocols[i] > 0){
      printf("%s packets: %"PRIu32"\n", pfwl_get_L7_protocol_name(i), protocols[i]);
    }
  }
  return 0;
}
