/*
 * demo_identification.c
 *
 * Given a .pcap file, it identifies the protocol of all the packets contained in it.
 *
 * Created on: 12/11/2012
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

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

int main(int argc, char** argv){
    if(argc!=2){
        fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
        return -1;
    }
    char* pcap_filename=argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    pfwl_state_t* state=pfwl_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
    pcap_t *handle=pcap_open_offline(pcap_filename, errbuf);

    if(handle==NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
        return (2);
    }

    uint ip_offset=0;
    const u_char* packet;
    struct pcap_pkthdr header;

    pfwl_identification_result_t r;
    u_int32_t protocols[PFWL_NUM_PROTOCOLS];
    memset(protocols, 0, sizeof(protocols));
    u_int32_t unknown = 0, icmp = 0;

    while((packet=pcap_next(handle, &header))!=NULL){

      ip_offset = pfwl_parse_datalink(packet, header, handle);

      if(ip_offset == -1)
          ++unknown;
      else {
          r = pfwl_get_protocol(state, packet+ip_offset, header.caplen-ip_offset, time(NULL));

          if(r.protocol_l4 == IPPROTO_TCP ||
             r.protocol_l4 == IPPROTO_UDP){
              if(r.protocol_l7 < PFWL_NUM_PROTOCOLS){
                  ++protocols[r.protocol_l7];
              }else{
                  ++unknown;
              }
          }else if(r.status == PFWL_STATUS_ICMP){
              ++icmp;
          }else{
              ++unknown;
          }
      }
    }

    pfwl_terminate(state);

    if(unknown > 0) printf("Unknown packets: %"PRIu32"\n", unknown);
    if(icmp > 0) printf("ICMP packets: %"PRIu32"\n", icmp);
    for(size_t i = 0; i < PFWL_NUM_PROTOCOLS; i++){
        if(protocols[i] > 0){
            printf("%s packets: %"PRIu32"\n", pfwl_get_protocol_string(i), protocols[i]);
        }
    }
    return 0;
}
