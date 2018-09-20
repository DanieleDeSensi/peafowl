/*
 * sip_extraction.c
 *
 * Given a .pcap file, extracts the SIP requestURI contained in it.
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

	dpi_library_state_t* state=dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
	pcap_t *handle=pcap_open_offline(pcap_filename, errbuf);

	if(handle==NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
		return (2);
	}

	int datalink_type=pcap_datalink(handle);
	uint ip_offset=0;
	if(datalink_type==DLT_EN10MB){
		printf("Datalink type: Ethernet\n");
		ip_offset=sizeof(struct ether_header);
	}else if(datalink_type==DLT_RAW){
		printf("Datalink type: RAW\n");
		ip_offset=0;
	}else if(datalink_type==DLT_LINUX_SLL){
		printf("Datalink type: Linux Cooked\n");
		ip_offset=16;
	}else{
		fprintf(stderr, "Datalink type not supported\n");
		exit(-1);
	}

	const u_char* packet;
	struct pcap_pkthdr header;

	uint virtual_offset = 0;

	pfwl_protocol_field_add(state, DPI_PROTOCOL_SIP, DPI_FIELDS_SIP_REQUEST_URI);

	while((packet=pcap_next(handle, &header))!=NULL){
        if(datalink_type == DLT_EN10MB){
            if(header.caplen < ip_offset){
                continue;
            }
            uint16_t ether_type = ((struct ether_header*) packet)->ether_type;
            if(ether_type == htons(0x8100)){ // VLAN
                virtual_offset = 4;
            }
            if(ether_type != htons(ETHERTYPE_IP) &&
               ether_type != htons(ETHERTYPE_IPV6)){
                continue;
            }
        }

        dpi_identification_result_t r = dpi_get_protocol(state, packet+ip_offset+virtual_offset, header.caplen-ip_offset-virtual_offset, time(NULL));

        if(r.protocol_l7 == DPI_PROTOCOL_SIP &&
           r.protocol_fields[DPI_FIELDS_SIP_REQUEST_URI].len){
          const char* field_value = r.protocol_fields[DPI_FIELDS_SIP_REQUEST_URI].s;
          size_t field_len = r.protocol_fields[DPI_FIELDS_SIP_REQUEST_URI].len;
          printf("Request URI detected: %.*s\n", (int) field_len, field_value);
        }
	}
	return 0;
}
