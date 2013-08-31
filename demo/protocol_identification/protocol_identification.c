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

#include <api.h>
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
	}else{
		fprintf(stderr, "Datalink type not supported\n");
		exit(-1);
	}

	const u_char* packet;
	struct pcap_pkthdr header;

	dpi_identification_result_t r;
	u_int32_t http_matches=0;
	u_int32_t dns_matches=0;
	u_int32_t bgp_matches=0;
	u_int32_t smtp_matches=0;
	u_int32_t pop3_matches=0;
	u_int32_t mdns_matches=0;
	u_int32_t ntp_matches=0;
	u_int32_t dhcp_matches=0;
	u_int32_t dhcpv6_matches=0;
	u_int32_t unknown=0;


	while((packet=pcap_next(handle, &header))!=NULL){
		if(header.len<ip_offset) continue;

		r=dpi_stateful_identify_application_protocol(state, packet+ip_offset, header.len-ip_offset, time(NULL));

		if(r.protocol.l4prot==IPPROTO_TCP){
			switch(r.protocol.l7prot){
				case DPI_PROTOCOL_TCP_BGP:
					++bgp_matches;
					break;
				case DPI_PROTOCOL_TCP_HTTP:
					++http_matches;
					break;
				case DPI_PROTOCOL_TCP_SMTP:
					++smtp_matches;
					break;
				case DPI_PROTOCOL_TCP_POP3:
					++pop3_matches;
					break;
				default:
					++unknown;
					break;
			}
		}else if(r.protocol.l4prot==IPPROTO_UDP){
		  switch(r.protocol.l7prot){
				case DPI_PROTOCOL_UDP_DHCP:
					++dhcp_matches;
					break;
				case DPI_PROTOCOL_UDP_DHCPv6:
					++dhcpv6_matches;
					break;
				case DPI_PROTOCOL_UDP_DNS:
					++dns_matches;
					break;
				case DPI_PROTOCOL_UDP_MDNS:
					++mdns_matches;
					break;
				case DPI_PROTOCOL_UDP_NTP:
			        ++ntp_matches;
					break;
				default:
					++unknown;
					break;
			}
		}else{
			++unknown;
		}

	}

	dpi_terminate(state);


	printf("Unknown packets: %"PRIu32"\n", unknown);
	printf("HTTP packets: %"PRIu32"\n", http_matches);
	printf("BGP packets: %"PRIu32"\n", bgp_matches);
	printf("POP3 packets: %"PRIu32"\n", pop3_matches);
	printf("SMTP packets: %"PRIu32"\n", smtp_matches);
	printf("NTP packets: %"PRIu32"\n", ntp_matches);
	printf("DNS packets: %"PRIu32"\n", dns_matches);
	printf("MDNS packets: %"PRIu32"\n", mdns_matches);
	printf("DHCP packets: %"PRIu32"\n", dhcp_matches);
	printf("DHCPv6 packets: %"PRIu32"\n", dhcpv6_matches);

	return 0;
}


