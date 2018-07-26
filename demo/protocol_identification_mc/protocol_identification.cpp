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

#include <mc_api.h>
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

#define AVAILABLE_PROCESSORS 8

int datalink_type=0;

u_int32_t http_matches=0;
u_int32_t dns_matches=0;
u_int32_t bgp_matches=0;
u_int32_t smtp_matches=0;
u_int32_t pop3_matches=0;
u_int32_t mdns_matches=0;
u_int32_t ntp_matches=0;
u_int32_t dhcp_matches=0;
u_int32_t sip_matches=0;
u_int32_t skype_matches=0;
u_int32_t rtp_matches=0;
u_int32_t dhcpv6_matches=0;
u_int32_t unknown=0;

typedef struct{
	pcap_t* handle;
	size_t ip_offset;
}reading_cb_data;

/**
 * This function will be called by the library (active mode only) to read
 * a packet from the network.
 * @param callback_data   A pointer to user specified data (e.g.
 *                        network socket).
 * @return                The packet read. If the pkt field is NULL, then
 *                        there are no more data to read and the library
 *                        will terminate. The user must never try to
 *                        modify the state after that he returned
 *                        pkt=NULL, otherwise the behaviour is not
 *                        defined.
 */
mc_dpi_packet_reading_result_t reading_cb(void* callback_data){
	pcap_t *handle = ((reading_cb_data*) callback_data)->handle;
	size_t ip_offset = ((reading_cb_data*) callback_data)->ip_offset;
	struct pcap_pkthdr header;
	bool goodpacket = false;

	mc_dpi_packet_reading_result_t res;
	do{
			const u_char* packet = pcap_next(handle, &header);
		res.pkt = NULL;

		size_t len = 0;
		uint virtual_offset = 0;
		if(packet){
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
	        len = header.caplen - ip_offset - virtual_offset;
			u_char* packetCopy = (u_char*) malloc(sizeof(u_char)*len);
			memcpy(packetCopy, packet + ip_offset + virtual_offset, sizeof(u_char)*len);
			res.pkt = packetCopy;
			res.user_pointer = packetCopy;
		}
		res.length = len;
		res.current_time = time(NULL);
		goodpacket = true;
	}while(!goodpacket);
	return res;
}



/**
 * This function will be called by the library (active mode only) to
 * process the result of the protocol identification.
 * @param processing_result   A pointer to the result of the library
 *                            processing.
 * @param callback_data       A pointer to user specified data (e.g.
 *                            network socket).
 */
void processing_cb(mc_dpi_processing_result_t* processing_result, void* callback_data){
	dpi_identification_result_t r = processing_result->result;
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
			case DPI_PROTOCOL_UDP_SIP:
				++sip_matches;
				break;
			case DPI_PROTOCOL_UDP_SKYPE:
				++skype_matches;
				break;
			case DPI_PROTOCOL_UDP_RTP:
				++rtp_matches;
				break;
			default:
				++unknown;
				break;
		}
	}else{
		++unknown;
	}
	free(processing_result->user_pointer);
}


int main(int argc, char** argv){
	if(argc!=2){
		fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
		return -1;
	}
	char* pcap_filename=argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	mc_dpi_parallelism_details_t par;
	memset(&par, 0, sizeof(par));
	par.available_processors = AVAILABLE_PROCESSORS;
	mc_dpi_library_state_t* state = mc_dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS, par);
	pcap_t *handle=pcap_open_offline(pcap_filename, errbuf);

	if(handle==NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
		return (2);
	}

	datalink_type=pcap_datalink(handle);
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


	/** Set callback to read packets from the network and to process the result of the identification (and maybe forward the packet). **/
	reading_cb_data cbd;
	cbd.handle = handle;
	cbd.ip_offset = ip_offset;
	mc_dpi_set_read_and_process_callbacks(state, reading_cb, processing_cb, (void*) &cbd);
	mc_dpi_run(state);

	mc_dpi_wait_end(state);
	mc_dpi_terminate(state);


	if (unknown > 0) printf("Unknown packets: %" PRIu32 "\n", unknown);
	if (http_matches > 0) printf("HTTP packets: %" PRIu32 "\n", http_matches);
	if (sip_matches > 0 ) printf("SIP packets: %" PRIu32 "\n", sip_matches);
	if (skype_matches > 0 ) printf("SKYPE packets: %" PRIu32 "\n", skype_matches);
	if (rtp_matches > 0 ) printf("RTP packets: %" PRIu32 "\n", rtp_matches);
	if (bgp_matches > 0 ) printf("BGP packets: %" PRIu32 "\n", bgp_matches);
	if (pop3_matches > 0 ) printf("POP3 packets: %" PRIu32 "\n", pop3_matches);
	if (smtp_matches > 0 ) printf("SMTP packets: %" PRIu32 "\n", smtp_matches);
	if (ntp_matches > 0 ) printf("NTP packets: %" PRIu32 "\n", ntp_matches);
	if (dns_matches > 0 ) printf("DNS packets: %" PRIu32 "\n", dns_matches);
	if (mdns_matches > 0 ) printf("MDNS packets: %" PRIu32 "\n", mdns_matches);
	if (dhcp_matches > 0 ) printf("DHCP packets: %" PRIu32 "\n", dhcp_matches);
	if (dhcpv6_matches > 0 ) printf("DHCPv6 packets: %" PRIu32 "\n", dhcpv6_matches);

	return 0;
}


