/*
 * demo_jpeg.c
 *
 * This demo application dumps on the disk all the jpeg images carried by HTTP packets
 * captured from a .pcap file or from the network.
 * Each dump file is named: "dump_test/[srcIP]:[srcPort]_to_[dstIP]:[dstPort]_at_[timestamp].jpeg
 *
 * Created on: 19/10/2012
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
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <unistd.h>

#ifndef ETHERTYPE_IPV6
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#endif


#define MAX_FILENAME_SIZE 128


void contentype_cb(dpi_http_message_informations_t* http_informations, const u_char* app_data, u_int32_t data_length, dpi_pkt_infos_t* pkt, void** flow_specific_user_data, void* user_data){
	if((*flow_specific_user_data==NULL) && (strncmp((char*)app_data, "image/jpeg", data_length)==0)){
		struct in_addr src, dst;
		src.s_addr=pkt->src_addr_t.ipv4_srcaddr;
		dst.s_addr=pkt->dst_addr_t.ipv4_dstaddr;
		char src_string[64];
		strcpy(src_string, inet_ntoa(src));
		char dst_string[64];
		strcpy(dst_string, inet_ntoa(dst));


		char filename[MAX_FILENAME_SIZE];
		sprintf(filename, "demo_jpeg_dump/%s:%"PRIu16"_to_%s:%"PRIu16"_at_%"PRIu32".jpeg", src_string, ntohs(pkt->srcport), dst_string, ntohs(pkt->dstport), pkt->processing_time);

		u_int32_t j=0;
		/** File already exists. **/
		while(access(filename, F_OK)!=-1){
			sprintf(filename, "demo_jpeg_dump/%s:%"PRIu16"_to_%s:%"PRIu16"_at_%"PRIu32"_%"PRIu32".jpeg", src_string, ntohs(pkt->srcport), dst_string, ntohs(pkt->dstport), pkt->processing_time, ++j);
		}
		*flow_specific_user_data=fopen(filename, "w");
		assert(*flow_specific_user_data);
	}
}

void body_cb(dpi_http_message_informations_t* http_informations, const u_char* app_data, u_int32_t data_length, dpi_pkt_infos_t* pkt, void** flow_specific_user_data, void* user_data, u_int8_t last_chunk){
	if(*flow_specific_user_data){
		u_int32_t i;
		for(i=0; i<data_length; ++i)
			fputc(app_data[i], ((FILE*) *flow_specific_user_data));

		if(last_chunk){
			assert(fclose(((FILE*) *flow_specific_user_data))==0);
			*flow_specific_user_data=NULL;
		}

	}
}

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

	dpi_http_header_field_callback* single_cb[1]={&contentype_cb};
	const char* ct[1]={"Content-Type"};

	dpi_http_callbacks_t callback={.header_url_callback=0, .header_names=ct, .num_header_types=1, .header_types_callbacks=single_cb, .header_completion_callback=0, .http_body_callback=&body_cb};


	dpi_library_state_t *state=dpi_init_stateful(32767,32767,1000000,1000000);
	dpi_set_flow_cleaner_callback(state, &flow_delete_cb);


	pcap_t *handle; /* Session handle */
	struct pcap_pkthdr header; /* The header that pcap gives us */
	const u_char *packet; /* The actual packet */

	u_int32_t packet_index=0;
	dpi_http_activate_callbacks(state, &callback, &packet_index);


	char errbuf[PCAP_ERRBUF_SIZE];
	bzero(errbuf, PCAP_ERRBUF_SIZE);
	printf("Open offline.\n");
	handle=pcap_open_offline(argv[1], errbuf);
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
	while( (packet = pcap_next(handle, &header)) != NULL){
		++packet_index;
		struct ether_header *ethhdr=(struct ether_header*) packet;
		if(ethhdr->ether_type!=htons(ETHERTYPE_IP) && ethhdr->ether_type!=htons(ETHERTYPE_IPV6)){
			continue;
		}
        dpi_get_protocol(state,(const u_char*) packet + sizeof(struct ether_header), header.caplen-sizeof(struct ether_header), time(NULL));

	}
	printf("Finished.\n");
	/* And close the session */
	pcap_close(handle);

	dpi_terminate(state);
	return 0;
}
