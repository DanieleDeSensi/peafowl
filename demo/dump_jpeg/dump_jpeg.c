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
  pfwl_protocol_field_add(state, PFWL_PROTOCOL_HTTP, PFWL_FIELDS_HTTP_CONTENT_TYPE);
  pfwl_protocol_field_add(state, PFWL_PROTOCOL_HTTP, PFWL_FIELDS_HTTP_BODY);

	pcap_t *handle; /* Session handle */
	struct pcap_pkthdr header; /* The header that pcap gives us */
	const u_char *packet; /* The actual packet */

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
  while((packet = pcap_next(handle, &header)) != NULL){
		struct ether_header *ethhdr=(struct ether_header*) packet;
		if(ethhdr->ether_type!=htons(ETHERTYPE_IP) && ethhdr->ether_type!=htons(ETHERTYPE_IPV6)){
			continue;
		}
    pfwl_identification_result_t r = pfwl_get_protocol(state,(const u_char*) packet + sizeof(struct ether_header), header.caplen-sizeof(struct ether_header), time(NULL));
    if(r.protocol_l7 == PFWL_PROTOCOL_HTTP){
      if((r.user_flow_data == NULL) && r.protocol_fields.http[PFWL_FIELDS_HTTP_CONTENT_TYPE].str.len && (strncmp((char*) r.protocol_fields.http[PFWL_FIELDS_HTTP_CONTENT_TYPE].str.s, "image/jpeg", r.protocol_fields.http[PFWL_FIELDS_HTTP_CONTENT_TYPE].str.len) == 0)){
        struct in_addr src, dst;
        src.s_addr = pkt->src_addr_t.ipv4_srcaddr;
        dst.s_addr = pkt->dst_addr_t.ipv4_dstaddr;
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
        r.user_flow_data = fopen(filename, "w");
        assert(r.user_flow_data);
      }


      if(r.protocol_fields.http[PFWL_FIELDS_HTTP_BODY].str.len && r.user_flow_data){
        u_int32_t i;
        for(i=0; i<data_length; ++i)
          fputc(app_data[i], ((FILE*) r.user_flow_data));

        if(last_chunk){
          assert(fclose(((FILE*) r.user_flow_data))==0);
          r.user_flow_data = NULL;
        }

      }
    }

	}
	printf("Finished.\n");
	/* And close the session */
	pcap_close(handle);

	pfwl_terminate(state);
	return 0;
}
