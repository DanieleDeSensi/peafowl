/*
 * dynamic_reconfiguration.c
 *
 * Tests the dynamic reconfiguration of the framework.
 *
 * Created on: 23/02/2014
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

#include "mc_api.h"
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

static unsigned int terminate = 0;

mc_dpi_packet_reading_result_t reading_cb(void* user_data){
	pcap_t* handle=(pcap_t*) user_data;
	struct pcap_pkthdr header;
	const u_char *packet;
	mc_dpi_packet_reading_result_t r;
	while(1){
		packet=pcap_next(handle, &header);
		if(packet==NULL || (((struct ether_header*) packet)->ether_type)==htons(ETHERTYPE_IP) || (((struct ether_header*) packet)->ether_type==htons(ETHERTYPE_IPV6))){
			break;
		}
	}


	/**
	 * pcap_next guarantees the validity of the returned pointer only until it is called again. For this reason is necessary to make
	 * a copy to be sure that it is not overwritten.
	 */
	unsigned char* pkt=NULL;
	if(packet!=NULL){
		pkt=(unsigned char*) malloc(sizeof(char)*(header.len-sizeof(struct ether_header)));
		memcpy(pkt, packet + sizeof(struct ether_header), header.len-sizeof(struct ether_header));
	}else{
		printf("Sending EOS!\n");
		terminate=1;
		fflush(stdout);
	}

	r.pkt=pkt;
	r.current_time=time(NULL);
	r.length=header.len-sizeof(struct ether_header);
	r.user_pointer=pkt;
	return r;
}

void processing_cb(mc_dpi_processing_result_t* processing_result, void* user_data){
	free(processing_result->user_pointer);
}

int main(int argc, char** argv){
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	if(argc!=3){
		fprintf(stderr, "Usage: %s pcap_file available_procs\n", argv[0]);
		return -1;
	}

	mc_dpi_parallelism_details_t details;
	bzero(&details, sizeof(mc_dpi_parallelism_details_t));
	details.available_processors=atoi(argv[2]);

	mc_dpi_library_state_t* state=mc_dpi_init_stateful(32767, 32767, 1000000, 1000000, details);


	printf("Open offline.\n");
	handle=pcap_open_offline(argv[1], errbuf);

	if(handle==NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		return (2);
	}

	mc_dpi_set_read_and_process_callbacks(state, &reading_cb, &processing_cb, (void*) handle);

	mc_dpi_run(state);

	uint i=0;
	uint num_workers=0;

	while(!terminate){
		sleep(1);
		num_workers=(i%(details.available_processors-2))+1;
		printf("Try to set %d workers.\n", num_workers);
		if(mc_dpi_set_num_workers(state, num_workers)==DPI_STATE_UPDATE_SUCCESS)
			printf("%d workers activated.\n", num_workers);
		else{
			printf("Workers change failed.\n");
			return 1;
		}
		mc_dpi_print_stats(state);
		++i;
	}

	mc_dpi_wait_end(state);
	mc_dpi_print_stats(state);
	/* And close the session */
	pcap_close(handle);
	mc_dpi_terminate(state);
	return 0;
}
