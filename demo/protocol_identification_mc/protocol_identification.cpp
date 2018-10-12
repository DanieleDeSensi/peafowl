/*
 * demo_identification.c
 *
 * Given a .pcap file, it identifies the protocol of all the packets contained in it.
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

#include <peafowl/peafowl_mc.h>
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

u_int32_t protocols[PFWL_PROTO_L7_NUM];
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
mc_pfwl_packet_reading_result_t reading_cb(void* callback_data){
	pcap_t *handle = ((reading_cb_data*) callback_data)->handle;
	size_t ip_offset = ((reading_cb_data*) callback_data)->ip_offset;
	struct pcap_pkthdr header;
	bool goodpacket = false;

	mc_pfwl_packet_reading_result_t res;
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
void processing_cb(mc_pfwl_processing_result_t* processing_result, void* callback_data){
	pfwl_dissection_info_t r = processing_result->result;
    if(r.protocol.l4prot == IPPROTO_TCP ||
       r.protocol.l4prot == IPPROTO_UDP){
        if(r.protocol.l7prot < PFWL_PROTO_L7_NUM){
            ++protocols[r.protocol.l7prot];
        }else{
            ++unknown;
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

	mc_pfwl_parallelism_details_t par;
	memset(&par, 0, sizeof(par));
	par.available_processors = AVAILABLE_PROCESSORS;
	mc_pfwl_state_t* state = mc_pfwl_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS, par);
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

    memset(protocols, 0, sizeof(protocols));
	/** Set callback to read packets from the network and to process the result of the identification (and maybe forward the packet). **/
	reading_cb_data cbd;
	cbd.handle = handle;
	cbd.ip_offset = ip_offset;
    mc_pfwl_set_core_callbacks(state, reading_cb, processing_cb, (void*) &cbd);
	mc_pfwl_run(state);

	mc_pfwl_wait_end(state);
	mc_pfwl_terminate(state);


	if (unknown > 0) printf("Unknown packets: %" PRIu32 "\n", unknown);
    for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
        if (protocols[i] > 0) printf("%s packets: %" PRIu32 "\n", pfwl_get_L7_protocol_name(i), protocols[i]);
    }
	return 0;
}


