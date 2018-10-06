/*
 * http_pm_mc.cpp
 *
 * This demo application loads in memory all the packets contained into a specified
 * .pcap file.
 * After that, it analyzes all the HTTP traffic (reordering the TCP packets to have
 * a well-formed stream), and searches for specific patterns (contained into a file 
 * specified by a command line parameter) inside the HTTP body using a certain number
 * of cores (specified by the user).
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

#define _POSIX_C_SOURCE 1
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <typeinfo>
#include "pattern_matching_lib/timer.h"
#include "pattern_matching_lib/trie.h"
#include "pattern_matching_lib/signatures.h"
/** Starting with demo-only includes. **/
#include <peafowl/config.h>
#include <peafowl/peafowl_mc.h>
#include <ff/mapping_utils.hpp>
#include <ff/ubuffer.hpp>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdint.h>

using namespace antivirus;
#define CAPACITY_CHUNK 1000
#define SCANNER_POOL_SIZE 4096

#define AVAILABLE_CORES 16
static u_int16_t mapping[AVAILABLE_CORES]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

static ff::uSWSR_Ptr_Buffer* scanner_pool;

typedef struct pcap_packets_memory{
	unsigned char** packets;
	u_int32_t* sizes;
	u_int32_t num_packets;
	u_int32_t next_packet_to_sent;
}pcap_packets_memory_t;

mc_pfwl_packet_reading_result_t reading_cb(void* user_data){
	mc_pfwl_packet_reading_result_t r;

	pcap_packets_memory_t* packets=(pcap_packets_memory_t*) user_data;

	if(packets->next_packet_to_sent==packets->num_packets){
		r.pkt=NULL;
		printf("Sending EOS!\n");
		fflush(stdout);
	}else{
		r.pkt=packets->packets[packets->next_packet_to_sent];
	}

	r.current_time=time(NULL);
	r.length=packets->sizes[packets->next_packet_to_sent];
	++packets->next_packet_to_sent;
	return r;
}

void processing_cb(mc_pfwl_processing_result_t* processing_result, void* user_data){
	;
}

static void match_found(string::size_type position, trie::value_type const &match) {
	using namespace std;
	cout << "Matched '" << match.second << "' at " << position << endl;
}

void body_cb(pfwl_http_message_informations_t* http_informations, const u_char* app_data, u_int32_t data_length, pfwl_pkt_info_t* pkt, void** flow_specific_user_data, void* user_data, u_int8_t last){
	if(*flow_specific_user_data==NULL){
		if(scanner_pool->mc_pop(flow_specific_user_data)==false){
            *flow_specific_user_data=new byte_scanner(*(static_cast<trie*>(user_data)), match_found);
		}
	}
	byte_scanner* scanner=(byte_scanner*) (*flow_specific_user_data);
	for(u_int32_t i=0; i<data_length; i++){
		scanner->match(app_data[i]);
	}
}

void flow_cleaner(void* flow_specific_user_data){
	if(scanner_pool->mp_push(flow_specific_user_data)==false){
        delete static_cast<byte_scanner*>(flow_specific_user_data);
	}
}


int main(int argc, char **argv){
	using namespace std;
	ff_mapThreadToCpu(mapping[0], -20);

	try {
		if (argc<4){
			cerr << "Usage: " << argv[0] << " virus-signatures-file input-file par_degree\n";
			exit(EXIT_FAILURE);
		}

		string::size_type trie_depth=DEFAULT_TRIE_MAXIMUM_DEPTH;
    
		char const *virus_signatures_file_name=argv[1];
		char const *input_file_name=argv[2];
		u_int16_t num_workers=atoi(argv[3]);

    
		ifstream signatures;
		signatures.open(virus_signatures_file_name);
		if(!signatures){
			cerr << argv[0] << ": failed to open '" << virus_signatures_file_name << "'\n";
			exit(EXIT_FAILURE);
		}

		signature_reader reader(signatures);
    
		cout << "reading '" << virus_signatures_file_name << "'... ";
    
		timer read_signatures_timer;
		read_signatures_timer.start();
		trie t(trie_depth);
		while (reader.next()) {
			t.insert(make_pair(reader.current_pattern(), reader.current_name()));
		}
		read_signatures_timer.stop();
		cout << setiosflags(ios_base::fixed) << setprecision(3) << read_signatures_timer.real_time() << " seconds.\n";
		cout << "preparing '" << virus_signatures_file_name << "'... ";
		timer prepare_signatures_timer;
		prepare_signatures_timer.start();
		t.prepare();
		prepare_signatures_timer.stop();
		cout << setiosflags(ios_base::fixed)
		     << setprecision(3)
		     << prepare_signatures_timer.real_time() << " seconds.\n";

		cout << "# of allocated trie nodes: " << t.node_count() << endl;

		timer full_timer;
		full_timer.start();
		/**************************************************************************/
		/*                       Start scanning the files.                        */
		/**************************************************************************/
		pcap_t *handle;
		char errbuf[PCAP_ERRBUF_SIZE];

		mc_pfwl_parallelism_details_t details;
		bzero(&details, sizeof(mc_pfwl_parallelism_details_t));
		details.available_processors=num_workers;
		details.mapping=mapping;

		mc_pfwl_state_t* state=mc_pfwl_init_stateful(32767, 32767, 1000000, 1000000, details);

		printf("Open offline.\n");
		handle=pcap_open_offline(input_file_name, errbuf);

		if(handle==NULL){
			fprintf(stderr, "Couldn't open device %s: %s\n", input_file_name, errbuf);
			exit(EXIT_FAILURE);
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
		unsigned char** packets;
		u_int32_t* sizes;
		u_int32_t num_packets=0;
		u_int32_t current_capacity=0;
		packets=(unsigned char**) malloc(sizeof(unsigned char*)*CAPACITY_CHUNK);
		sizes=(u_int32_t*) malloc((sizeof(u_int32_t))*CAPACITY_CHUNK);
		assert(packets);
		assert(sizes);
		current_capacity+=CAPACITY_CHUNK;
		uint virtual_offset = 0;
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

			if(num_packets==current_capacity){
                unsigned char** tmp = (unsigned char**) realloc(packets, sizeof(unsigned char*)*(current_capacity+CAPACITY_CHUNK));
                if(!tmp){
                    fprintf(stderr, "NULL on realloc\n");
                    exit(EXIT_FAILURE);
                }
                packets=tmp;
                u_int32_t* tmp2 = (u_int32_t*) realloc(sizes, sizeof(u_int32_t)*(current_capacity+CAPACITY_CHUNK));
                if(!tmp2){
                    fprintf(stderr, "NULL on realloc\n");
                    exit(EXIT_FAILURE);
                }
                sizes=tmp2;
				current_capacity+=CAPACITY_CHUNK;
				assert(packets);
				assert(sizes);
			}


	        size_t len = header.caplen - ip_offset - virtual_offset;
			if(posix_memalign((void**) &(packets[num_packets]), PFWL_CACHE_LINE_SIZE, sizeof(unsigned char)*len)){
				throw std::runtime_error("posix_memalign failure.");
			}
			assert(packets[num_packets]);
			memcpy(packets[num_packets], packet + ip_offset + virtual_offset, len);
			sizes[num_packets] = len;
			++num_packets;
		}
		std::cout << "Read " << num_packets << " packets." << std::endl;
		pcap_close(handle);
		pcap_packets_memory_t x;
		x.packets=packets;
		x.sizes=sizes;
		x.next_packet_to_sent=0;
		x.num_packets=num_packets;


		scanner_pool=new ff::uSWSR_Ptr_Buffer(SCANNER_POOL_SIZE);
		scanner_pool->init();
		for(uint i=0; i<SCANNER_POOL_SIZE; i++){
			scanner_pool->push(new byte_scanner(t, match_found));
		}
    mc_pfwl_set_core_callbacks(state, &reading_cb, &processing_cb, (void*) &x);
		mc_pfwl_set_flow_cleaner_callback(state, &flow_cleaner);
		pfwl_http_callbacks_t callback={0, 0, 0, 0, 0, &body_cb};
		mc_pfwl_http_activate_callbacks(state, &callback, (void*)(&t));
		timer scan_timer;
		scan_timer.start();
		mc_pfwl_run(state);


		mc_pfwl_wait_end(state);
		std::cout << "++++Ended" << std::endl;
		mc_pfwl_print_stats(state);
		scan_timer.stop();

		byte_scanner* bs;
		while(!scanner_pool->empty()){
			scanner_pool->pop((void**) &bs);
			delete bs;
		}
		/* And close the session */
		mc_pfwl_terminate(state);
		delete scanner_pool;

		full_timer.stop();
#if 0
	     		cout << "Completion time: "
			 <<	setiosflags(ios_base::fixed) << setprecision(3)
		     << full_timer.real_time() << " seconds.\n";
#endif

		u_int32_t i;
		for(i=0; i<num_packets; i++){
			free(packets[i]);
		}
		free(packets);
		free(sizes);
		exit(EXIT_SUCCESS);
    }catch(exception const &ex){
    	cout.flush();
    	cerr << typeid(ex).name() << " exception: " << ex.what() << "\n";
    	throw;
    }
}
