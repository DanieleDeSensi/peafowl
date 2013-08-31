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
#include <mc_api.h>
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
static u_int16_t mapping[AVAILABLE_CORES]={0,1,2,3,4,5,6,7,8,9,10,11, 12,13,14,15};

static ff::uSWSR_Ptr_Buffer* scanner_pool;

typedef struct pcap_packets_memory{
	unsigned char** packets;
	u_int32_t* sizes;
	u_int32_t num_packets;
	u_int32_t next_packet_to_sent;
	u_int32_t performed_iterations;
	u_int32_t iterations_to_perform;
}pcap_packets_memory_t;

mc_dpi_packet_reading_result_t reading_cb(void* user_data){
	mc_dpi_packet_reading_result_t r;

	pcap_packets_memory_t* packets=(pcap_packets_memory_t*) user_data;

	if(packets->next_packet_to_sent==packets->num_packets){
		++packets->performed_iterations;
		packets->next_packet_to_sent=0;
	}

	if(packets->performed_iterations<packets->iterations_to_perform){
		r.pkt=packets->packets[packets->next_packet_to_sent];
	}else{
		r.pkt=NULL;
		printf("Sending EOS!\n");
		fflush(stdout);
	}
	r.current_time=time(NULL);
	r.length=packets->sizes[packets->next_packet_to_sent];
	++packets->next_packet_to_sent;
	return r;
}

void processing_cb(mc_dpi_processing_result_t* processing_result, void* user_data){
	;
}

static void match_found(string::size_type position, trie::value_type const &match) {
	using namespace std;
	cout << "Matched '" << match.second << "' at " << position << endl;
}

void body_cb(dpi_http_message_informations_t* http_informations, const u_char* app_data, u_int32_t data_length, dpi_pkt_infos_t* pkt, void** flow_specific_user_data, void* user_data, u_int8_t last){
	if(*flow_specific_user_data==NULL){
		if(scanner_pool->mc_pop(flow_specific_user_data)==false){
			*flow_specific_user_data=new byte_scanner(*((trie*) user_data), match_found);
		}
	}
	byte_scanner* scanner=(byte_scanner*) (*flow_specific_user_data);
	for(u_int32_t i=0; i<data_length; i++){
		scanner->match(app_data[i]);
	}
}

void flow_cleaner(void* flow_specific_user_data){
	if(scanner_pool->mp_push(flow_specific_user_data)==false){
		delete (byte_scanner*) flow_specific_user_data;
	}
}


int main(int argc, char **argv){
	using namespace std;
	ff_mapThreadToCpu(mapping[0], -20);

	try {
		if (argc<5){
			cerr << "Usage: " << argv[0] << " virus-signatures-file input-file num_iterations par_degree\n";
			exit(EXIT_FAILURE);
		}

		string::size_type trie_depth=DEFAULT_TRIE_MAXIMUM_DEPTH;
    
		char const *virus_signatures_file_name=argv[1];
		char const *input_file_name=argv[2];
		u_int16_t num_iterations=atoi(argv[3]);
		u_int16_t num_workers=atoi(argv[4]);

    
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

		mc_dpi_parallelism_details_t details;
		bzero(&details, sizeof(mc_dpi_parallelism_details_t));
		details.available_processors=AVAILABLE_CORES;
		details.mapping=mapping;

		details.single_farm_num_workers=num_workers;
		mc_dpi_library_state_t* state=mc_dpi_init_stateful(32767, 32767, 1000000, 1000000, details);

		printf("Open offline.\n");
		handle=pcap_open_offline(input_file_name, errbuf);

		if(handle==NULL){
			fprintf(stderr, "Couldn't open device %s: %s\n", input_file_name, errbuf);
			exit(EXIT_FAILURE);
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
		while((packet=pcap_next(handle, &header))!=NULL){
			if((((struct ether_header*) packet)->ether_type)!=htons(ETHERTYPE_IP) && (((struct ether_header*) packet)->ether_type!=htons(ETHERTYPE_IPV6))){
				continue;
			}

			if(num_packets==current_capacity){
				packets=(unsigned char**) realloc(packets, sizeof(unsigned char*)*(current_capacity+CAPACITY_CHUNK));
				sizes=(u_int32_t*) realloc(sizes, sizeof(u_int32_t)*(current_capacity+CAPACITY_CHUNK));
				current_capacity+=CAPACITY_CHUNK;
				assert(packets);
				assert(sizes);
			}

			assert(header.len>sizeof(struct ether_header));

			posix_memalign((void**) &(packets[num_packets]), DPI_CACHE_LINE_SIZE, sizeof(unsigned char)*(header.len-sizeof(struct ether_header)));
			assert(packets[num_packets]);
			memcpy(packets[num_packets], packet+sizeof(struct ether_header), (header.len-sizeof(struct ether_header)));
			sizes[num_packets]=(header.len-sizeof(struct ether_header));
			++num_packets;
		}
		std::cout << "Read " << num_packets << " packets." << std::endl;
		pcap_close(handle);
		pcap_packets_memory_t x;
		x.packets=packets;
		x.sizes=sizes;
		x.performed_iterations=0;
		x.next_packet_to_sent=0;
		x.iterations_to_perform=num_iterations;
		x.num_packets=num_packets;


		scanner_pool=new ff::uSWSR_Ptr_Buffer(SCANNER_POOL_SIZE);
		scanner_pool->init();
		for(uint i=0; i<SCANNER_POOL_SIZE; i++){
			scanner_pool->push(new byte_scanner(t, match_found));
		}
		mc_dpi_set_read_and_process_callbacks(state, &reading_cb, &processing_cb, (void*) &x);
		mc_dpi_set_flow_cleaner_callback(state, &flow_cleaner);
		dpi_http_callbacks_t callback={0, 0, 0, 0, 0, &body_cb};
		mc_dpi_http_activate_callbacks(state, &callback, (void*)(&t));
		timer scan_timer;
		scan_timer.start();
		mc_dpi_run(state);


		mc_dpi_wait_end(state);
		mc_dpi_print_stats(state);
		scan_timer.stop();

		byte_scanner* bs;
		while(!scanner_pool->empty()){
			scanner_pool->pop((void**) &bs);
			delete bs;
		}
		/* And close the session */
		mc_dpi_terminate(state);
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
