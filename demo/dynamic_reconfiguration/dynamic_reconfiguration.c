/*
 * http_pm_mc.cpp
 *
 * This demo application loads in memory all the packets contained into a specified
 * .pcap file.
 * After that, it analyzes all the HTTP traffic (reordering the TCP packets to have
 * a well-formed stream), and searches for specific patterns (contained into a file
 * specified by a command line parameter) inside the HTTP body using a certain number
 * of cores (specified by the user).
 * In addition to that, it dynamically changes the parallelism degree while the
 * analyzer is running.
 *
 * Created on: 02/03/2014
 *
 * =========================================================================
 *  Copyright (C) 2012-2014, Daniele De Sensi (d.desensi.software@gmail.com)
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


#define _POSIX_C_SOURCE 1
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <typeinfo>
#include "timer.h"
#include "trie.h"
#include "signatures.h"

#include "mc_api.h"
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <ff/mapping_utils.hpp>
#include <ff/utils.hpp>
#include <ff/ubuffer.hpp>
 
using namespace antivirus;
#define CAPACITY_CHUNK 1000
#define SCANNER_POOL_SIZE 4096
#define CLOCK_FREQ 2000000000L
 
 
#define AVAILABLE_CORES 16
static u_int16_t mapping[AVAILABLE_CORES]={0,2,3,4,5,6,7,8,9,10,11,12,13,14,15,1};
 
static ff::uSWSR_Ptr_Buffer* scanner_pool;

static int terminating;

typedef struct pcap_packets_memory{
  unsigned char** packets;
  u_int32_t* sizes;
  u_int32_t num_packets;
  u_int32_t next_packet_to_sent;
  u_int32_t performed_iterations;
  u_int32_t iterations_to_perform;
}pcap_packets_memory_t;
 
mc_dpi_packet_reading_result_t reading_cb(void* user_data){
  static unsigned long last_ts=getticks();
  static u_int32_t last_sec=0;
 
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
    terminating=1;
    printf("Sending EOS!\n");
    fflush(stdout);
  }
  if(getticks()-last_ts>CLOCK_FREQ){
    last_ts=getticks();
    ++last_sec;
  }
 
  r.current_time=last_sec;
  r.length=packets->sizes[packets->next_packet_to_sent];
  ++packets->next_packet_to_sent;
  return r;
}
 
void processing_cb(mc_dpi_processing_result_t* processing_result,
                   void* user_data){
  ;
}
 
static void match_found(string::size_type position,
                        trie::value_type const &match){
  using namespace std;
  cout << "Matched '" << match.second << "' at " << position << endl;
}
 
void body_cb(dpi_http_message_informations_t* http_informations,
             const u_char* app_data, u_int32_t data_length,
             dpi_pkt_infos_t* pkt,
             void** flow_specific_user_data, void* user_data,
             u_int8_t last){
  if(*flow_specific_user_data==NULL){
    if(scanner_pool->mc_pop(flow_specific_user_data)==false){
            *flow_specific_user_data=
	      new byte_scanner(*((trie*) user_data), match_found);
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
 

static double idle_watts_socket[DPI_MAX_CPU_SOCKETS];
static double idle_watts_cores[DPI_MAX_CPU_SOCKETS];
static double idle_watts_offcores[DPI_MAX_CPU_SOCKETS];
static double idle_watts_dram[DPI_MAX_CPU_SOCKETS];


void print_watts(mc_dpi_joules_counters diff, double interval){
  uint i=0;

  printf("================Energy Stats===============\n");
  printf("Watts of entire socket:\t|");
  for(i=0; i<diff.num_sockets; i++){
    printf("%8.4f|", (diff.joules_socket[i])/interval);
  }
  printf("\n");
  printf("Watts of cores:\t\t|");
  for(i=0; i<diff.num_sockets; i++){
    printf("%8.4f|", (diff.joules_cores[i])/interval);
  }
  printf("\n");
  printf("Watts of offcores:\t|");
  for(i=0; i<diff.num_sockets; i++){
    printf("%8.4f|", (diff.joules_offcores[i])/interval);
  }
  printf("\n");
  printf("Watts of DRAM:\t\t|");
  for(i=0; i<diff.num_sockets; i++){
    printf("%8.4f|", (diff.joules_dram[i])/interval);
  }
  printf("\n");
  printf("===========================================\n");
}
 
int main(int argc, char **argv){
  memset(idle_watts_socket, 0, sizeof(idle_watts_socket));
  memset(idle_watts_cores, 0, sizeof(idle_watts_cores));
  memset(idle_watts_offcores, 0, sizeof(idle_watts_offcores));
  memset(idle_watts_dram, 0, sizeof(idle_watts_dram));

  using namespace std;
  ff_mapThreadToCpu(mapping[0], -20);
  terminating=0;
  unsigned int num_workers=0;
  unsigned int dynamically_change=1;

  try {
    if (argc<4){
            cerr << "Usage: " << argv[0] <<
                    " virus-signatures-file input-file "
	             "num_iterations [num_workers]\n";
            exit(EXIT_FAILURE);
    }
    if(argc>4){
      num_workers=atoi(argv[4]);
      dynamically_change=0;
    }
 
    string::size_type trie_depth=DEFAULT_TRIE_MAXIMUM_DEPTH;
     
    char const *virus_signatures_file_name=argv[1];
    char const *input_file_name=argv[2];
    u_int16_t num_iterations=atoi(argv[3]);
     
    ifstream signatures;
    signatures.open(virus_signatures_file_name);
    if(!signatures){
            cerr << argv[0] << ": failed to open '" <<
	      virus_signatures_file_name << "'\n";
            exit(EXIT_FAILURE);
    }
 
    signature_reader reader(signatures);
     
    cout << "reading '" << virus_signatures_file_name << "'... ";
     
    timer read_signatures_timer;
    read_signatures_timer.start();
    trie t(trie_depth);
    while (reader.next()) {
      t.insert(make_pair(reader.current_pattern(),
			 reader.current_name()));
    }
    read_signatures_timer.stop();
    cout << setiosflags(ios_base::fixed) << setprecision(3) <<
      read_signatures_timer.real_time() << " seconds.\n";
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

    /******************************************************/
    /*             Start scanning the files.              */
    /******************************************************/
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
 
    mc_dpi_parallelism_details_t details;
    bzero(&details, sizeof(mc_dpi_parallelism_details_t));
    details.available_processors=AVAILABLE_CORES;
    details.mapping=mapping;
 
    mc_dpi_library_state_t* state=mc_dpi_init_stateful(
						       32767, 32767, 1000000, 1000000, details);
 
    printf("Open offline.\n");
    handle=pcap_open_offline(input_file_name, errbuf);
 
    if(handle==NULL){
      fprintf(stderr, "Couldn't open device %s: %s\n",
	      input_file_name, errbuf);
      exit(EXIT_FAILURE);
    }
    const u_char* packet;
    struct pcap_pkthdr header;
    unsigned char** packets;
    u_int32_t* sizes;
    u_int32_t num_packets=0;
    u_int32_t current_capacity=0;
    packets=(unsigned char**)
      malloc(sizeof(unsigned char*)*CAPACITY_CHUNK);
    sizes=(u_int32_t*)
      malloc((sizeof(u_int32_t))*CAPACITY_CHUNK);
    assert(packets);
    assert(sizes);
    current_capacity+=CAPACITY_CHUNK;
    while((packet=pcap_next(handle, &header))!=NULL){
      if((((struct ether_header*) packet)->ether_type)!=
	 htons(ETHERTYPE_IP) &&
	 (((struct ether_header*) packet)->ether_type!=
	  htons(ETHERTYPE_IPV6))){
	continue;
      }
 
      if(num_packets==current_capacity){
	packets=(unsigned char**)
	  realloc(packets, sizeof(unsigned char*)*
		  (current_capacity+CAPACITY_CHUNK));
	sizes=(u_int32_t*)
	  realloc(sizes, sizeof(u_int32_t)*
		  (current_capacity+CAPACITY_CHUNK));
	current_capacity+=CAPACITY_CHUNK;
	assert(packets);
	assert(sizes);
      }
 
      assert(header.len>sizeof(struct ether_header));
 
      posix_memalign((void**) &(packets[num_packets]),
		     DPI_CACHE_LINE_SIZE,
		     sizeof(unsigned char)*
		     (header.len-sizeof(struct ether_header)));
      assert(packets[num_packets]);
      memcpy(packets[num_packets],
	     packet+sizeof(struct ether_header),
	     (header.len-sizeof(struct ether_header)));
            sizes[num_packets]=
	      (header.len-sizeof(struct ether_header));
            ++num_packets;
    }
    std::cout << "Read " << num_packets << " packets." <<
      std::endl;
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
    mc_dpi_set_read_and_process_callbacks(
					  state, &reading_cb, &processing_cb, (void*) &x);
    mc_dpi_set_flow_cleaner_callback(state, &flow_cleaner);
    dpi_http_callbacks_t callback={0, 0, 0, 0, 0, &body_cb};
    mc_dpi_http_activate_callbacks(state, &callback, (void*)(&t));
    
    double total_joules_socket=0;
    double total_joules_cores=0;
    double total_joules_offcores=0;
    double total_joules_dram=0;

    mc_dpi_joules_counters joules_before, joules_after, joules_diff;
    double interval;
    unsigned int i=0;

#if 0
    joules_before = mc_dpi_read_joules_counters(state);
    interval = 10;
    printf("Computing watts before running farm (over a %f secs interval)\n", interval);
    sleep(interval);
    joules_after = mc_dpi_read_joules_counters(state);
    joules_diff = mc_dpi_diff_joules_counters(joules_after, joules_before);
    print_watts(joules_diff, interval);

    for(i=0; i<joules_before.num_sockets; i++){
      idle_watts_socket[i]=joules_diff.joules_socket[i]/interval;
      idle_watts_cores[i]=joules_diff.joules_cores[i]/interval;
      idle_watts_offcores[i]=joules_diff.joules_offcores[i]/interval;
      idle_watts_dram[i]=joules_diff.joules_dram[i]/interval;
    }
#endif
    printf("Wrapping interval: %d seconds\n", mc_dpi_joules_counters_wrapping_interval(state));

    if(!dynamically_change){
      printf("Fixed workers are required.\n");
      mc_dpi_set_num_workers(state, num_workers);
    }

    full_timer.start();
    mc_dpi_run(state);

    i=0;

    while(!terminating){
      if(dynamically_change){
        num_workers=(i%(details.available_processors-2))+1;
        struct timeval before;
        gettimeofday(&before,NULL);
        u_int64_t before_usec = 1000000 * before.tv_sec + before.tv_usec;
        if(mc_dpi_set_num_workers(state, num_workers)==DPI_STATE_UPDATE_SUCCESS)
	  printf("%d workers activated.\n", num_workers);
        else{
	  printf("Workers change failed.\n");
	  return 1;
        }
        struct timeval after;
        gettimeofday(&after,NULL);
        u_int64_t after_usec = 1000000 * after.tv_sec + after.tv_usec;
        printf("Reconfigured in %f msecs\n", ((double)(after_usec - before_usec))/(double)1000);
      }
      joules_before = mc_dpi_read_joules_counters(state);
      interval=10;
      sleep(interval);
      joules_after = mc_dpi_read_joules_counters(state);
      joules_diff = mc_dpi_diff_joules_counters(joules_after, joules_before);
      //print_watts(joules_diff, interval);
      printf("\n");
      int j;
      for(j=0; j<joules_before.num_sockets; j++){
	total_joules_socket+=joules_diff.joules_socket[j];
	total_joules_cores+=joules_diff.joules_cores[j];
	total_joules_offcores+=joules_diff.joules_offcores[j];
	total_joules_dram+=joules_diff.joules_dram[j];
      }
      ++i;
    }
 
    mc_dpi_wait_end(state);
    full_timer.stop();
    //    mc_dpi_print_stats(state);
 
    byte_scanner* bs;
    while(!scanner_pool->empty()){
      scanner_pool->pop((void**) &bs);
      delete bs;
    }
    /* And close the session */
    mc_dpi_terminate(state);
    delete scanner_pool;
 
    cout << "Completion time: ["
         <<   setiosflags(ios_base::fixed) << setprecision(3)
         << full_timer.real_time() << " seconds.]\n";

    printf("Socket: [%fJ, %fW]\n", total_joules_socket, total_joules_socket/(double)full_timer.real_time());
    printf("Cores: [%fJ, %fW]\n", total_joules_cores, total_joules_cores/(double)full_timer.real_time());
    printf("Offcores: [%fJ, %fW]\n", total_joules_offcores, total_joules_offcores/(double)full_timer.real_time());
    printf("DRAM: [%fJ, %fW]\n", total_joules_dram, total_joules_dram/(double)full_timer.real_time());

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
