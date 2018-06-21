/*
 * dynamic_reconfiguration.c
 *
 * Created on: 20/05/2014  
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
#include <ff/ubuffer.hpp>
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
#include <cinttypes>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "mc_api.h"
#include <netinet/ip.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <ff/mapping_utils.hpp>
#include <ff/utils.hpp>
#include <ff/ubuffer.hpp>

#define USE_PKT_POOL
 
using namespace antivirus;
#define CAPACITY_CHUNK 1000
#define SCANNER_POOL_SIZE 4096
#define CLOCK_FREQ 2000000000L
#define SNAPLEN 2000 

#define MIN(a,b) (((a)<(b))?(a):(b))
 
//#define AVAILABLE_CORES 16
//static u_int16_t mapping_fixed[AVAILABLE_CORES]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

#define AVAILABLE_CORES 10
static u_int16_t mapping_fixed[AVAILABLE_CORES]={0,8,9,10,11,12,13,14,15,1/*,2,3,4,5,6,7*/};
 
static ff::uSWSR_Ptr_Buffer* scanner_pool;
static int terminating;

static u_int32_t last_sec=0;
static unsigned long polling_interval=0;

static unsigned long ip_offset=0; 
static int sockfd = 0, newsockfd = 0;

ff::SWSR_Ptr_Buffer *pkt_buff;
int verbose = 0;
unsigned long num_pkt_buffers =64000; // 128000;

void error(const char *msg)
{
  perror(msg);
  exit(1);
}

static unsigned long long pktlengthsnum = 1428043;
static unsigned long* pktlengths = NULL;

void load_pktlengths(){
  pktlengths = (unsigned long* )malloc(sizeof(unsigned long) * pktlengthsnum);
	FILE* pktlengthsfile = fopen("sizes.txt", "r");
	unsigned long i = 0; 
	for (i = 0 ; i< pktlengthsnum; i++){
	  fscanf(pktlengthsfile, "%lu", &(pktlengths[i]));
	}

	fclose(pktlengthsfile);
}


static unsigned long long rcvd_pkts = 0;

int
readn(int f, char *av, int n)
{
  char *a;
  int t;

  a = av;
  t = 0;
  while(t < n){
    int m = read(f, a+t, n-t);
    if(m <= 0){
      if(t == 0)
	return m;
      break;
    }
    t += m;
  }
  return t;
}
 
mc_dpi_packet_reading_result_t reading_cb(void* user_data){
    static unsigned long last_ts=getticks();
    static unsigned long long i = 0;
    /* Grab a packet */
    void *pkt_handle;
    while(1){
        int n = 0;
    	mc_dpi_packet_reading_result_t r;

    	if(getticks()-last_ts>CLOCK_FREQ){
      		last_ts = getticks();
      		++last_sec;
    	}

	++rcvd_pkts;
	/*	struct ether_header *ethhdr=(struct ether_header*) packet;
	if(ethhdr->ether_type!=htons(ETHERTYPE_IP) && ethhdr->ether_type!=htons(ETHERTYPE_IPV6)){
		continue;
	}
	assert(header.len==header.caplen);
	*/
#ifdef USE_PKT_POOL
        while(pkt_buff->empty()){printf("not enough buffers\n");exit(-1);}
        pkt_buff->pop(&pkt_handle);
#else
	pkt_handle=malloc(SNAPLEN);
#endif

	n = readn(newsockfd,(char*)pkt_handle, pktlengths[i]);
	if (n != pktlengths[i]){
	  error("ERROR reading from socket");
	}

	i = (i+1) % pktlengthsnum;

	/*	struct iphdr *ip = (struct iphdr *)pkt_handle;
        struct in_addr srcip, dstip;
        srcip.s_addr=ip->saddr;
	dstip.s_addr=ip->daddr;
	printf("Src ip: %s ", inet_ntoa(srcip));
	printf("Dst ip: %s\n", inet_ntoa(dstip));
	*/
	r.pkt = (unsigned char*) pkt_handle;
	r.current_time=last_sec;
	r.length=n;
	r.user_pointer=pkt_handle;
	return r;
    }
}
 
void processing_cb(mc_dpi_processing_result_t* processing_result,
                   void* user_data){
#ifdef USE_PKT_POOL
    pkt_buff->push((void*)processing_result->user_pointer);
#else
    free((void*)processing_result->user_pointer);
#endif
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
 

FILE* outstats = NULL;

static double idle_watts_socket = 0, idle_watts_cores = 0, idle_watts_offcores = 0, idle_watts_dram = 0;
static double idle_watts_socket_0 = 0, idle_watts_cores_0 = 0, idle_watts_offcores_0 = 0, idle_watts_dram_0 = 0;

void print_stats_callback(u_int16_t num_workers, unsigned long int cores_frequencies, mc_dpi_joules_counters joules, double current_system_load){
  static unsigned long long plast = 0;
  static ticks lastticks = getticks();
  ticks currentticks;
  float pktloss=0;
  unsigned long long tmp_rcvd_pkts = rcvd_pkts;
  double interval;
  currentticks = getticks();
  interval = (double) (currentticks - lastticks) / (double) CLOCK_FREQ;
  fprintf(outstats, "%d %d %lu %f %f %f %f %f %f %f %f %f %f %f\n", last_sec,
                                   num_workers,
                                   cores_frequencies,
	  			   (double)(tmp_rcvd_pkts - plast) / interval,
				   pktloss,
	  ((/*joules.joules_socket[0]+*/joules.joules_socket[1])/(double)interval) - idle_watts_socket,
	  ((/*joules.joules_cores[0]+*/joules.joules_cores[1])/(double)interval) - idle_watts_cores,
	  ((/*joules.joules_offcores[0]+*/joules.joules_offcores[1])/(double)interval) - idle_watts_offcores,
	  ((/*joules.joules_dram[0]+*/joules.joules_dram[1])/(double)interval) - idle_watts_dram,
          ((/*joules.joules_socket[0]+*/joules.joules_socket[0])/(double)interval) - idle_watts_socket_0,
          ((/*joules.joules_cores[0]+*/joules.joules_cores[0])/(double)interval) - idle_watts_cores_0,
          ((/*joules.joules_offcores[0]+*/joules.joules_offcores[0])/(double)interval) - idle_watts_offcores_0,
          ((/*joules.joules_dram[0]+*/joules.joules_dram[0])/(double)interval) - idle_watts_dram_0,
	current_system_load);
  fflush(outstats);
  plast = tmp_rcvd_pkts;
  lastticks = currentticks;
}

 
int main(int argc, char **argv){
  using namespace std;
  ff_mapThreadToCpu(mapping_fixed[0], -20);
  terminating=0;

  try {
    if (argc<3){
            cerr << "Usage: " << argv[0] <<
                " virus-signatures-file polling-interval\n";
            exit(EXIT_FAILURE);
    }

 
    string::size_type trie_depth=DEFAULT_TRIE_MAXIMUM_DEPTH;
     
    char const *virus_signatures_file_name=argv[1];
    polling_interval=atoi(argv[2]);
    outstats = fopen("stats.txt", "w");
    fprintf(outstats, "#CurrentTime NumWorkers Frequency TotalRate PktLoss WattsSocket WattsCores WattsOffCores WattsDRAM\n");
     
    ifstream signatures(virus_signatures_file_name);
    if(!signatures){
            cerr << argv[0] << ": failed to open '" <<
	      virus_signatures_file_name << "'\n";
            exit(EXIT_FAILURE);
    }
 
    signature_reader reader(signatures);
     
    cout << "reading '" << virus_signatures_file_name << "'... ";
     
    timer read_signatures_timer();
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
    timer prepare_signatures_timer();
    prepare_signatures_timer.start();
    t.prepare();
    prepare_signatures_timer.stop();
    cout << setiosflags(ios_base::fixed)
	 << setprecision(3)
	 << prepare_signatures_timer.real_time() << " seconds.\n";
 
    cout << "# of allocated trie nodes: " << t.node_count() << endl;
 
    timer full_timer();

    load_pktlengths();
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    int portno;

    struct sockaddr_in serv_addr, cli_addr;

    if (sockfd < 0)
      error("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 7001;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      error("ERROR on binding");
    }
    socklen_t clilen;
    listen(sockfd, 5);     
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd,(struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0)        
      error("ERROR on accept");

    //    int rwnd = 0;
    //   unsigned int s;
    //    getsockopt(newsockfd, SOL_SOCKET,SO_RCVBUF,(void *)&rwnd, &s);
    //    printf("Current size: %d\n", rwnd);
    //    rwnd = 349536;
    //    setsockopt(newsockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rwnd, sizeof(rwnd));

    mc_dpi_parallelism_details_t details;
    bzero(&details, sizeof(mc_dpi_parallelism_details_t));
    details.available_processors=AVAILABLE_CORES;
    details.mapping=mapping_fixed;
    mc_dpi_library_state_t* state=mc_dpi_init_stateful(
						       32767, 32767, 1000000, 1000000, details);
 
 
    scanner_pool=new ff::uSWSR_Ptr_Buffer(SCANNER_POOL_SIZE);
    scanner_pool->init();
    for(uint i=0; i<SCANNER_POOL_SIZE; i++){
      scanner_pool->push(new byte_scanner(t, match_found));
    }
    mc_dpi_set_read_and_process_callbacks(
					  state, &reading_cb, &processing_cb, NULL);
    mc_dpi_set_flow_cleaner_callback(state, &flow_cleaner);
    dpi_http_callbacks_t callback={0, 0, 0, 0, 0, &body_cb};
    mc_dpi_http_activate_callbacks(state, &callback, (void*)(&t));
     
    mc_dpi_joules_counters joules_before, joules_after, joules_diff;
    joules_before = mc_dpi_joules_counters_read(state);
    double interval = 10;
    printf("Computing watts before running farm (over a %f secs interval)\n", interval);
    sleep(interval);
    joules_after = mc_dpi_joules_counters_read(state);
    joules_diff = mc_dpi_joules_counters_diff(state, joules_after, joules_before);


      idle_watts_socket+=joules_diff.joules_socket[1]/interval;
      idle_watts_cores+=joules_diff.joules_cores[1]/interval;
      idle_watts_offcores+=joules_diff.joules_offcores[1]/interval;
      idle_watts_dram+=joules_diff.joules_dram[1]/interval;
      printf("Idle watts %d: Socket: %f Cores: %f Offcores: %f DRAM: %f\n", 1, joules_diff.joules_socket[1]/interval, joules_diff.joules_cores[1]/interval,joules_diff.joules_offcores[1]/interval, joules_diff.joules_dram[1]/interval);

      idle_watts_socket_0+=joules_diff.joules_socket[0]/interval;
      idle_watts_cores_0+=joules_diff.joules_cores[0]/interval;
      idle_watts_offcores_0+=joules_diff.joules_offcores[0]/interval;
      idle_watts_dram_0+=joules_diff.joules_dram[0]/interval;
      printf("Idle watts %d: Socket: %f Cores: %f Offcores: %f DRAM: %f\n", 0, joules_diff.joules_socket[0]/interval, joules_diff.joules_cores[0]/interval,joules_diff.joules_offcores[0]/interval, joules_diff.joules_dram[0]/interval);


    printf("Wrapping interval: %d seconds\n", mc_dpi_joules_counters_wrapping_interval(state));

#ifdef USE_PKT_POOL
    pkt_buff = new ff::SWSR_Ptr_Buffer(num_pkt_buffers);
    if(pkt_buff == NULL) {
      printf("SWSR_Ptr_Buffer() failed\n");
      return(-1);
    }
    pkt_buff->init();
    void* tmpbuf;
    for(int i=0; i<num_pkt_buffers; i++) {
      posix_memalign((void**) &tmpbuf,
                     DPI_CACHE_LINE_SIZE,
	             SNAPLEN);
      pkt_buff->push(tmpbuf);
      //pkt_buff->push(malloc(SNAPLEN));
    }
#endif

    //    mc_dpi_ipv4_fragmentation_disable(state);
    //    mc_dpi_tcp_reordering_disable(state);

    mc_dpi_reconfiguration_parameters reconf_params;
    reconf_params.sampling_interval = polling_interval;
    reconf_params.num_samples = 6;
    reconf_params.system_load_up_threshold = 90;
    //reconf_params.worker_load_up_threshold = 90;
    reconf_params.system_load_down_threshold = 80;
    //reconf_params.worker_load_down_threshold = 80;
    //reconf_params.freq_type = MC_DPI_RECONF_FREQ_SINGLE; 
    reconf_params.freq_type = MC_DPI_RECONF_FREQ_GLOBAL;
    reconf_params.freq_strategy = MC_DPI_RECONF_STRAT_CORES_CONSERVATIVE;
    reconf_params.stabilization_period = 4;
    //    reconf_params.migrate_collector = 1;
  
    mc_dpi_reconfiguration_set_parameters(state, reconf_params);

    full_timer.start();
    mc_dpi_run(state);
    mc_dpi_set_stats_collection_callback(state,
					 polling_interval,
					 print_stats_callback);
 
    mc_dpi_wait_end(state);
    full_timer.stop();
 
    byte_scanner* bs;
    while(!scanner_pool->empty()){
      scanner_pool->pop((void**) &bs);
      delete bs;
    }
    /* And close the session */
    mc_dpi_terminate(state);
    delete scanner_pool;
    close(newsockfd);
    close(sockfd);
    fclose(outstats);
    exit(EXIT_SUCCESS);
  }catch(exception const &ex){
    cout.flush();
    cerr << typeid(ex).name() << " exception: " << ex.what() << "\n";
    throw;
  }
}
