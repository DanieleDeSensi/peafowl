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
#include <iostream>
#include <ff/mapping_utils.hpp>
#include <ff/utils.hpp>
#include <ff/ubuffer.hpp>



#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000
#define CAPACITY_CHUNK 1000

#define AVAILABLE_PROCESSORS 8

#define CLOCK_FREQ 2400000000L


static int terminating = 0;

u_int32_t total_pkts=0;
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
static unsigned int intervals;
static double* rates = NULL;
static double* durations = NULL;
static u_int32_t current_interval=0;
static time_t last_sec=0;
static u_int64_t processed_packets=0;

typedef struct pcap_packets_memory{
  unsigned char** packets;
  u_int32_t* sizes;
  u_int32_t num_packets;
  u_int32_t next_packet_to_sent;
}pcap_packets_memory_t;

inline ticks ticks_wait(ticks nticks) {
  ticks delta;
  ticks t0 = getticks();
  do { delta = (getticks()) - t0; } while (delta < nticks);
  return delta-nticks;
}

double getmstime(){
  struct timeval  tv;
  gettimeofday(&tv, NULL);

  return (tv.tv_sec) * 1000 + (tv.tv_usec) / 1000 ;
}
 
#define BURST_SIZE 10.0


#define CLOCK_RESYNC 10
void* clock_thread(void*){
  ff_mapThreadToCpu(0, -20);
  last_sec = time(NULL);
  while(!terminating){
    sleep(1);
#if 1
    last_sec = time(NULL);
#else
    int i = 0;
    time_t tmp;
    if(i++ == CLOCK_RESYNC){
      i = 0;
      tmp = time(NULL);
      if(tmp>=last_sec){
    last_sec = tmp;
      }
    }else{
      ++last_sec;
    }
#endif
  }
  return NULL;
}


mc_dpi_packet_reading_result_t reading_cb(void* user_data){
  static time_t current_interval_start=0;
  static u_int32_t current_burst_size = 0;
  static ticks excess = 0;
  static ticks def = getticks();
 
  mc_dpi_packet_reading_result_t r;
 
  pcap_packets_memory_t* packets=(pcap_packets_memory_t*) user_data;

  if(packets->next_packet_to_sent==packets->num_packets){
    packets->next_packet_to_sent=0;
  }
 
  if(current_interval < intervals){
    r.pkt=packets->packets[packets->next_packet_to_sent];
  }else{
    r.pkt=NULL;
    terminating=1;
    printf("Sending EOS!\n");
    fflush(stdout);
  }

  if(current_burst_size == BURST_SIZE){
    /** Sleep to get the rate. **/
    double wait_interval_secs = 1.0 / rates[current_interval];
    ticks ticks_to_sleep = ((double)CLOCK_FREQ * wait_interval_secs * (double) BURST_SIZE);

    current_burst_size = 0;

    excess += (getticks()-def);

    if(excess >= ticks_to_sleep){
        //excess = 0;
      excess -= ticks_to_sleep;
    }else{
        excess = ticks_wait(ticks_to_sleep - excess);
    }
   
    def = getticks();
  }


  ++current_burst_size;

  if(current_interval_start == 0){
    current_interval_start = last_sec;
  }

  ++processed_packets;

  /** Go to the next rate **/
  if(last_sec - current_interval_start >= durations[current_interval]){
    current_interval_start = last_sec;
    current_interval++;
    excess = 0;
  }
 
  r.current_time=last_sec;
  r.length=packets->sizes[packets->next_packet_to_sent];
  ++packets->next_packet_to_sent;

  ++total_pkts;
  return r;
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
}

static void load_rates(const char* fileName){
  FILE* f = NULL;
  f = fopen(fileName, "r");
  float rate = 0;
  float duration = 0;
  unsigned int size = 0;
  rates = (double*) malloc(sizeof(double)*10);
  durations = (double*) malloc(sizeof(double)*10);
  size = 10;
  intervals = 0;
  if(f){
    char line[512];
    while(fgets(line, 512, f) != NULL){
      sscanf(line, "%f %f", &rate, &duration);
      rates[intervals] = rate;
      durations[intervals] = duration;
      ++intervals;

      if(intervals == size){
        size += 10;
        double* tmp = (double*) realloc(rates, sizeof(double)*size);
        if(!tmp){
            std::cerr << "NULL realloc" << std::endl;
            exit(EXIT_FAILURE);
        }
        rates = tmp;
        tmp = (double*) realloc(durations, sizeof(double)*size);
        if(!tmp){
            std::cerr << "NULL realloc" << std::endl;
            exit(EXIT_FAILURE);
        }
        durations = tmp;
      }
    }
    fclose(f);
  }
}

int main(int argc, char** argv){
	if(argc < 3){
		fprintf(stderr, "Usage: %s pcap_file rates_file\n", argv[0]);
		return -1;
	}
	char* pcap_filename = argv[1];
  load_rates(argv[2]);
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

        const u_char* packet;
    struct pcap_pkthdr header;
    unsigned char** packets;
    u_int32_t* sizes;
    u_int32_t num_packets=0;
    u_int32_t current_capacity=0;
    packets = (unsigned char**) malloc(sizeof(unsigned char*)*CAPACITY_CHUNK);
    sizes = (u_int32_t*) malloc((sizeof(u_int32_t))*CAPACITY_CHUNK);
    assert(packets);
    assert(sizes);
    current_capacity += CAPACITY_CHUNK;
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


    while((packet = pcap_next(handle, &header)) != NULL){
        if(header.caplen < ip_offset)
            continue;
        uint virtual_offset = 0;
        if(datalink_type == DLT_EN10MB){
            if(header.caplen < ip_offset + sizeof(struct ether_header)){
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
            unsigned char** tmp=(unsigned char**)realloc(packets, sizeof(unsigned char*)*(current_capacity+CAPACITY_CHUNK));
            if(!tmp){
                std::cerr << "NULL realloc" << std::endl;
                exit(EXIT_FAILURE);
            }
            packets = tmp;
            u_int32_t* tmp2 = (u_int32_t*) realloc(sizes, sizeof(u_int32_t)*(current_capacity+CAPACITY_CHUNK));
            if(!tmp2){
                std::cerr << "NULL realloc" << std::endl;
                exit(EXIT_FAILURE);
            }
            sizes = tmp2;
            current_capacity+=CAPACITY_CHUNK;
            assert(packets);
            assert(sizes);
        }
 
        assert(header.caplen>sizeof(struct ether_header));
 
        posix_memalign((void**) &(packets[num_packets]),
                       DPI_CACHE_LINE_SIZE,
                       sizeof(unsigned char)*
                       (header.caplen-ip_offset-virtual_offset));
        assert(packets[num_packets]);
        memcpy(packets[num_packets], packet+ip_offset+virtual_offset,
               (header.caplen-sizeof(struct ether_header)));
        sizes[num_packets] = (header.caplen-ip_offset-virtual_offset);
        ++num_packets;
    }
    std::cout << "Read " << num_packets << " packets." << std::endl;
    pcap_close(handle);
    pcap_packets_memory_t x;
    x.packets=packets;
    x.sizes=sizes;
    x.next_packet_to_sent=0;
    x.num_packets=num_packets;

  pthread_t clock;
	mc_dpi_set_read_and_process_callbacks(state, reading_cb, processing_cb, (void*) &x);
  pthread_create(&clock, NULL, clock_thread, NULL);

  struct timeval tv;

  gettimeofday(&tv, NULL);
  double time_start = ((tv.tv_sec) * 1000 + (tv.tv_usec) / 1000) / 1000.0; 

	mc_dpi_run(state);
	mc_dpi_wait_end(state);
	mc_dpi_terminate(state);

  gettimeofday(&tv, NULL);
  double time_end = ((tv.tv_sec) * 1000 + (tv.tv_usec) / 1000) / 1000.0; 


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

  double time_compute = time_end - time_start;
  printf("Processed: %" PRIu32 " packets in %d seconds. Rate: %f pps\n", total_pkts, time_compute, total_pkts / time_compute);
	return 0;
}


