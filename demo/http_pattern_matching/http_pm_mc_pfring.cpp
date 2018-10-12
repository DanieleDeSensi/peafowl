/*
 * http_pm_mc_pfring.cpp
 *
 * This demo application analyzes the HTTP traffic (reordering the TCP packets to have
 * a well-formed stream), and searches for specific patterns (contained into a file 
 * specified by a command line parameter) inside the HTTP body.
 * The traffic is captured by using PF_RING (low latency network capture mechanism).
 *
 * Over high bandwidth networks, getting the timestamp for each received packet
 * could have a very negative impact over the bandwidth of the application. In order 
 * to have low latency timestamping, in this example we perform it by reading the
 * CPU clock. To correctly perform this kind of timestamping the macro 
 * CLOCK_FREQ must be set with the correct CPU frequency (in Hz) and the
 * 'cpu-freq' tool should be used to set the CPU frequency manager to 'performance'.
 *
 * For low bandwidth networks this is not really needed and time(NULL) or gettimeofday
 * can be used for timestamping.
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
#include <peafowl/peafowl_mc.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <ff/mapping_utils.hpp>
#include <ff/utils.hpp>
#include <ff/ubuffer.hpp>


// #define USE_PF_RING_CLUSTER  1

#define ALARM_SLEEP 10 //Interval (seconds) between two successive stats print

#include <time.h>
#include <signal.h>
extern "C" {
#include <pfring.h>
}

using namespace antivirus;
#define CAPACITY_CHUNK 1000
#define SCANNER_POOL_SIZE 8192  //4096
#define CLOCK_FREQ 2000000000L
#define TEST_DURATION_SECS 120

#define SNAPLEN 2000

#define AVAILABLE_CORES 16
static u_int16_t mapping[AVAILABLE_CORES]=
  {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

static struct timeval startTime;
u_int64_t numPkts = 0, numBytes = 0;
pfring *ring;
ff::SWSR_Ptr_Buffer *pkt_buff;
int verbose = 0;
unsigned long num_pkt_buffers = 128000;
//unsigned long num_pkt_buffers = 32000;


static ff::uSWSR_Ptr_Buffer* scanner_pool;

mc_pfwl_packet_reading_result_t reading_cb(void* user_data){
	static unsigned long last_ts=getticks();
	static u_int32_t last_sec=0;
#ifdef USE_PF_RING_CLUSTER
	pfring_pkt_buff *pkt_handle = NULL;
#else
	void *pkt_handle;
#endif
	struct pfring_pkthdr hdr;


	if(numPkts == 0) gettimeofday(&startTime, NULL);

	while(pkt_buff->empty()){;}
	/**
	if(pkt_buff->empty()) {
		printf("Not enough buffer available: please start over\n");
		exit(-1);
	}
	**/

	pkt_buff->pop(&pkt_handle);

	if(verbose) printf("pkt_buff->pop()\n");

	while(1) {
        int rc;
#ifdef USE_PF_RING_CLUSTER
		rc = pfring_recv_pkt_buff(ring, pkt_handle, &hdr, 1);
#else
		rc = pfring_recv(ring, (u_char**)&pkt_handle, SNAPLEN, &hdr, 1);
#endif

		if(rc < 0) {
			printf("pfring_recv_pkt_buff() returned %d\n", rc);
			exit(-1);
		} else if(rc == 0) {
			continue;
		} else {
			mc_pfwl_packet_reading_result_t r;
			const unsigned char *p = (const unsigned char*)pkt_handle;

			r.pkt = &p[14];

			if(getticks()-last_ts>CLOCK_FREQ){
				last_ts = getticks();
				++last_sec;
			}
			r.current_time=last_sec;
			r.length=hdr.caplen-14;
			r.user_pointer=pkt_handle;

			numPkts++, numBytes += r.length; // hdr.len;
			return r;
		}
	} /* while */
}


void processing_cb(mc_pfwl_processing_result_t* processing_result, void* user_data){
	pkt_buff->push((void*)processing_result->user_pointer);
	if(verbose) printf("pkt_buff->push()\n");
}


static void match_found(string::size_type position,
		trie::value_type const &match){
	using namespace std;
	cout << "Matched '" << match.second << "' at " << position << endl;
}

void body_cb(pfwl_http_message_informations_t* http_informations,
		const u_char* app_data, u_int32_t data_length,
		pfwl_pkt_info_t* pkt,
		void** flow_specific_user_data, void* user_data,
		u_int8_t last){
  
	if(*flow_specific_user_data==NULL){

		if(scanner_pool->mc_pop(flow_specific_user_data)==false){
			*flow_specific_user_data=
                    new byte_scanner(*(static_cast<trie*>(user_data)), match_found);
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

/*
 * The time difference in millisecond
 */
double delta_time (struct timeval * now,
		struct timeval * before) {
	time_t delta_seconds;
	time_t delta_microseconds;

	/*
	 * compute delta in second, 1/10's and 1/1000's second units
	 */
	delta_seconds      = now -> tv_sec  - before -> tv_sec;
	delta_microseconds = now -> tv_usec - before -> tv_usec;

	if(delta_microseconds < 0) {
		/* manually carry a one from the seconds field */
		delta_microseconds += 1000000;  /* 1e6 */
		-- delta_seconds;
	}
	return((double)(delta_seconds * 1000) + (double)delta_microseconds/1000);
}

void print_stats() {
	pfring_stat pfringStat;
	struct timeval endTime;
    double deltaMillisecSinceStart;
	static u_int64_t lastPkts = 0;
	static u_int64_t lastBytes = 0;
	u_int64_t diffPkts, diffBytes;
	static struct timeval lastTime;

	if(startTime.tv_sec == 0) return;

	gettimeofday(&endTime, NULL);

	if(pfring_stats(ring, &pfringStat) >= 0){
		fprintf(stderr, 
				"Absolute Stats: [%lu pkts rcvd][%lu pkts dropped]\n"
				"Total Pkts=%lu/Dropped=%.1f %%\n",
				(unsigned long)pfringStat.recv, (unsigned long)pfringStat.drop,
				(unsigned long)(pfringStat.recv),
			pfringStat.recv == 0 ? 0 : (double)(pfringStat.drop*100)/(double)(pfringStat.recv+pfringStat.drop));
	}

	if(lastTime.tv_sec > 0) {
        double deltaMillisecInterval;
        deltaMillisecSinceStart = delta_time(&endTime, &startTime);
		deltaMillisecInterval = delta_time(&endTime, &lastTime);
		diffPkts = numPkts-lastPkts;
		diffBytes = numBytes-lastBytes;

                fprintf(stderr, "==================Average=====================\n"
			"[%.1f pkt/sec][%.2f Gbit/sec]\n",
			((double)(numPkts*1000)/(double)(deltaMillisecSinceStart)),
			(double)8*numBytes/(double)(deltaMillisecSinceStart*1000000));

		fprintf(stderr, "==================Current=====================\n"
		                "[%.1f pkt/sec][%.2f Gbit/sec]\n",
         			((double)(diffPkts*1000)/(double)(deltaMillisecInterval)),
                         	(double)8*diffBytes/(double)(deltaMillisecInterval*1000000));
	}

	lastPkts = numPkts;
	lastBytes = numBytes;

	lastTime.tv_sec = endTime.tv_sec, lastTime.tv_usec = endTime.tv_usec;

	fprintf(stderr, "==============================================\n");
	if(deltaMillisecSinceStart/1000 > TEST_DURATION_SECS){
	  exit(-1);
	}
}

/* ******************************** */

void sigproc(int sig) {
	static int called = 0;

	if(called) return; else called = 1;

	print_stats();
	pfring_close(ring);
	exit(0);
}

void my_sigalarm(int sig) {
	print_stats();
	printf("\n");
	alarm(ALARM_SLEEP);
	signal(SIGALRM, my_sigalarm);
}

int main(int argc, char **argv){
	using namespace std;
	ff_mapThreadToCpu(mapping[0], -20);

	try {
		if (argc<4){
			cerr << "Usage: " << argv[0] <<
					" virus-signatures-file device "
					"availableCores\n";
			exit(EXIT_FAILURE);
		}

		string::size_type trie_depth=DEFAULT_TRIE_MAXIMUM_DEPTH;

		char const *virus_signatures_file_name=argv[1];
		char const *device=argv[2];
		u_int16_t num_workers=atoi(argv[3]);


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
		full_timer.start();
		/******************************************************/
		/*             Start scanning the files.              */
		/******************************************************/

		mc_pfwl_parallelism_details_t details;
		bzero(&details, sizeof(mc_pfwl_parallelism_details_t));
		details.available_processors=num_workers;
		details.mapping=mapping;

		mc_pfwl_state_t* state=mc_pfwl_init_stateful(
				32767, 32767, 1000000, 1000000, details);

		int snaplen = SNAPLEN;
		int flags = PF_RING_PROMISC;

		ring = pfring_open(device, snaplen, flags);

		if(ring==NULL){
			fprintf(stderr, "Couldn't open device %s\n", device);
			return (2);
		}

		pfring_set_direction(ring, rx_only_direction);
		scanner_pool=new ff::uSWSR_Ptr_Buffer(SCANNER_POOL_SIZE, true);
		scanner_pool->init();
		for(uint i=0; i<SCANNER_POOL_SIZE; i++){
			scanner_pool->push(new byte_scanner(t, match_found));
		}
		//		mc_pfwl_tcp_reordering_disable(state);
        mc_pfwl_set_core_callbacks(
				state, &reading_cb, &processing_cb, (void*) NULL);
		mc_pfwl_set_flow_cleaner_callback(state, &flow_cleaner);
		pfwl_http_callbacks_t callback={0, 0, 0, 0, 0, &body_cb};
				assert(mc_pfwl_http_activate_callbacks(state, &callback, (void*)(&t))==1);


		pkt_buff = new ff::SWSR_Ptr_Buffer(num_pkt_buffers);
		if(pkt_buff == NULL) {
			printf("SWSR_Ptr_Buffer() failed\n");
			return(-1);
		}
		pkt_buff->init();

		for(int i=0; i<num_pkt_buffers; i++) {
#ifdef USE_PF_RING_CLUSTER
			pfring_pkt_buff *pkt_handle;

			if((pkt_handle = pfring_alloc_pkt_buff(ring)) == NULL) {
				printf("Error allocating pkt buff\n");
				return(-1);
			} else
				pkt_buff->push(pkt_handle);
#else
			pkt_buff->push(malloc(SNAPLEN));
			if(verbose) printf("pkt_buff->push() empty buffer\n");
#endif
		}

		signal(SIGINT, sigproc);
		signal(SIGALRM, my_sigalarm);
		alarm(ALARM_SLEEP);

		pfring_enable_ring(ring);

		timer scan_timer;
		scan_timer.start();
		mc_pfwl_run(state);


		mc_pfwl_wait_end(state);
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

		cout << "Completion time: "
				<<	setiosflags(ios_base::fixed) << setprecision(3)
				<< full_timer.real_time() << " seconds.\n";

		u_int32_t i;
		exit(EXIT_SUCCESS);
	}catch(exception const &ex){
		cout.flush();
		cerr << typeid(ex).name() << " exception: " << ex.what() << "\n";
		throw;
	}
}
