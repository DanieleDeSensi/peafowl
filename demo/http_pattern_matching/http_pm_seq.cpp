/*
 * http_pm_seq.cpp
 *
 * This demo application loads in memory all the packets contained into a specified
 * .pcap file.
 * After that, it analyzes all the HTTP traffic (reordering the TCP packets to have
 * a well-formed stream), and searches for specific patterns (contained into a file
 * specified by a command line parameter) inside the HTTP body.
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
#include <peafowl/peafowl.h>
#include <peafowl/config.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <ff/ubuffer.hpp>

using namespace antivirus;
#define CAPACITY_CHUNK 1000
#define SCANNER_POOL_SIZE 4096


static ff::uSWSR_Ptr_Buffer* scanner_pool;

trie* my_trie;

static void match_found(string::size_type position, trie::value_type const &match) {
  using namespace std;
  cout << "Matched '" << match.second << "' at " << position << endl;
}

void body_cb(const char* app_data, u_int32_t data_length, void** flow_specific_user_data){
  if(*flow_specific_user_data==NULL){
    if(scanner_pool->mc_pop(flow_specific_user_data)==false){
      *flow_specific_user_data=new byte_scanner(*my_trie, match_found);
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

  try {
    if (argc<4){
      cerr << "Usage: " << argv[0] << " virus-signatures-file input-file num_iterations\n";
      exit(EXIT_FAILURE);
    }

    string::size_type trie_depth=DEFAULT_TRIE_MAXIMUM_DEPTH;
    
    char const *virus_signatures_file_name=argv[1];
    char const *input_file_name=argv[2];
    u_int16_t num_iterations=atoi(argv[3]);

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
    my_trie = &t;
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
      if(num_packets==current_capacity){
        unsigned char** tmp = (unsigned char**) realloc(packets, sizeof(unsigned char*)*(current_capacity+CAPACITY_CHUNK));
        if(!tmp){
          fprintf(stderr, "NULL on realloc\n");
          exit(EXIT_FAILURE);
        }
        packets = tmp;
        u_int32_t* tmp2 = (u_int32_t*) realloc(sizes, sizeof(u_int32_t)*(current_capacity+CAPACITY_CHUNK));
        if(!tmp2){
          fprintf(stderr, "NULL on realloc\n");
          exit(EXIT_FAILURE);
        }
        sizes = tmp2;
        current_capacity+=CAPACITY_CHUNK;
        assert(packets);
        assert(sizes);
      }


      if(posix_memalign((void**) &(packets[num_packets]), PFWL_CACHE_LINE_SIZE, sizeof(unsigned char)*(header.caplen))){
        throw std::runtime_error("posix_memalign failure.");
      }
      assert(packets[num_packets]);
      memcpy(packets[num_packets], packet, (header.caplen));
      sizes[num_packets]=(header.caplen);
      ++num_packets;
    }
    std::cout << "Read " << num_packets << " packets." << std::endl;
    pcap_close(handle);



    scanner_pool=new ff::uSWSR_Ptr_Buffer(SCANNER_POOL_SIZE);
    scanner_pool->init();
    for(uint i=0; i<SCANNER_POOL_SIZE; i++){
      scanner_pool->push(new byte_scanner(t, match_found));
    }

    pfwl_state_t* state=pfwl_init();
    pfwl_set_flow_cleaner_callback(state, &flow_cleaner);
    pfwl_protocol_field_add(state, PFWL_FIELDS_HTTP_BODY);

    uint i,j;
    for(j=0; j<num_iterations; j++){
      for(i=0; i<num_packets; i++){
        pfwl_dissection_info_t r = pfwl_dissect_from_L2(state, packets[i], sizes[i], 0, pcap_datalink(handle));
        if(r.protocol_l7 == PFWL_PROTOCOL_HTTP){
          size_t body_length = r.protocol_fields[PFWL_FIELDS_HTTP_BODY].str.len;
          if(body_length){
            const char* body = r.protocol_fields[PFWL_FIELDS_HTTP_BODY].str.s;
            body_cb(body, body_length, r.user_flow_data);
          }
        }
      }
    }

    byte_scanner* bs;
    while(!scanner_pool->empty()){
      scanner_pool->pop((void**) &bs);
      delete bs;
    }
    /* And close the session */
    pfwl_terminate(state);
    delete scanner_pool;

    full_timer.stop();

    cout << "Completion time: "
         <<	setiosflags(ios_base::fixed) << setprecision(3)
         << full_timer.real_time() << " seconds.\n";

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
