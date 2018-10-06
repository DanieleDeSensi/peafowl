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

#include <peafowl/peafowl.h>
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

int main(int argc, char** argv){
  if(argc!=2){
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }
  char* pcap_filename=argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  pfwl_state_t* state = pfwl_init();
  pcap_t *handle=pcap_open_offline(pcap_filename, errbuf);

  if(handle==NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
    return (2);
  }

  const u_char* packet;
  struct pcap_pkthdr header;

  pfwl_dissection_info_t r;
  u_int32_t protocols[PFWL_NUM_PROTOCOLS];
  memset(protocols, 0, sizeof(protocols));
  u_int32_t unknown=0;

  while((packet=pcap_next(handle, &header))!=NULL){
    r = pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), pcap_datalink(handle));

    if(r.protocol_l4 == IPPROTO_TCP ||
       r.protocol_l4 == IPPROTO_UDP){
      if(r.protocol_l7 < PFWL_NUM_PROTOCOLS){
        ++protocols[r.protocol_l7];
      }else{
        ++unknown;
      }
    }else{
      ++unknown;
    }
  }

  pfwl_terminate(state);

  if (unknown > 0) printf("Unknown packets: %"PRIu32"\n", unknown);
  for(size_t i = 0; i < PFWL_NUM_PROTOCOLS; i++){
    if(protocols[i] > 0){
      printf("%s packets: %"PRIu32"\n", pfwl_get_protocol_string(i), protocols[i]);
    }
  }
  return 0;
}

