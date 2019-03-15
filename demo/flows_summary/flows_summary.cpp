/*
 * flows_summary.c
 *
 * Given a .pcap file, prints summary information about the contained flows.
 *
 * Created on: 05/01/2019
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

#include <peafowl/peafowl.hpp>
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

static void printHeader(){
  printf("#Id\tThreadId\tAddressSrc\tAddressDst\tPortSrc\tPortDst\t"
         "ProtoL2\tProtoL3\tProtoL4\tProtosL7\t"
         "Packets(DirA|DirB)\tBytes(DirA|DirB)\tPacketsL7(DirA|DirB)\tBytesL7(DirA|DirB)\t"
         "TimestampFirst(DirA|DirB)\tTimestampLast(DirA|DirB)\n");
}

static const char* convertAddress(peafowl::IpAddress address, char* buf, size_t buf_size){
  if(address.isIPv4()){
    struct in_addr a;
    a.s_addr = address.getIPv4();
    return inet_ntop(AF_INET, (void*) &a, buf, buf_size);
  }else{
    struct in6_addr tmp = address.getIPv6();
    return inet_ntop(AF_INET6, (void*) &tmp, buf, buf_size);
  }
}

static std::string convertL7Protocols(const peafowl::FlowInfo& info){
  std::string r = "";
  for(auto prot : info.getProtocolsL7()){
    r += peafowl::getL7ProtocolName(prot);
  }
  if(r == ""){
    r = "Unknown";
  }
  return r;
}

static char tmp_srcaddr[64], tmp_dstaddr[64];

class FlowManager: public peafowl::FlowManager{
public:
  void onTermination(const peafowl::FlowInfo& info){
    printf("%" PRIu64 "\t%" PRIu16 "\t%s\t%s\t%" PRIu16 "\t%" PRIu16 "\t"
           "%s\t%s\t%s\t%s\t"
           "%" PRIu64 "|%" PRIu64 "\t%" PRIu64 "|%" PRIu64 "\t%" PRIu64 "|%" PRIu64 "\t%" PRIu64 "|%" PRIu64 "\t"
           "%" PRIu32 "|%" PRIu32 "\t%" PRIu32 "|%" PRIu32 "\n",
           info.getId(),
           info.getThreadId(),
           convertAddress(info.getAddressSrc(), tmp_srcaddr, sizeof(tmp_srcaddr)),
           convertAddress(info.getAddressDst(), tmp_dstaddr, sizeof(tmp_dstaddr)),
           ntohs(info.getPortSrc()),
           ntohs(info.getPortDst()),
           peafowl::getL2ProtocolName(info.getProtocolL2()).c_str(),
           peafowl::getL3ProtocolName(info.getProtocolL3()).c_str(),
           peafowl::getL4ProtocolName(info.getProtocolL4()).c_str(),
           convertL7Protocols(info).c_str(),
           info.getNumPackets(PFWL_DIRECTION_OUTBOUND),     info.getNumPackets(PFWL_DIRECTION_INBOUND),
           info.getNumBytes(PFWL_DIRECTION_OUTBOUND),       info.getNumBytes(PFWL_DIRECTION_INBOUND),
           info.getNumPacketsL7(PFWL_DIRECTION_OUTBOUND),   info.getNumPacketsL7(PFWL_DIRECTION_INBOUND),
           info.getNumBytesL7(PFWL_DIRECTION_OUTBOUND),     info.getNumBytesL7(PFWL_DIRECTION_INBOUND),
           info.getTimestampFirst(PFWL_DIRECTION_OUTBOUND), info.getTimestampFirst(PFWL_DIRECTION_INBOUND),
           info.getTimestampLast(PFWL_DIRECTION_OUTBOUND),  info.getTimestampLast(PFWL_DIRECTION_INBOUND)
           );
  }
};

int main(int argc, char** argv){
  if(argc != 2){
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }
  char* pcap_filename = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  const u_char* packet;
  uint32_t protocols[PFWL_PROTO_L7_NUM];
  struct pcap_pkthdr header;
  memset(protocols, 0, sizeof(protocols));
  uint32_t unknown = 0;

  pcap_t *handle = pcap_open_offline(pcap_filename, errbuf);
  if(handle == NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
    return (2);
  }

  peafowl::Peafowl* pfwl = new peafowl::Peafowl();
  FlowManager fm;
  pfwl->setFlowManager(&fm);
  printHeader();
  peafowl::DissectionInfo r;
  peafowl::ProtocolL2 dlt = peafowl::convertPcapDlt(pcap_datalink(handle));
  while((packet = pcap_next(handle, &header)) != NULL){
    if(pfwl->dissectFromL2(packet, header.caplen, time(NULL), dlt, r) >= PFWL_STATUS_OK){
      if(r.l4.getProtocol() == IPPROTO_TCP || r.l4.getProtocol() == IPPROTO_UDP){
        if(r.l7.getProtocol() < PFWL_PROTO_L7_NUM){
          ++protocols[r.l7.getProtocol()];
        }else{
          ++unknown;
        }
      }else{
        ++unknown;
      }
    }
  }
  delete pfwl;

  if (unknown > 0) printf("Unknown packets: %" PRIu32 "\n", unknown);
  for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
    if(protocols[i] > 0){
      printf("%s packets: %" PRIu32 "\n", peafowl::getL7ProtocolName((peafowl::ProtocolL7) i).c_str(), protocols[i]);
    }
  }
  return 0;
}
