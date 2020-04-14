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
    r += prot.getName();
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
           "%.0f|%.0f\t%.0f|%.0f\t%.0f|%.0f\t%.0f|%.0f\t"
           "%.0f|%.0f\t%.0f|%.0f\n",
           info.getId(),
           info.getThreadId(),
           convertAddress(info.getAddressSrc(), tmp_srcaddr, sizeof(tmp_srcaddr)),
           convertAddress(info.getAddressDst(), tmp_dstaddr, sizeof(tmp_dstaddr)),
           ntohs(info.getPortSrc()),
           ntohs(info.getPortDst()),
           info.getProtocolL2().getName().c_str(),
           info.getProtocolL3().getName().c_str(),
           info.getProtocolL4().getName().c_str(),
           convertL7Protocols(info).c_str(),
           info.getStatistic(PFWL_STAT_PACKETS, PFWL_DIRECTION_OUTBOUND)        , info.getStatistic(PFWL_STAT_PACKETS, PFWL_DIRECTION_INBOUND),
           info.getStatistic(PFWL_STAT_BYTES, PFWL_DIRECTION_OUTBOUND)          , info.getStatistic(PFWL_STAT_BYTES, PFWL_DIRECTION_INBOUND),
           info.getStatistic(PFWL_STAT_L7_PACKETS, PFWL_DIRECTION_OUTBOUND)     , info.getStatistic(PFWL_STAT_L7_PACKETS, PFWL_DIRECTION_INBOUND),
           info.getStatistic(PFWL_STAT_L7_BYTES, PFWL_DIRECTION_OUTBOUND)       , info.getStatistic(PFWL_STAT_L7_BYTES, PFWL_DIRECTION_INBOUND),
           info.getStatistic(PFWL_STAT_TIMESTAMP_FIRST, PFWL_DIRECTION_OUTBOUND), info.getStatistic(PFWL_STAT_TIMESTAMP_FIRST, PFWL_DIRECTION_INBOUND),
           info.getStatistic(PFWL_STAT_TIMESTAMP_LAST, PFWL_DIRECTION_OUTBOUND) , info.getStatistic(PFWL_STAT_TIMESTAMP_LAST, PFWL_DIRECTION_INBOUND)
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
  peafowl::ProtocolL2 dlt = peafowl::convertPcapDlt(pcap_datalink(handle));
  while((packet = pcap_next(handle, &header)) != NULL){
    std::string pkt;
    pkt.assign((const char*) packet, header.caplen);
    peafowl::DissectionInfo r = pfwl->dissectFromL2(pkt, header.ts.tv_sec, dlt);
    if(!r.getStatus().isError()){
      if(r.getL4().getProtocol() == IPPROTO_TCP ||
         r.getL4().getProtocol() == IPPROTO_UDP){
        if(r.getL7().getProtocol() < PFWL_PROTO_L7_NUM){
          ++protocols[r.getL7().getProtocol()];
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
      printf("%s packets: %" PRIu32 "\n", peafowl::ProtocolL7((pfwl_protocol_l7_t) i).getName().c_str(), protocols[i]);
    }
  }
  return 0;
}
