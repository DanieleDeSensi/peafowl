/**
 *  Test for HTTP protocol.
 **/
#include "../src/api.h"
#include "gtest/gtest.h"
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

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

void getProtocols(const char* pcapName,
                  std::vector<uint>& tcpProtocols,
                  std::vector<uint>& udpProtocols,
                  uint& unknown){
    tcpProtocols.clear();
    udpProtocols.clear();
    tcpProtocols.resize(DPI_NUM_TCP_PROTOCOLS + 1); // +1 to store unknown protocols
    udpProtocols.resize(DPI_NUM_UDP_PROTOCOLS + 1); // +1 to store unknown protocols

    char errbuf[PCAP_ERRBUF_SIZE];
    dpi_library_state_t* state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
    pcap_t *handle = pcap_open_offline(pcapName, errbuf);

    if(handle==NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", pcapName, errbuf);
        exit(-1);
    }

    int datalink_type=pcap_datalink(handle);
    uint ip_offset=0;
    if(datalink_type==DLT_EN10MB){
        ip_offset=sizeof(struct ether_header);
    }else if(datalink_type==DLT_RAW){
        ip_offset=0;
    }else if(datalink_type==DLT_LINUX_SLL){
        ip_offset=16;
    }else{
        fprintf(stderr, "Datalink type not supported\n");
        exit(-1);
    }

    const u_char* packet;
    struct pcap_pkthdr header;
    dpi_identification_result_t r;

    while((packet=pcap_next(handle, &header))!=NULL){
        if(header.len<ip_offset) continue;
        uint virtual_offset = 0;
        if(((struct ether_header*) packet)->ether_type == htons(0x8100)){
            virtual_offset = 4;
        }
        r=dpi_stateful_identify_application_protocol(state, packet+ip_offset+virtual_offset, header.len-ip_offset, time(NULL));

        dpi_l7_prot_id proto = r.protocol.l7prot;
        if(r.protocol.l4prot == IPPROTO_TCP){
            if(proto > DPI_NUM_TCP_PROTOCOLS){proto = DPI_NUM_TCP_PROTOCOLS;}
            ++tcpProtocols[proto];
        }else if(r.protocol.l4prot == IPPROTO_UDP){
            if(proto > DPI_NUM_UDP_PROTOCOLS){proto = DPI_NUM_UDP_PROTOCOLS;}
            ++udpProtocols[proto];
        }
    }

    dpi_terminate(state);
}

TEST(HTTPTest, Generic) {
    std::vector<uint> tcpProtocols;
    std::vector<uint> udpProtocols;
    uint unknown;
    getProtocols("./pcaps/http.cap", tcpProtocols, udpProtocols, unknown);
    EXPECT_EQ(tcpProtocols[DPI_PROTOCOL_TCP_HTTP], 35);
}
