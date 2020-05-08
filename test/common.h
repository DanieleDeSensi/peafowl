#ifndef PEAFOWL_TEST_COMMON
#define PEAFOWL_TEST_COMMON

#include <peafowl/peafowl.h>
#include <peafowl/peafowl.hpp>
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

typedef struct{
	const u_char* pkt;
	unsigned long caplen;
	double ts;
}pcap_pkt_t;

class Pcap{
private:
    pcap_t* _handle;
public:
    pfwl_protocol_l2_t _datalink_type;
    Pcap(const char* pcapName);
    ~Pcap();

    pcap_pkt_t getNextPacket();
};

void getProtocols(const char* pcapName, std::vector<uint>& protocols, pfwl_state_t* state = NULL, std::function< void(pfwl_status_t, pfwl_dissection_info_t) > lambda = [](pfwl_status_t, pfwl_dissection_info_t){}, bool pcap_ts = false);
void getProtocolsCpp(const char* pcapName, std::vector<uint>& protocols, peafowl::Peafowl* state = NULL, std::function< void(peafowl::Status, peafowl::DissectionInfo&) > lambda = [](peafowl::Status, peafowl::DissectionInfo&){}, bool pcap_ts = false);

#endif // PEAFOWL_TEST_COMMON
