#ifndef PEAFOWL_TEST_COMMON
#define PEAFOWL_TEST_COMMON

#include <peafowl/peafowl.h>
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

class Pcap{
private:
    pcap_t* _handle;
public:
    pfwl_protocol_l2_t _datalink_type;
    Pcap(const char* pcapName);

    std::pair<const u_char*, unsigned long> getNextPacket();
};

void getProtocols(const char* pcapName, std::vector<uint>& protocols, pfwl_state_t* state = NULL, std::function< void(pfwl_dissection_info_t) > lambda = [](pfwl_dissection_info_t){});

#endif // PEAFOWL_TEST_COMMON
