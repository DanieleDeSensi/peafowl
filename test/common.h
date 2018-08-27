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
    uint _ip_offset;
    int _datalink_type;
public:
    Pcap(const char* pcapName);

    std::pair<const u_char*, unsigned long> getNextPacket();
};


void getProtocolsOld(const char* pcapName,
                  std::vector<uint>& tcpProtocols,
                  std::vector<uint>& udpProtocols);

void getProtocols(const char* pcapName,
                  std::vector<uint>& protocols);

#endif // PEAFOWL_TEST_COMMON
