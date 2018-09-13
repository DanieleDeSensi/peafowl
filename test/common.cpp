#include "common.h"

Pcap::Pcap(const char* pcapName):_handle(NULL), _ip_offset(0), _datalink_type(0){
    char errbuf[PCAP_ERRBUF_SIZE];
    _handle = pcap_open_offline(pcapName, errbuf);

    if(_handle==NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", pcapName, errbuf);
        exit(-1);
    }

    _datalink_type=pcap_datalink(_handle);
    _ip_offset=0;
    if(_datalink_type==DLT_EN10MB){
        _ip_offset=sizeof(struct ether_header);
    }else if(_datalink_type==DLT_RAW){
        _ip_offset=0;
    }else if(_datalink_type==DLT_LINUX_SLL){
        _ip_offset=16;
    }else{
        fprintf(stderr, "Datalink type not supported\n");
        exit(-1);
    }
}

std::pair<const u_char*, unsigned long> Pcap::getNextPacket(){
    std::pair<const u_char*, unsigned long> r;
    struct pcap_pkthdr header;

    while(true){
        const u_char* packet=pcap_next(_handle, &header);
        if(!packet){
            r.first = NULL;
            r.second = 0;
            return r;
        }
        uint16_t virtual_offset = 0;

        if(_datalink_type == DLT_EN10MB){
            if(header.caplen < _ip_offset){
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
        r.first = packet+_ip_offset+virtual_offset;
        r.second = header.caplen-_ip_offset-virtual_offset;
        return r;
    }
}

void getProtocolsOld(const char* pcapName,
                  std::vector<uint>& tcpProtocols,
                  std::vector<uint>& udpProtocols){
    tcpProtocols.clear();
    udpProtocols.clear();
    tcpProtocols.resize(DPI_NUM_TCP_PROTOCOLS + 1); // +1 to store unknown protocols
    udpProtocols.resize(DPI_NUM_UDP_PROTOCOLS + 1); // +1 to store unknown protocols
    Pcap pcap(pcapName);

    dpi_identification_result_t r;
    std::pair<const u_char*, unsigned long> pkt;
    dpi_library_state_t* state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);

    while((pkt = pcap.getNextPacket()).first != NULL){
        r = dpi_stateful_identify_application_protocol(state, pkt.first, pkt.second, time(NULL));
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

std::vector<dpi_identification_result_t> getProtocols(const char* pcapName,
                  std::vector<uint>& protocols){
    return getProtocolsWithState(pcapName,
                          protocols,
                          dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS));
}

std::vector<dpi_identification_result_t> getProtocolsWithState(const char* pcapName,
                           std::vector<uint>& protocols,
                           dpi_library_state_t* state){
    std::vector<dpi_identification_result_t> results;
    protocols.clear();
    protocols.resize(DPI_NUM_PROTOCOLS + 1); // +1 to store unknown protocols

    Pcap pcap(pcapName);

    dpi_identification_result_t r;
    std::pair<const u_char*, unsigned long> pkt;

    while((pkt = pcap.getNextPacket()).first != NULL){
        r = dpi_get_protocol(state, pkt.first, pkt.second, time(NULL));
        results.push_back(r);
        if(r.protocol.l4prot == IPPROTO_TCP ||
           r.protocol.l4prot == IPPROTO_UDP){
            if(r.protocol.l7prot > DPI_NUM_PROTOCOLS){r.protocol.l7prot = DPI_NUM_PROTOCOLS;}
            ++protocols[r.protocol.l7prot];
        }
    }

    dpi_terminate(state);
    return results;
}
