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

std::vector<pfwl_identification_result_t> getProtocols(const char* pcapName,
                  std::vector<uint>& protocols){
    return getProtocolsWithState(pcapName,
                          protocols,
                          pfwl_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS));
}

std::vector<pfwl_identification_result_t> getProtocolsWithState(const char* pcapName,
                           std::vector<uint>& protocols,
                           pfwl_library_state_t* state){
    std::vector<pfwl_identification_result_t> results;
    protocols.clear();
    protocols.resize(PFWL_NUM_PROTOCOLS + 1); // +1 to store unknown protocols

    Pcap pcap(pcapName);

    pfwl_identification_result_t r;
    std::pair<const u_char*, unsigned long> pkt;

    while((pkt = pcap.getNextPacket()).first != NULL){
        r = pfwl_get_protocol(state, pkt.first, pkt.second, time(NULL));
        results.push_back(r);
        if(r.protocol_l4 == IPPROTO_TCP ||
           r.protocol_l4 == IPPROTO_UDP){
            if(r.protocol_l7 > PFWL_NUM_PROTOCOLS){r.protocol_l7 = PFWL_NUM_PROTOCOLS;}
            ++protocols[r.protocol_l7];
        }
    }

    pfwl_terminate(state);
    return results;
}
