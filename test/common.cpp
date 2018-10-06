#include "common.h"

Pcap::Pcap(const char* pcapName):_handle(NULL), _datalink_type(0){
    char errbuf[PCAP_ERRBUF_SIZE];
    _handle = pcap_open_offline(pcapName, errbuf);

    if(_handle==NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", pcapName, errbuf);
        exit(-1);
    }

    _datalink_type=pcap_datalink(_handle);
}

std::pair<const u_char*, unsigned long> Pcap::getNextPacket(){
    std::pair<const u_char*, unsigned long> r;
    struct pcap_pkthdr header;

    while(true){
        const u_char* packet = pcap_next(_handle, &header);
        if(!packet){
            r.first = NULL;
            r.second = 0;
            return r;
        }
        r.second = header.caplen;
        r.first = packet;
        return r;
    }
}

std::vector<pfwl_dissection_info_t> getProtocols(const char* pcapName, std::vector<uint>& protocols){
    return getProtocolsWithState(pcapName, protocols, pfwl_init());
}

std::vector<pfwl_dissection_info_t> getProtocolsWithState(const char* pcapName, std::vector<uint>& protocols, pfwl_state_t* state){
    std::vector<pfwl_dissection_info_t> results;
    protocols.clear();
    protocols.resize(PFWL_NUM_PROTOCOLS + 1); // +1 to store unknown protocols

    Pcap pcap(pcapName);
    pfwl_dissection_info_t r;
    std::pair<const u_char*, unsigned long> pkt;

    while((pkt = pcap.getNextPacket()).first != NULL){
        r = pfwl_dissect_from_L2(state, pkt.first, pkt.second, time(NULL), pcap._datalink_type);
        // We copy the packet to avoid copying all the extracted fields manually
        // Indeed the fields are valid only for the lifetime of the packet
        // This is only done to simplify the testing process.
        for(size_t i = 0; i < PFWL_FIELDS_NUM; i++){
          if(i == PFWL_FIELDS_HTTP_CONTENT_TYPE ||
             i == PFWL_FIELDS_HTTP_BODY ||
             i == PFWL_FIELDS_SIP_REQUEST_URI ||
             i == PFWL_FIELDS_SIP_METHOD){
            size_t field_len = r.protocol_fields[i].str.len;
            const char* field = r.protocol_fields[i].str.s;
            if(field_len){
              char* tmp = (char*) malloc(sizeof(char) * field_len);
              memcpy((void*) tmp, field, field_len);
              r.protocol_fields[i].str.s = tmp;
            }
          }
        }
        r.user_flow_data = (void**) malloc(sizeof(int*)); // Dirty trick.
        *r.user_flow_data = NULL;

        results.push_back(r);
        if(r.protocol_l4 == IPPROTO_TCP ||
           r.protocol_l4 == IPPROTO_UDP){
            if(r.protocol_l7 > PFWL_NUM_PROTOCOLS){r.protocol_l7 = PFWL_NUM_PROTOCOLS;}
            ++protocols[r.protocol_l7];
        }
    }

    return results;
}
