#include "common.h"

Pcap::Pcap(const char* pcapName):_handle(NULL), _datalink_type(PFWL_PROTO_L2_NUM){
  char errbuf[PCAP_ERRBUF_SIZE];
  _handle = pcap_open_offline(pcapName, errbuf);

  if(_handle==NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n", pcapName, errbuf);
    exit(-1);
  }

  _datalink_type = pfwl_convert_pcap_dlt(pcap_datalink(_handle));
}

Pcap::~Pcap(){
  pcap_close(_handle);
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

void getProtocols(const char* pcapName, std::vector<uint>& protocols, pfwl_state_t* state, std::function< void(pfwl_status_t, pfwl_dissection_info_t) > lambda){
  bool terminate = false;
  if(!state){
    state = pfwl_init();
    terminate = true;
  }
  protocols.clear();
  protocols.resize(PFWL_PROTO_L7_NUM);

  Pcap pcap(pcapName);
  pfwl_dissection_info_t r;
  std::pair<const u_char*, unsigned long> pkt;

  while((pkt = pcap.getNextPacket()).first != NULL){
    pfwl_status_t status = pfwl_dissect_from_L2(state, pkt.first, pkt.second, time(NULL), pcap._datalink_type, &r);
    lambda(status, r);
    if(r.l4.protocol == IPPROTO_TCP || r.l4.protocol == IPPROTO_UDP){
      for(size_t i = 0; i < r.l7.protocols_num; i++){
        pfwl_protocol_l7_t proto = r.l7.protocols[i];
        if(proto < PFWL_PROTO_L7_NUM){
          ++protocols[proto];
        }
      }
    }
  }

  if(terminate){
    pfwl_terminate(state);
  }
}

void getProtocolsCpp(const char* pcapName, std::vector<uint>& protocols, peafowl::Peafowl* state, std::function< void(peafowl::Status, peafowl::DissectionInfo&) > lambda){
  bool terminate = false;
  if(!state){
    state = new peafowl::Peafowl();
    terminate = true;
  }
  protocols.clear();
  protocols.resize(PFWL_PROTO_L7_NUM);

  Pcap pcap(pcapName);
  peafowl::DissectionInfo r;
  std::pair<const u_char*, unsigned long> pkt;

  while((pkt = pcap.getNextPacket()).first != NULL){
    r = state->dissectFromL2(pkt.first, pkt.second, time(NULL), pcap._datalink_type);
    lambda(r.status, r);
    if(r.l4.getProtocol() == IPPROTO_TCP || r.l4.getProtocol() == IPPROTO_UDP){
      for(auto proto : r.l7.getProtocols()){
        if(proto < PFWL_PROTO_L7_NUM){
          ++protocols[proto];
        }
      }
    }
  }

  if(terminate){
    delete state;
  }
}
