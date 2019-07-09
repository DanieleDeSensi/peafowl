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

pcap_pkt_t Pcap::getNextPacket(){
  pcap_pkt_t r;
  struct pcap_pkthdr header;

  while(true){
    const u_char* packet = pcap_next(_handle, &header);
    if(!packet){
      r.pkt = NULL;
      r.caplen = 0;
      r.ts = 0;
      return r;
    }
    r.caplen = header.caplen;
    r.pkt = packet;
    r.ts = header.ts.tv_sec * 1000.0 * 1000.0 + header.ts.tv_usec;
    return r;
  }
}

void getProtocols(const char* pcapName, std::vector<uint>& protocols, pfwl_state_t* state, std::function< void(pfwl_status_t, pfwl_dissection_info_t) > lambda, bool pcap_ts){
  bool terminate = false;
  if(!state){
    state = pfwl_init();
    terminate = true;
  }
  protocols.clear();
  protocols.resize(PFWL_PROTO_L7_NUM);

  Pcap pcap(pcapName);
  pfwl_dissection_info_t r;
  pcap_pkt_t pkt;

  while((pkt = pcap.getNextPacket()).pkt != NULL){
    uint timestamp;
    if(pcap_ts){
      timestamp = pkt.ts;
    }else{
      timestamp = time(NULL);
    }
    pfwl_status_t status = pfwl_dissect_from_L2(state, pkt.pkt, pkt.caplen, timestamp, pcap._datalink_type, &r);
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

void getProtocolsCpp(const char* pcapName, std::vector<uint>& protocols, peafowl::Peafowl* state, std::function< void(peafowl::Status, peafowl::DissectionInfo&) > lambda, bool pcap_ts){
  bool terminate = false;
  if(!state){
    state = new peafowl::Peafowl();
    terminate = true;
  }
  protocols.clear();
  protocols.resize(PFWL_PROTO_L7_NUM);

  Pcap pcap(pcapName);
  pcap_pkt_t pkt;

  while((pkt = pcap.getNextPacket()).pkt != NULL){
    std::string s;
    s.assign((const char*) pkt.pkt, pkt.caplen);
    uint timestamp;
    if(pcap_ts){
      timestamp = pkt.ts;
    }else{
      timestamp = time(NULL);
    }
    peafowl::DissectionInfo r = state->dissectFromL2(s, timestamp, pcap._datalink_type);
    lambda(r.getStatus(), r);
    if(r.getL4().getProtocol() == IPPROTO_TCP || 
       r.getL4().getProtocol() == IPPROTO_UDP){
      for(auto proto : r.getL7().getProtocols()){
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
