/**
 *  Test for QUIC protocol.
 **/
#include "common.h"

TEST(QUICTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/quic-024-0.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC], (uint) 413);
    getProtocols("./pcaps/quic-024-1.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC], (uint) 1);
    getProtocols("./pcaps/quic-039.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC], (uint) 1);
    getProtocols("./pcaps/quic-043.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC], (uint) 1);
}

static void checkSNI(const char* pcap, const char* sni, pfwl_field_matching_t matchType){
  pfwl_state_t* state = pfwl_init();
  pfwl_field_string_tags_add_L7(state, PFWL_FIELDS_L7_QUIC_SNI, sni, matchType, "TAG");

  std::vector<uint> protocols;
  bool foundSni = false;
  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){

    for(size_t i = 0; i < r.l7.tags_num; i++){
      if(r.l7.protocol == PFWL_PROTO_L7_QUIC &&
         r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG")){
        foundSni = true;
      }
    }
  });
  EXPECT_TRUE(foundSni);
  pfwl_terminate(state);
}

TEST(QUICTest, Tags) {
  checkSNI("./pcaps/quic-024-0.pcap", "mail.google.com", PFWL_FIELD_MATCHING_EXACT);
  checkSNI("./pcaps/quic-024-0.pcap", "google.com", PFWL_FIELD_MATCHING_SUFFIX);
  checkSNI("./pcaps/quic-024-1.pcap", "google.com", PFWL_FIELD_MATCHING_SUFFIX);
  checkSNI("./pcaps/quic-039.pcap", "ytimg.com", PFWL_FIELD_MATCHING_SUFFIX);
  checkSNI("./pcaps/quic-043.pcap", "googlevideo.com", PFWL_FIELD_MATCHING_SUFFIX);
}

static void checkVersion(const char* pcap, const char* expectedVersion){
  pfwl_state_t* state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_VERSION);

  std::vector<uint> protocols;
  bool foundVersion = false;
  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    pfwl_string_t version;
    if(r.l7.protocol == PFWL_PROTO_L7_QUIC &&
       !pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, &version) &&
       !strncmp((const char*) version.value, expectedVersion, version.length)){
      foundVersion = true;
    }
  });
  EXPECT_TRUE(foundVersion);
  pfwl_terminate(state);
}

TEST(QUICTest, Version) {
  checkVersion("./pcaps/quic-024-0.pcap", "Q024");
  checkVersion("./pcaps/quic-024-1.pcap", "Q024");
  checkVersion("./pcaps/quic-039.pcap"  , "Q039");
  checkVersion("./pcaps/quic-043.pcap"  , "Q043");
}
