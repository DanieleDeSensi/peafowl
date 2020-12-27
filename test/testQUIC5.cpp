/**
 *  Test for QUIC protocol.
 **/
#include "common.h"

#ifdef HAVE_OPENSSL
TEST(QUICTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/quic-050.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC5], (uint) 65);
    getProtocols("./pcaps/quic-t51.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC5], (uint) 642);
    getProtocols("./pcaps/quic-draft29.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC5], (uint) 9);
    getProtocols("./pcaps/quic-draft27-facebook.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_QUIC5], (uint) 1);
}

static void checkSNI(const char* pcap, const char* sni, pfwl_field_matching_t matchType){
  pfwl_state_t* state = pfwl_init();
  pfwl_field_string_tags_add_L7(state, PFWL_FIELDS_L7_QUIC_SNI, sni, matchType, "TAG");

  std::vector<uint> protocols;
  bool foundSni = false;
  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){

    for(size_t i = 0; i < r.l7.tags_num; i++){
      if(r.l7.protocol == PFWL_PROTO_L7_QUIC5 &&
         r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG")){
        foundSni = true;
      }
    }
  });
  EXPECT_TRUE(foundSni);
  pfwl_terminate(state);
}

TEST(QUICTest, ServerName) {
  checkSNI("./pcaps/quic-050.pcap", "www.google.com", PFWL_FIELD_MATCHING_EXACT);
  checkSNI("./pcaps/quic-t51.pcap", "www.google.com", PFWL_FIELD_MATCHING_EXACT);
  checkSNI("./pcaps/quic-draft29.pcap", "ssl.gstatic.com", PFWL_FIELD_MATCHING_EXACT);
  checkSNI("./pcaps/quic-draft27-facebook.pcap", "scontent-bru2-1.xx.fbcdn.net", PFWL_FIELD_MATCHING_EXACT);
}

static void checkVersion(const char* pcap, const char* expectedVersion){
  pfwl_state_t* state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_VERSION);

  std::vector<uint> protocols;
  bool foundVersion = false;
  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    pfwl_string_t version;
    if(r.l7.protocol == PFWL_PROTO_L7_QUIC5 &&
       !pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, &version) &&
       !strncmp((const char*) version.value, expectedVersion, version.length)){
      foundVersion = true;
    }
  });
  EXPECT_TRUE(foundVersion);
  pfwl_terminate(state);
}

TEST(QUICTest, Version) {
  checkVersion("./pcaps/quic-050.pcap", "Q050");
  checkVersion("./pcaps/quic-t51.pcap", "T051");
  checkVersion("./pcaps/quic-draft29.pcap", "draft-29");
  checkVersion("./pcaps/quic-draft27-facebook.pcap", "facebook mvfst draft-27");
}

static void checkUserAgent(const char* pcap, const char* expectedUAID){
  pfwl_state_t* state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_UAID);

  std::vector<uint> protocols;
  bool foundVersion = false;
  getProtocols(pcap, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    pfwl_string_t uaid;
    if(r.l7.protocol == PFWL_PROTO_L7_QUIC5 &&
       !pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, &uaid) &&
       !strncmp((const char*) uaid.value, expectedUAID, uaid.length)){
      foundVersion = true;
    }
  });
  EXPECT_TRUE(foundVersion);
  pfwl_terminate(state);
}

TEST(QUICTest, Useragent) {
  checkUserAgent("./pcaps/quic-050.pcap", "Chrome/86.0.4240.198 Intel Mac OS X 10_15_7");
  checkUserAgent("./pcaps/quic-t51.pcap", "dev Chrome/86.0.4240.9 Windows NT 6.1; Win64; x64");
  checkUserAgent("./pcaps/quic-draft29.pcap", "Chrome/87.0.4280.88 Intel Mac OS X 10_15_7");
  /* NO UserAgent present in quic-draft27-facebook.pcap so no test for it */
}
#endif