/**
 *  Test for SSL protocol.
 **/
#include "common.h"

TEST(SSLTest, Generic) {
  std::vector<uint> protocols;
  getProtocols("./pcaps/ssl.pcapng", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 840);
  getProtocols("./pcaps/6in4tunnel.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 55);
  getProtocols("./pcaps/dropbox.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 224);
  getProtocols("./pcaps/spotify.pcapng", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 11);
  getProtocols("./pcaps/ssl-2.cap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 52);
  getProtocols("./pcaps/ssl-3.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 20);
  getProtocols("./pcaps/ssl-4.pcap", protocols); // Short flows and we do not see syn. We detect only if we disable TCP reordering.
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 0);
  pfwl_state_t* state = pfwl_init();
  pfwl_tcp_reordering_disable(state);
  getProtocols("./pcaps/ssl-4.pcap", protocols, state); // Short flows and we do not see syn. We detect only if we disable TCP reordering.
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 5);
  pfwl_terminate(state);
}

TEST(SSLTest, ServerName) {
  std::vector<uint> protocols;
  pfwl_state_t* state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_CERTIFICATE);

  // Test 1
  bool serverNameFound = false;
  getProtocols("./pcaps/ssl-2.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    pfwl_string_t field;
    if(status >= PFWL_STATUS_OK &&
       r.l7.protocol == PFWL_PROTO_L7_SSL &&
       !pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_CERTIFICATE, &field)){
      EXPECT_EQ(strncmp((const char*) field.value, "www.snakeoil.dom", field.length), 0);
      serverNameFound = true;
    }
  });
  EXPECT_TRUE(serverNameFound);

  // Test 2
  serverNameFound = false;
  getProtocols("./pcaps/ssl-3.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    pfwl_string_t field;
    if(status >= PFWL_STATUS_OK &&
       r.l7.protocol == PFWL_PROTO_L7_SSL &&
       !pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_CERTIFICATE, &field)){
      EXPECT_EQ(strncmp((const char*) field.value, "*.google.com", field.length), 0);
      serverNameFound = true;
    }
  });
  EXPECT_TRUE(serverNameFound);

  // Test 3
  pfwl_tcp_reordering_disable(state);
  bool clientNameFound = false;
  serverNameFound = false;
  getProtocols("./pcaps/ssl-4.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    pfwl_string_t field;
    if(status >= PFWL_STATUS_OK &&
       r.l7.protocol == PFWL_PROTO_L7_SSL){

      if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_CERTIFICATE, &field)){
        EXPECT_EQ(strncmp((const char*) field.value, "BAWMASHBIJ.corp.smsc.com", field.length), 0);
        serverNameFound = true;
      }

      if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_SNI, &field)){
        EXPECT_EQ(strncmp((const char*) field.value, "bawmashbij", field.length), 0);
        clientNameFound = true;
      }
    }
  });
  EXPECT_TRUE(serverNameFound);
  EXPECT_TRUE(clientNameFound);
  pfwl_tcp_reordering_enable(state);

  pfwl_terminate(state);
}

TEST(SSLTest, Tags) {
  pfwl_state_t* state = pfwl_init();
  pfwl_field_string_tags_add_L7(state, PFWL_FIELDS_L7_SSL_CERTIFICATE, "snakeoil.dom", PFWL_FIELD_MATCHING_SUFFIX, "TAG_SUFFIX");

  std::vector<uint> protocols;
  bool foundSni = false;
  getProtocols("./pcaps/ssl-2.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){

    for(size_t i = 0; i < r.l7.tags_num; i++){
      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_SUFFIX")){
        foundSni = true;
      }
    }
  });
  EXPECT_TRUE(foundSni);
  pfwl_terminate(state);
}
