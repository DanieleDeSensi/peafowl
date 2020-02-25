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
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SSL], (uint) 13);
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

TEST(SSLTest, JA3){
  std::vector<uint> protocols;
  pfwl_state_t* state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_CIPHER_SUITES);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_EXTENSIONS);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SSL_JA3);

  bool versionFound = false, ciphersFound = false, extensionsFound = false, 
       curvesFound = false, curvesPointsFound = false, jaFound = false;

  bool versionFoundSer = false, ciphersFoundSer = false, extensionsFoundSer = false, 
       curvesFoundSer = false, curvesPointsFoundSer = false, jaFoundSer = false;
  uint pktId = 1;
  getProtocols("./pcaps/ssl-3.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    pfwl_string_t field;
    int64_t fieldNum;
    int64_t htype;
    if(status >= PFWL_STATUS_OK && r.l7.protocol == PFWL_PROTO_L7_SSL){
      if(!pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_HANDSHAKE_TYPE, &htype)){
        if(htype == 0x01){
          if(!pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE, &fieldNum)){
            EXPECT_EQ((uint16_t) fieldNum, 770);
            versionFound = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_CIPHER_SUITES, &field)){
            EXPECT_EQ(strncmp((const char*) field.value, "49172-49162-57-56-55-54-136-135-134-133-49167-49157-53-132-49171-49161-51-50-49-48-154-153-152-151-69-68-67-66-49166-49156-47-150-65-7-49169-49159-49164-49154-5-4-49170-49160-22-19-16-13-49165-49155-10-255", field.length), 0);
            ciphersFound = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_EXTENSIONS, &field)){
            EXPECT_EQ(strncmp((const char*) field.value, "11-10-35-15", field.length), 0);
            extensionsFound = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES, &field)){
            curvesFound = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS, &field)){
            curvesPointsFound = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_JA3, &field)){
            EXPECT_EQ(strncmp((const char*) field.value, "5eb6e1fe80f696450a62a48bb3d6a965", field.length), 0);
            jaFound = true;
          }
        }else if(htype == 0x02){
          if(!pfwl_field_number_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_VERSION_HANDSHAKE, &fieldNum)){
            EXPECT_EQ((uint16_t) fieldNum, 770);
            versionFoundSer = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_CIPHER_SUITES, &field)){
            EXPECT_EQ(strncmp((const char*) field.value, "49171", field.length), 0);
            ciphersFoundSer = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_EXTENSIONS, &field)){
            EXPECT_EQ(strncmp((const char*) field.value, "65281-35-11", field.length), 0);
            extensionsFoundSer = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES, &field)){
            curvesFoundSer = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_ELLIPTIC_CURVES_POINT_FMTS, &field)){
            curvesPointsFoundSer = true;
          }
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SSL_JA3, &field)){            
            EXPECT_EQ(strncmp((const char*) field.value, "b5237e0430ad71aac52aa90b6627cb5f", field.length), 0);
            jaFoundSer = true;
          }
        }
      }
    }
  });
  EXPECT_TRUE(versionFound);
  EXPECT_TRUE(ciphersFound);
  EXPECT_TRUE(extensionsFound);
  EXPECT_TRUE(curvesFound);
  EXPECT_TRUE(curvesPointsFound);
  EXPECT_TRUE(jaFound);

  EXPECT_TRUE(versionFoundSer);
  EXPECT_TRUE(ciphersFoundSer);
  EXPECT_TRUE(extensionsFoundSer);
  EXPECT_FALSE(curvesFoundSer);
  EXPECT_FALSE(curvesPointsFoundSer);
  EXPECT_TRUE(jaFoundSer);

  pfwl_tcp_reordering_enable(state);
  pfwl_terminate(state);
}


TEST(SSLTest, JA3Tags) {
  pfwl_state_t* state = pfwl_init();
  pfwl_field_tags_load_L7(state, PFWL_FIELDS_L7_SSL_JA3, "./tags/ja3.json");

  std::vector<uint> protocols;
  bool found = true;
  getProtocols("./pcaps/whatsapp_login_call.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    for(size_t i = 0; i < r.l7.tags_num; i++){
      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "Used by many programs on OSX,apple.WebKit.Networking")){
        found = true;
      }
    }
  });
  EXPECT_TRUE(found);
  pfwl_terminate(state);
}
