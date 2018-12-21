/**
 *  Test for HTTP protocol.
 **/
#include "common.h"

static const char* expectedRequestURIs[] = {"sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:97239287044@voip.brujula.net", "sip:0097239287044@sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:0097239287044@sip.cybercity.dk", "sip:35104724@sip.cybercity.dk", "sip:35104724@sip.cybercity.dk", "sip:35104724@sip.cybercity.dk", "sip:35104724@sip.cybercity.dk", "sip:sip.cybercity.dk", "sip:sip.cybercity.dk"};
static const char* expectedMethods[] = {"REGISTER", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "INVITE", "INVITE", "INVITE", "CANCEL", "CANCEL", "CANCEL", "ACK", "CANCEL", "CANCEL", "CANCEL", "CANCEL", "CANCEL", "CANCEL", "CANCEL", "CANCEL", "INVITE", "INVITE", "INVITE", "ACK", "INVITE", "ACK", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "REGISTER", "INVITE", "ACK", "REGISTER", "INVITE", "ACK", "INVITE", "ACK", "INVITE", "ACK", "REGISTER", "REGISTER"};
static size_t nextExpectedURI = 0;
static size_t nextExpectedMethod = 0;

TEST(SIPTest, Generic) {
  std::vector<uint> protocols;
  getProtocols("./pcaps/sip-rtp.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SIP], (uint) 102);
}

TEST(SIPTest, CallbackRequestURI){
  std::vector<uint> protocols;
  pfwl_state_t* state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SIP_REQUEST_URI);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_SIP_METHOD);

  getProtocols("./pcaps/sip-rtp.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    if(r.l7.protocol == PFWL_PROTO_L7_SIP){
      pfwl_string_t field;
      if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SIP_REQUEST_URI, &field)){
        EXPECT_TRUE(!strncmp((const char*) field.value, expectedRequestURIs[nextExpectedURI], field.length));
        ++nextExpectedURI;
      }else if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_SIP_METHOD, &field)){
        EXPECT_TRUE(!strncmp((const char*) field.value, expectedMethods[nextExpectedMethod], field.length));
        ++nextExpectedMethod;
      }
    }
  });
  EXPECT_EQ(protocols[PFWL_PROTO_L7_SIP], (uint) 102);
}

TEST(SIPTest, Tags) {
  pfwl_state_t* state = pfwl_init();
  pfwl_field_string_tags_add_L7(state, PFWL_FIELDS_L7_SIP_REQUEST_URI, "sip.cybercity.dk", PFWL_FIELD_MATCHING_SUFFIX, "TAG_SUFFIX");

  std::vector<uint> protocols;
  bool foundRURI = false;
  getProtocols("./pcaps/sip-rtp.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){

    for(size_t i = 0; i < r.l7.tags_num; i++){
      if(r.l7.protocol == PFWL_PROTO_L7_SIP &&
         r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_SUFFIX")){
        foundRURI = true;
      }
    }
  });
  EXPECT_TRUE(foundRURI);
  pfwl_terminate(state);
}
