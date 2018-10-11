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
  EXPECT_EQ(protocols[PFWL_PROTOCOL_SIP], (uint) 102);
  getProtocols("./pcaps/whatsapp.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTOCOL_SIP], (uint) 6);
  getProtocols("./pcaps/dropbox.pcap", protocols);
  EXPECT_EQ(protocols[PFWL_PROTOCOL_SIP], (uint) 140);
}

TEST(SIPTest, CallbackRequestURI){
  std::vector<uint> protocols;
  pfwl_state_t* state = pfwl_init();
  pfwl_protocol_field_add(state, PFWL_FIELDS_SIP_REQUEST_URI);
  pfwl_protocol_field_add(state, PFWL_FIELDS_SIP_METHOD);

  getProtocols("./pcaps/sip-rtp.pcap", protocols, state, [&](pfwl_dissection_info_t r){
    if(r.l7.protocol == PFWL_PROTOCOL_SIP){
      pfwl_string_t field;
      if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_SIP_REQUEST_URI, &field)){
        EXPECT_TRUE(!strncmp((const char*) field.value, expectedRequestURIs[nextExpectedURI], field.length));
        ++nextExpectedURI;
      }else if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_SIP_METHOD, &field)){
        EXPECT_TRUE(!strncmp((const char*) field.value, expectedMethods[nextExpectedMethod], field.length));
        ++nextExpectedMethod;
      }
    }
  });
  EXPECT_EQ(protocols[PFWL_PROTOCOL_SIP], (uint) 102);
}
