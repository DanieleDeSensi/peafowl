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
    EXPECT_EQ(protocols[DPI_PROTOCOL_SIP], (uint) 102);
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SIP], (uint) 6);
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SIP], (uint) 140);
}

TEST(SIPTest, CallbackRequestURI){
    std::vector<uint> protocols;
    dpi_library_state_t* state = dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
    pfwl_protocol_field_add(state, DPI_PROTOCOL_SIP, DPI_FIELDS_SIP_REQUEST_URI);
    pfwl_protocol_field_add(state, DPI_PROTOCOL_SIP, DPI_FIELDS_SIP_METHOD);
    std::vector<dpi_identification_result_t>  results = getProtocolsWithState("./pcaps/sip-rtp.pcap", protocols, state);
    EXPECT_EQ(protocols[DPI_PROTOCOL_SIP], (uint) 102);
    for(auto r : results){
      if(r.protocol_l7 == DPI_PROTOCOL_SIP){
        if(r.protocol_fields[DPI_FIELDS_SIP_REQUEST_URI].len){
          const char* field_value = r.protocol_fields[DPI_FIELDS_SIP_REQUEST_URI].s;
          size_t field_len = r.protocol_fields[DPI_FIELDS_SIP_REQUEST_URI].len;
          EXPECT_TRUE(!strncmp(field_value, expectedRequestURIs[nextExpectedURI], field_len));
          ++nextExpectedURI;
        }else if(r.protocol_fields[DPI_FIELDS_SIP_METHOD].len){
          const char* field_value = r.protocol_fields[DPI_FIELDS_SIP_METHOD].s;
          size_t field_len = r.protocol_fields[DPI_FIELDS_SIP_METHOD].len;
          EXPECT_TRUE(!strncmp(field_value, expectedMethods[nextExpectedMethod], field_len));
          ++nextExpectedMethod;
        }
      }
    }
}
