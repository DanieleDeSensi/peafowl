/**
 *  Test for HTTP protocol.
 **/
#include "common.h"
#include <netinet/ip.h>

TEST(HTTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/http.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_HTTP], (uint) 35);
    getProtocols("./pcaps/http-jpeg.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_HTTP], (uint) 15);
    getProtocols("./pcaps/skype-irc.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_HTTP], (uint) 12);
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_HTTP], (uint) 4);
    getProtocols("./pcaps/6in4tunnel.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_HTTP], (uint) 6);
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_HTTP], (uint) 11);
    getProtocols("./pcaps/spotify.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_HTTP], (uint) 10);
}

TEST(HTTPTest, ContentType) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
  unsigned char first_bytes[] = {0xd8, 0xff, 0xe0, 0xff, 0x10, 0x00, 0x46, 0x4a, 0x46,  0x49, 0x01, 0x00, 0x01, 0x01, 0x48, 0x00};
  unsigned char last_bytes[] = {0x6c, 0x7d, 0xf7, 0xfa, 0x9b, 0xd9, 0x53, 0xfd, 0x9f, 0xea, 0xfc, 0x73, 0xec, 0x8f, 0x36, 0xf7, 0x59, 0x7f, 0xff, 0x9f, 0xd9};
#else

  unsigned char first_bytes[] = {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46,  0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48};
  unsigned char last_bytes[] = {0x7d, 0x6c, 0xfa, 0xf7, 0xd9, 0x9b, 0xfd, 0x53, 0xea, 0x9f, 0x73, 0xfc, 0x8f, 0xec, 0xf7, 0x36, 0x7f, 0x59, 0x9f, 0xff, 0xd9};
#endif
  std::vector<uint> protocols;
  pfwl_state_t* state = pfwl_init();
  pfwl_protocol_field_add(state, PFWL_FIELDS_HTTP_CONTENT_TYPE);
  pfwl_protocol_field_add(state, PFWL_FIELDS_HTTP_BODY);
  for(auto r : getProtocolsWithState("./pcaps/http-jpeg.pcap", protocols, state)){
    if(r.protocol_l7 == PFWL_PROTOCOL_HTTP){
      if((*r.user_flow_data == NULL) &&
         r.protocol_fields[PFWL_FIELDS_HTTP_CONTENT_TYPE].str.len &&
         (strncmp((char*) r.protocol_fields[PFWL_FIELDS_HTTP_CONTENT_TYPE].str.s, "image/jpeg", r.protocol_fields[PFWL_FIELDS_HTTP_CONTENT_TYPE].str.len) == 0)){
        *r.user_flow_data = (void*) 1;
      }

      size_t field_len = r.protocol_fields[PFWL_FIELDS_HTTP_BODY].str.len;
      const char* field = r.protocol_fields[PFWL_FIELDS_HTTP_BODY].str.s;
      if(field_len && *r.user_flow_data){
        size_t i;
        for(i = 0; i < sizeof(first_bytes); ++i){
          printf("%2X ", field[i]);
          EXPECT_EQ(field[i], first_bytes[i]);
        }

        printf("\n");
        for(i = 0; i < sizeof(last_bytes); i++){
          EXPECT_EQ(field[field_len - i], last_bytes[i]);
        }
        *r.user_flow_data = 0;
      }
    }
  }

  pfwl_terminate(state);
}
