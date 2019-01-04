/**
 *  Test for HTTP protocol.
 **/
#include "common.h"
#include <netinet/ip.h>

TEST(HTTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/http.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 36);
    getProtocols("./pcaps/http-jpeg.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 16);
    getProtocols("./pcaps/skype-irc.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 14);
    getProtocols("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 4);
    getProtocols("./pcaps/6in4tunnel.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 7);
    getProtocols("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 14);
    getProtocols("./pcaps/spotify.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 10);
    getProtocols("./pcaps/http-2.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 8);
    getProtocols("./pcaps/http-2-out-of-order.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 9);
    getProtocols("./pcaps/http-segmented.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 20);
    getProtocols("./pcaps/ethereum-js-http.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 7);
}

TEST(HTTPTest, TCPDuplicates){
  std::vector<uint> protocols;
  pfwl_state_t* state = pfwl_init();
  pfwl_tcp_reordering_disable(state);
  getProtocols("./pcaps/http.cap", protocols, state);
  // Two TCP segments retransmitted. So it counts 37 rather than 35
  EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 38);
}

TEST(HTTPTest, ContentType) {
//#if __BYTE_ORDER == __LITTLE_ENDIAN
//  unsigned char first_bytes[] = {0xd8, 0xff, 0xe0, 0xff, 0x10, 0x00, 0x46, 0x4a, 0x46,  0x49, 0x01, 0x00, 0x01, 0x01, 0x48, 0x00};
//  unsigned char last_bytes[] = {0x6c, 0x7d, 0xf7, 0xfa, 0x9b, 0xd9, 0x53, 0xfd, 0x9f, 0xea, 0xfc, 0x73, 0xec, 0x8f, 0x36, 0xf7, 0x59, 0x7f, 0xff, 0x9f, 0xd9};
  unsigned char first_bytes[] = {0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46,  0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48};
  unsigned char last_bytes[] = {0x7d, 0x6c, 0xfa, 0xf7, 0xd9, 0x9b, 0xfd, 0x53, 0xea, 0x9f, 0x73, 0xfc, 0x8f, 0xec, 0xf7, 0x36, 0x7f, 0x59, 0x9f, 0xff, 0xd9};
  std::vector<uint> protocols;
  pfwl_state_t* state = pfwl_init();
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_HTTP_HEADERS);
  pfwl_field_add_L7(state, PFWL_FIELDS_L7_HTTP_BODY);
  bool ctFound = false;
  bool bodyFound = false;
  getProtocols("./pcaps/http-jpeg.pcap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
  if(r.l7.protocol == PFWL_PROTO_L7_HTTP){
    pfwl_string_t field;
    if((*r.flow_info.udata == NULL) &&
       !pfwl_http_get_header(&r, "Content-Type", &field) &&
       (strncmp((const char*)  field.value, "image/jpeg", field.length) == 0)){
      ctFound = true;
      *r.flow_info.udata = (void*) 1;
    }

    if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_HTTP_BODY, &field) &&
       *r.flow_info.udata){
      bodyFound = true;
      for(size_t i = 0; i < sizeof(first_bytes); ++i){
        EXPECT_EQ(field.value[i], first_bytes[i]);
      }

      for(size_t i = 0; i < sizeof(last_bytes); i++){
        EXPECT_EQ(field.value[field.length - sizeof(last_bytes) + i], last_bytes[i]);
      }
      *r.flow_info.udata = 0;
    }
  }
  });
  EXPECT_TRUE(ctFound);
  EXPECT_TRUE(bodyFound);
  pfwl_terminate(state);
}

TEST(HTTPTest, ContentType2) {
    const char* filenames[] = {"./pcaps/http-2.pcap", "./pcaps/http-2-out-of-order.pcap"};
    for(auto filename : filenames){
      std::vector<uint> protocols;
      pfwl_state_t* state = pfwl_init();
      pfwl_field_add_L7(state, PFWL_FIELDS_L7_HTTP_HEADERS);
      pfwl_field_add_L7(state, PFWL_FIELDS_L7_HTTP_BODY);
      bool cTypeFound = false, bodyFound = false, uAgentFound = false, hostFound = false;
      size_t packet_id = 1; // Just simpler to compare with Wireshark dissection, where packets start from 1
      getProtocols(filename, protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
        if(r.l7.protocol == PFWL_PROTO_L7_HTTP){
          // Content type
          pfwl_string_t field;
          if(!pfwl_http_get_header(&r, "Content-Type", &field)){
            cTypeFound = true;
            EXPECT_FALSE(strncmp((const char*) field.value, "text/html", field.length));
          }

          // Host
          if(!pfwl_http_get_header(&r, "Host", &field)){
            hostFound = true;
            EXPECT_FALSE(strncmp((const char*) field.value, "bill.ins.com", field.length));
          }

          // User agent
          if(!pfwl_http_get_header(&r, "User-Agent", &field)){
            uAgentFound = true;
            EXPECT_FALSE(strncmp((const char*) field.value, "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)", field.length));
          }

          // Body
          if(!pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_HTTP_BODY, &field)){
            size_t body_packet_id;
            if(strstr(filename, "out-of-order")){
              body_packet_id = 5;
            }else{
              body_packet_id = 7;
            }
            if(packet_id == body_packet_id){
              bodyFound = true;
              EXPECT_FALSE(strncmp((const char*) field.value, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">", 90));
              EXPECT_EQ(field.value[field.length - 4], 'L');
              EXPECT_EQ(field.value[field.length - 3], '>');
            }
          }
        }
        packet_id++;
      });

      EXPECT_TRUE(cTypeFound);
      EXPECT_TRUE(uAgentFound);
      EXPECT_TRUE(hostFound);
      EXPECT_TRUE(bodyFound);

      pfwl_terminate(state);
    }
}

TEST(HTTPTest, Tags) {
  pfwl_state_t* state = pfwl_init();
  pfwl_field_string_tags_add_L7(state, PFWL_FIELDS_L7_HTTP_URL, "load.html", PFWL_FIELD_MATCHING_SUFFIX, "TAG_SUFFIX");
  pfwl_field_string_tags_add_L7(state, PFWL_FIELDS_L7_HTTP_BODY, "<?xml version", PFWL_FIELD_MATCHING_PREFIX, "TAG_PREFIX");
  pfwl_field_mmap_tags_add_L7(state, PFWL_FIELDS_L7_HTTP_HEADERS, "user-agent", "mozilla", PFWL_FIELD_MATCHING_PREFIX, "TAG_MOZILLA");
  pfwl_field_mmap_tags_add_L7(state, PFWL_FIELDS_L7_HTTP_HEADERS, "host", "www.ethereal", PFWL_FIELD_MATCHING_PREFIX, "TAG_ETHEREAL");

  std::vector<uint> protocols;
  bool foundSuffix = false, foundPrefix = false, foundMozilla = false, foundEthereal = false;
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){

    for(size_t i = 0; i < r.l7.tags_num; i++){
      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_SUFFIX")){
        foundSuffix = true;
      }

      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_PREFIX")){
        foundPrefix = true;
      }

      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_MOZILLA")){
        foundMozilla = true;
      }

      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_ETHEREAL")){
        foundEthereal = true;
      }
    }
  });
  EXPECT_TRUE(foundSuffix);
  EXPECT_TRUE(foundPrefix);
  EXPECT_TRUE(foundMozilla);
  EXPECT_TRUE(foundEthereal);
  pfwl_terminate(state);
}

TEST(HTTPTest, TagsFromFile) {
  pfwl_state_t* state = pfwl_init();
  pfwl_field_tags_load_L7(state, PFWL_FIELDS_L7_HTTP_URL, "./tags/http_url.json");
  pfwl_field_tags_load_L7(state, PFWL_FIELDS_L7_HTTP_BODY, "./tags/http_body.json");
  pfwl_field_tags_load_L7(state, PFWL_FIELDS_L7_HTTP_HEADERS, "./tags/http_headers.json");

  std::vector<uint> protocols;
  bool foundSuffix = false, foundPrefix = false, foundMozilla = false, foundEthereal = false;
  getProtocols("./pcaps/http.cap", protocols, state, [&](pfwl_status_t status, pfwl_dissection_info_t r){
    for(size_t i = 0; i < r.l7.tags_num; i++){
      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_SUFFIX")){
        foundSuffix = true;
      }

      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_PREFIX")){
        foundPrefix = true;
      }

      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_MOZILLA")){
        foundMozilla = true;
      }

      if(r.l7.tags_num &&
         !strcmp(r.l7.tags[i], "TAG_ETHEREAL")){
        foundEthereal = true;
      }
    }
  });
  EXPECT_TRUE(foundSuffix);
  EXPECT_TRUE(foundPrefix);
  EXPECT_TRUE(foundMozilla);
  EXPECT_TRUE(foundEthereal);
  pfwl_terminate(state);
}

