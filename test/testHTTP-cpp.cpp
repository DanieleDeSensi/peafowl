/**
 *  Test for HTTP protocol.
 **/
#include "common.h"
#include <netinet/ip.h>

TEST(HTTPTest, Generic) {
    std::vector<uint> protocols;
    getProtocolsCpp("./pcaps/http.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 36);
    getProtocolsCpp("./pcaps/http-jpeg.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 16);
    getProtocolsCpp("./pcaps/skype-irc.cap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 14);
    getProtocolsCpp("./pcaps/whatsapp.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 4);
    getProtocolsCpp("./pcaps/6in4tunnel.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 7);
    getProtocolsCpp("./pcaps/dropbox.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 14);
    getProtocolsCpp("./pcaps/spotify.pcapng", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 10);
    getProtocolsCpp("./pcaps/http-2.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 8);
    getProtocolsCpp("./pcaps/http-2-out-of-order.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 9);
    getProtocolsCpp("./pcaps/http-segmented.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 20);
    getProtocolsCpp("./pcaps/ethereum-js-http.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTO_L7_HTTP], (uint) 7);
}

TEST(HTTPTest, TCPDuplicates){
  std::vector<uint> protocols;
  peafowl::Peafowl state;
  state.tcpReorderingDisable();
  getProtocolsCpp("./pcaps/http.cap", protocols, &state);
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
  peafowl::Peafowl state;
  state.fieldAddL7(PFWL_FIELDS_L7_HTTP_HEADERS);
  state.fieldAddL7(PFWL_FIELDS_L7_HTTP_BODY);
  bool ctFound = false;
  bool bodyFound = false;
  peafowl::Field field;
  getProtocolsCpp("./pcaps/http-jpeg.pcap", protocols, &state, [&](peafowl::Status status, peafowl::DissectionInfo& r){
  if(r.getL7().getProtocol() == PFWL_PROTO_L7_HTTP){
    if((*r.getFlowInfo().getUserData() == NULL) &&
       (field = r.getL7().httpGetHeader("Content-Type")).isPresent() &&
       field.getString() == "image/jpeg"){
      ctFound = true;
      r.getFlowInfo().setUserData((void*) 1);
    }

    if((field = r.getL7().getField(PFWL_FIELDS_L7_HTTP_BODY)).isPresent() &&
       *r.getFlowInfo().getUserData()){
      bodyFound = true;
      std::string s = field.getString();
      for(size_t i = 0; i < sizeof(first_bytes); ++i){
        EXPECT_TRUE((unsigned char) s[i] == first_bytes[i]);
      }

      for(size_t i = 0; i < sizeof(last_bytes); i++){
        EXPECT_TRUE((unsigned char) s[s.size() - sizeof(last_bytes) + i] == last_bytes[i]);
      }
      r.getFlowInfo().setUserData(0);
    }
  }
  });
  EXPECT_TRUE(ctFound);
  EXPECT_TRUE(bodyFound);
}

TEST(HTTPTest, ContentType2) {
    const char* filenames[] = {"./pcaps/http-2.pcap", "./pcaps/http-2-out-of-order.pcap"};
    for(auto filename : filenames){
      std::vector<uint> protocols;
      peafowl::Peafowl state;
      state.fieldAddL7(PFWL_FIELDS_L7_HTTP_HEADERS);
      state.fieldAddL7(PFWL_FIELDS_L7_HTTP_BODY);
      bool cTypeFound = false, bodyFound = false, uAgentFound = false, hostFound = false;
      size_t packet_id = 1; // Just simpler to compare with Wireshark dissection, where packets start from 1
      getProtocolsCpp(filename, protocols, &state, [&](peafowl::Status status, peafowl::DissectionInfo& r){
        if(r.getL7().getProtocol() == PFWL_PROTO_L7_HTTP){
          // Content type
          peafowl::Field field;
          if((field = r.getL7().httpGetHeader("Content-Type")).isPresent()){
            cTypeFound = true;
            EXPECT_STREQ(field.getString().c_str(), "text/html");
          }

          // Host
          if((field = r.getL7().httpGetHeader("Host")).isPresent()){
            hostFound = true;
            EXPECT_STREQ(field.getString().c_str(), "bill.ins.com");
          }

          // User agent
          if((field = r.getL7().httpGetHeader("User-Agent")).isPresent()){
            uAgentFound = true;
            EXPECT_STREQ(field.getString().c_str(), "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)");
          }

          // Body
          if((field = r.getL7().getField(PFWL_FIELDS_L7_HTTP_BODY)).isPresent()){
            size_t body_packet_id;
            if(strstr(filename, "out-of-order")){
              body_packet_id = 5;
            }else{
              body_packet_id = 7;
            }
            if(packet_id == body_packet_id){
              bodyFound = true;
              std::string s = field.getString();
              EXPECT_FALSE(strncmp((const char*) s.c_str(), "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">", 90));
              EXPECT_EQ(s[s.size() - 4], 'L');
              EXPECT_EQ(s[s.size() - 3], '>');
            }
          }
        }
        packet_id++;
      });

      EXPECT_TRUE(cTypeFound);
      EXPECT_TRUE(uAgentFound);
      EXPECT_TRUE(hostFound);
      EXPECT_TRUE(bodyFound);
    }
}

TEST(HTTPTest, Tags) {
  peafowl::Peafowl state;
  state.fieldStringTagsAddL7(PFWL_FIELDS_L7_HTTP_URL, "load.html", PFWL_FIELD_MATCHING_SUFFIX, "TAG_SUFFIX");
  state.fieldStringTagsAddL7(PFWL_FIELDS_L7_HTTP_BODY, "<?xml version", PFWL_FIELD_MATCHING_PREFIX, "TAG_PREFIX");
  state.fieldMmapTagsAddL7(PFWL_FIELDS_L7_HTTP_HEADERS, "user-agent", "mozilla", PFWL_FIELD_MATCHING_PREFIX, "TAG_MOZILLA");
  state.fieldMmapTagsAddL7(PFWL_FIELDS_L7_HTTP_HEADERS, "host", "www.ethereal", PFWL_FIELD_MATCHING_PREFIX, "TAG_ETHEREAL");

  std::vector<uint> protocols;
  bool foundSuffix = false, foundPrefix = false, foundMozilla = false, foundEthereal = false;
  getProtocolsCpp("./pcaps/http.cap", protocols, &state, [&](peafowl::Status status, peafowl::DissectionInfo& r){

    for(auto tag : r.getL7().getTags()){
      if(tag == "TAG_SUFFIX"){
        foundSuffix = true;
      }

      if(tag == "TAG_PREFIX"){
        foundPrefix = true;
      }

      if(tag == "TAG_MOZILLA"){
        foundMozilla = true;
      }

      if(tag == "TAG_ETHEREAL"){
        foundEthereal = true;
      }
    }
  });
  EXPECT_TRUE(foundSuffix);
  EXPECT_TRUE(foundPrefix);
  EXPECT_TRUE(foundMozilla);
  EXPECT_TRUE(foundEthereal);
}

TEST(HTTPTest, TagsFromFile) {
  peafowl::Peafowl state;
  state.fieldTagsLoadL7(PFWL_FIELDS_L7_HTTP_URL, "./tags/http_url.json");
  state.fieldTagsLoadL7(PFWL_FIELDS_L7_HTTP_BODY, "./tags/http_body.json");
  state.fieldTagsLoadL7(PFWL_FIELDS_L7_HTTP_HEADERS, "./tags/http_headers.json");

  std::vector<uint> protocols;
  bool foundSuffix = false, foundPrefix = false, foundMozilla = false, foundEthereal = false;
  getProtocolsCpp("./pcaps/http.cap", protocols, &state, [&](peafowl::Status status, peafowl::DissectionInfo& r){
    for(auto tag : r.getL7().getTags()){
      if(tag == "TAG_SUFFIX"){
        foundSuffix = true;
      }

      if(tag == "TAG_PREFIX"){
        foundPrefix = true;
      }

      if(tag == "TAG_MOZILLA"){
        foundMozilla = true;
      }

      if(tag == "TAG_ETHEREAL"){
        foundEthereal = true;
      }
    }
  });
  EXPECT_TRUE(foundSuffix);
  EXPECT_TRUE(foundPrefix);
  EXPECT_TRUE(foundMozilla);
  EXPECT_TRUE(foundEthereal);
}

