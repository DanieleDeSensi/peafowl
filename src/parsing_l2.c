/*
 * peafowl_l2_parsing.c
 *
 * Created on: 6/10/2018
 * =========================================================================
 * Copyright (c) 2018, Michele Campus (michelecampus5@gmail.com)
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */
#include <peafowl/config.h>
#include <peafowl/flow_table.h>
#include <peafowl/hash_functions.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/ipv4_reassembly.h>
#include <peafowl/ipv6_reassembly.h>
#include <peafowl/peafowl.h>
#include <peafowl/tcp_stream_management.h>
#include <peafowl/utils.h>

#include <arpa/inet.h>
#include <assert.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#endif

#ifndef PFWL_DEBUG_L2
#define PFWL_DEBUG_L2 0
#endif
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_L2)                                                         \
      fprintf(stderr, fmt, __VA_ARGS__);                                       \
  } while (0)

/* Header offsets */
#define ETHHDR_SIZE 14
#define TOKENRING_SIZE 22
#define PPPHDR_SIZE 4
#define SLIPHDR_SIZE 16
#define RAWHDR_SIZE 0
#define LOOPHDR_SIZE 4
#define FDDIHDR_SIZE 21
#define ISDNHDR_SIZE 16
#define IEEE80211HDR_SIZE 32

/* SNAP extension */
#define SNAP 0xAA
/* Ethernet protocol ID's from Ether Type field */
#define ETHERTYPE_ARP 0x0806      /* Address resolution */
#define ETHERTYPE_RARP 0x8035     /* Reverse ARP */
#define ETHERTYPE_VLAN 0x8100     /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_MPLS_UNI 0x8847 /* Multiprotocol Label Switching */
#define ETHERTYPE_MPLS_MULTI 0x8848

/* Value for Type and Subtype */
enum ieee80211_types {
  W_MGMT = 0,
  W_CTRL,
  W_DATA,
};
// MGMT
#define M_BEACON 8
#define M_DISASS 10
#define M_B_ACK 10
// CTRL
#define C_RTS 11
#define C_ACK 13
// DATA
#define D_DATA 0
#define D_NULL 2
#define D_QOSD 8
#define D_QOSN 12

/* RADIOTAP_FLAGS */
enum ieee80211_radiotap_flags {
  F_CFP = 0x01,
  F_SHORTPRE = 0x02,
  F_WEP = 0x04,
  F_FRAG = 0x08,
  F_FCS = 0x10,
  F_DATAPAD = 0x20,
  F_BADFCS = 0x40,
};

/* +++++++++++++++++ LLC SNAP header (IEEE 802.2) ++++++++++++ */
struct llc_snap_hdr {
  /* llc, should be 0xaa 0xaa 0x03 for snap */
  uint8_t dsap;
  uint8_t ssap;
  uint8_t control;
  /* snap */
  uint8_t oui[3];
  uint16_t type;
} __attribute__((__packed__));

/* +++++++++++++++ 802.1Q header (Virtual LAN) +++++++++++++++ */
struct vlan_hdr {
  uint16_t tci;
  uint16_t type;
} __attribute__((__packed__));

/* +++++++++++++++++++++++ MPLS header +++++++++++++++++++++++ */
struct mpls_header {
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  uint32_t ttl : 8, s : 1, exp : 3, label : 20;
#elif (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
  uint32_t label : 20, exp : 3, s : 1, ttl : 8;
#endif
} __attribute__((__packed__));

/* ++++++++++ Radio Tap header (for IEEE 802.11) +++++++++++++ */
struct radiotap_hdr {
  uint8_t version; /* set to 0 */
  uint8_t pad;
  uint16_t len;
  uint32_t present;
} __attribute__((__packed__));

/* ++++++++++++ Wireless header (IEEE 802.11) ++++++++++++++++ */
struct wifi_hdr {
  uint8_t ts;
  uint8_t flags;
  uint16_t duration;
  uint8_t rcvr[6]; // these 3 fields
  uint8_t trsm[6]; // should be
  uint8_t dest[6]; // in a different order
  uint16_t fgsq;
  uint16_t seq_ctrl;
  /* u_int64_t ccmp - for data encription only - check fc.flag */
} __attribute__((__packed__));

static uint16_t pfwl_check_dtype(const u_char *packet, uint16_t type,
                                 uint16_t off) {
  uint32_t dlink_offset = off;

  // define vlan header
  const struct vlan_hdr *vlan_header = NULL;
  // define mpls
  union mpls {
    uint32_t u32;
    struct mpls_header mpls;
  } mpls;

  switch (type) {
  /**
   NOTE:
   The check for IPv4 or IPv6 type is done later
   in another function
   TODO: ARP check
      **/
  // VLAN
  case ETHERTYPE_VLAN:
    debug_print("%s\n", "Ethernet type: VLAN\n");
    vlan_header = (struct vlan_hdr *) (packet + dlink_offset);
    type = ntohs(vlan_header->type);
    // double tagging for 802.1Q
    if (type == 0x8100) {
      debug_print("%s\n", "\tdouble tagging VLAN\n");
      dlink_offset += 4;
      // vlan_header = (struct vlan_hdr *) (packet + dlink_offset);
    }
    dlink_offset += 4;
    break;
  // MPLS
  case ETHERTYPE_MPLS_UNI:
  case ETHERTYPE_MPLS_MULTI:
    debug_print("%s\n", "Ethernet type: MPLS\n");
    mpls.u32 = *((uint32_t *) &packet[dlink_offset]);
    mpls.u32 = ntohl(mpls.u32);
    dlink_offset += 4;
    // multiple MPLS fields
    while (!mpls.mpls.s) {
      mpls.u32 = *((uint32_t *) &packet[dlink_offset]);
      mpls.u32 = ntohl(mpls.u32);
      dlink_offset += 4;
    }
    break;
  }
  return dlink_offset;
}

/*
  Function for pfwl_parse_datalink()
  @return n bit from position p of number x
*/
static inline uint8_t getBits(uint16_t x, int p, int n) {
  return (x >> (p + 1 - n)) & ~(~0 << n);
}

pfwl_status_t pfwl_dissect_L2(const unsigned char *packet,
                              pfwl_protocol_l2_t datalink_type,
                              pfwl_dissection_info_t *dissection_info) {
  memset(dissection_info, 0, sizeof(pfwl_dissection_info_t));
  // check parameters
  if (!packet || datalink_type == PFWL_PROTO_L2_NUM) {
    return PFWL_ERROR_L2_PARSING;
  }

  // len and offset
  uint16_t type = 0, eth_type_1 = 0;
  uint16_t wifi_len = 0, radiotap_len = 0;
  uint16_t dlink_offset = 0;

  // define ethernet header
  struct ether_header *ether_header = NULL;
  // define radio_tap header
  struct radiotap_hdr *radiotap_header = NULL;
  // define wifi header
  struct wifi_hdr *wifi_header = NULL;
  // define llc header
  struct llc_snap_hdr *llc_snap_header = NULL;

  // check the datalink type to cast properly datalink header
  switch (datalink_type) {
  /** IEEE 802.3 Ethernet - 1 **/
  case PFWL_PROTO_L2_EN10MB:
    debug_print("%s\n", "Datalink type: Ethernet\n");
    ether_header = (struct ether_header *) (packet);
    // set datalink offset
    dlink_offset = ETHHDR_SIZE;
    // assign MAC to l2 structure dissection info
    memcpy(dissection_info->l2.mac_src, ether_header->ether_shost, ETH_ALEN);
    memcpy(dissection_info->l2.mac_dst, ether_header->ether_dhost, ETH_ALEN);
    type = ntohs(ether_header->ether_type);
    if (type <= 1500)
      eth_type_1 = 1; // ethernet I - followed by llc snap 05DC
    // check for LLC layer with SNAP extension
    if (eth_type_1) {
      if (packet[dlink_offset] == SNAP) {
        llc_snap_header = (struct llc_snap_hdr *) (packet + dlink_offset);
        type = llc_snap_header->type; // LLC type is the l3 proto type
        dlink_offset += 8;
      }
    }
    break;

  /** Linux Cooked Capture - 113 **/
  case PFWL_PROTO_L2_LINUX_SLL:
    debug_print("%s\n", "Datalink type: Linux Cooked\n");
    type = (packet[dlink_offset + 14] << 8) + packet[dlink_offset + 15];
    dlink_offset = 16;
    break;

  /**
    NOTE: for Radiotap and Wireless
    must be added 4 bytes of FCS (present in the end of l7)
    to match the correct total bytes of the pkt
 **/
  /** Radiotap link-layer - 127 **/
  case PFWL_PROTO_L2_IEEE802_11_RADIO: {
    debug_print("%s\n", "Datalink type: Radiotap\n");
    radiotap_header = (struct radiotap_hdr *) packet;
    radiotap_len = radiotap_header->len;
    dlink_offset = radiotap_len;

    const unsigned char *p_radio = packet + 8;

    // Check if MAC timestamp is present
    if (getBits(radiotap_header->present, 0, 1) == 1) {
      p_radio += 8;
    }

    // Check if Flag byte is present
    if (getBits(radiotap_header->present, 1, 1) == 1) {
      // Check Bad FCS presence
      if (*p_radio == F_BADFCS) {
        debug_print("%s\n", "Malformed Radiotap packet. DISCARD\n");
        return PFWL_ERROR_L2_PARSING;
      }
      p_radio++;
    }

    /**
        Once Radiotap is present,
        we must check if Wifi data is present
     **/
    wifi_header = (struct wifi_hdr *) (packet + radiotap_len);
    // uint8_t ts;   // TYPE/SUBTYPE (the following 3 getBits)

    // Check Data type
    if (getBits(wifi_header->ts, 3, 2) == W_DATA) {
      if ((getBits(wifi_header->ts, 7, 4) == D_DATA) ||
          (getBits(wifi_header->ts, 7, 4) == D_QOSD)) {
        wifi_len = sizeof(struct wifi_hdr); /* 26 bytes */
        dlink_offset += wifi_len;
      }
    }
    // Managment or Control type
    else {
      debug_print("%s\n", "802.11 Managment or Control packet. DISCARD\n");
      return PFWL_ERROR_L2_PARSING;
    }

    // Check LLC
    llc_snap_header = (struct llc_snap_hdr *) (packet + wifi_len);
    if (llc_snap_header->dsap == SNAP || llc_snap_header->ssap == SNAP)
      dlink_offset += sizeof(struct llc_snap_hdr);
    else {
      debug_print("%s\n",
                  "Probably a wifi packet with data encription. Discard\n");
      return PFWL_ERROR_L2_PARSING;
    }
    break;
  }

  case PFWL_PROTO_L2_IEEE802_11: {
    wifi_header = (struct wifi_hdr *) (packet + radiotap_len);
    // uint8_t ts;   // TYPE/SUBTYPE (the following 3 getBits)

    // Check Data type
    if (getBits(wifi_header->ts, 3, 2) == W_DATA) {
      if ((getBits(wifi_header->ts, 7, 4) == D_DATA) ||
          (getBits(wifi_header->ts, 7, 4) == D_QOSD)) {
        wifi_len = sizeof(struct wifi_hdr); /* 26 bytes */
        dlink_offset = wifi_len;
      }
    }
    // Managment or Control type
    else {
      debug_print("%s\n", "802.11 Managment or Control packet. DISCARD\n");
      return PFWL_ERROR_L2_PARSING;
    }

    // Check LLC
    llc_snap_header = (struct llc_snap_hdr *) (packet + wifi_len);
    if (llc_snap_header->dsap == SNAP || llc_snap_header->ssap == SNAP)
      dlink_offset += sizeof(struct llc_snap_hdr);
    else {
      debug_print("%s\n",
                  "Probably a wifi packet with data encription. Discard\n");
      return PFWL_ERROR_L2_PARSING;
    }
    break;
  }

  /** LINKTYPE_IEEE802_5 - 6 **/
  case PFWL_PROTO_L2_IEEE802:
    debug_print("%s\n", "Datalink type: Tokenring\n");
    dlink_offset = TOKENRING_SIZE;
    break;

  /** LINKTYPE_SLIP - 8 **/
  case PFWL_PROTO_L2_SLIP:
    debug_print("%s\n", "Datalink type: Slip\n");
    dlink_offset = SLIPHDR_SIZE;
    break;

  /** LINKTYPE_PPP - 09 **/
  case PFWL_PROTO_L2_PPP:
    debug_print("%s\n", "Datalink type: PPP\n");
    dlink_offset = PPPHDR_SIZE;
    break;

  /** LINKTYPE_FDDI - 10 **/
  case PFWL_PROTO_L2_FDDI:
    debug_print("%s\n", "Datalink type: FDDI\n");
    dlink_offset = FDDIHDR_SIZE;
    break;

  /** LINKTYPE_RAW - 101 **/
  case PFWL_PROTO_L2_RAW:
    debug_print("%s\n", "Datalink type: Raw\n");
    dlink_offset = RAWHDR_SIZE;
    break;

  /** LINKTYPE_LOOP - 108 **/
  case PFWL_PROTO_L2_LOOP:
  /** LINKTYPE_NULL - 0 **/
  case PFWL_PROTO_L2_NULL:
    debug_print("%s\n", "Datalink type: Loop or Null\n");
    dlink_offset = LOOPHDR_SIZE;
    break;
  default:
    return PFWL_ERROR_L2_PARSING;
    break;
  }

  dlink_offset = pfwl_check_dtype(packet, type, dlink_offset);
  dissection_info->l2.length = dlink_offset;
  return PFWL_STATUS_OK;
}

#ifdef HAVE_PCAP
pfwl_protocol_l2_t pfwl_convert_pcap_dlt(int dlt) {
  switch (dlt) {
  case DLT_EN10MB:
    return PFWL_PROTO_L2_EN10MB;
  case DLT_LINUX_SLL:
    return PFWL_PROTO_L2_LINUX_SLL;
  case DLT_IEEE802_11_RADIO:
    return PFWL_PROTO_L2_IEEE802_11_RADIO;
  case DLT_IEEE802_11:
    return PFWL_PROTO_L2_IEEE802_11;
  case DLT_IEEE802:
    return PFWL_PROTO_L2_IEEE802;
  case DLT_SLIP:
    return PFWL_PROTO_L2_SLIP;
  case DLT_PPP:
    return PFWL_PROTO_L2_PPP;
  case DLT_FDDI:
    return PFWL_PROTO_L2_FDDI;
  case DLT_RAW:
    return PFWL_PROTO_L2_RAW;
  case DLT_LOOP:
    return PFWL_PROTO_L2_LOOP;
  case DLT_NULL:
    return PFWL_PROTO_L2_NULL;
  default:
    return PFWL_PROTO_L2_NUM;
  }
}
#else
pfwl_protocol_l2_t pfwl_convert_pcap_dlt(int x) {
  fprintf(
      stderr,
      "To use the pfwl_convert_pcap_dlt call, libpcap needs to be installed");
}
#endif

// clang-format off
static const char* pfwl_l2_protocols_names[PFWL_PROTO_L2_NUM] = {
  [PFWL_PROTO_L2_EN10MB]           = "EN10MB",
  [PFWL_PROTO_L2_LINUX_SLL]        = "LINUX_SSL",
  [PFWL_PROTO_L2_IEEE802_11_RADIO] = "IEEE802_11_RADIO",
  [PFWL_PROTO_L2_IEEE802_11]       = "IEEE802_11",
  [PFWL_PROTO_L2_IEEE802]          = "IEEE802",
  [PFWL_PROTO_L2_SLIP]             = "SLIP",
  [PFWL_PROTO_L2_PPP]              = "PPP",
  [PFWL_PROTO_L2_FDDI]             = "FDDI",
  [PFWL_PROTO_L2_RAW]              = "RAW",
  [PFWL_PROTO_L2_LOOP]             = "LOOP",
  [PFWL_PROTO_L2_NULL]             = "NULL",
};
// clang-format on

const char *pfwl_get_L2_protocol_name(pfwl_protocol_l2_t protocol){
  if(protocol < PFWL_PROTO_L2_NUM){
    return pfwl_l2_protocols_names[protocol];
  }else{
    return "Unknown";
  }
}

pfwl_protocol_l2_t pfwl_get_L2_protocol_id(const char *const name){
  for(size_t i = 0; i < PFWL_PROTO_L2_NUM; i++){
    if(!strcasecmp(name, pfwl_l2_protocols_names[i])){
      return (pfwl_protocol_l2_t) i;
    }
  }
  return PFWL_PROTO_L2_NUM;
}

const char **const pfwl_get_L2_protocols_names(){
  return pfwl_l2_protocols_names;
}
