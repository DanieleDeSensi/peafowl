/**
 * @file  structures.h
 * @brief Declaration of structures for the packet headers parsing
 *
 * Created on: 24/09/2018
 *
 * =========================================================================
 *  Copyright (C) 2018, Michele Campus (michelecampus5@gmail.com)
 *  Copyright (C) 2012-2018, Daniele De Sensi (d.desensi.software@gmail.com)
 *
 *  This file is part of Peafowl.
 *
 *  Peafowl is free software: you can redistribute it and/or
 *  modify it under the terms of the Lesser GNU General Public
 *  License as published by the Free Software Foundation, either
 *  version 3 of the License, or (at your option) any later version.

 *  Peafowl is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  Lesser GNU General Public License for more details.
 *
 *  You should have received a copy of the Lesser GNU General Public
 *  License along with Peafowl.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 * =========================================================================
 */

#ifndef STRUCTURES_H
#define STRUCTURES_H

#ifdef __cplusplus
extern "C" {
#endif

/* Header offsets */
#define ETHHDR_SIZE          14
#define TOKENRING_SIZE       22
#define PPPHDR_SIZE           4
#define SLIPHDR_SIZE         16
#define RAWHDR_SIZE           0
#define LOOPHDR_SIZE          4
#define FDDIHDR_SIZE         21
#define ISDNHDR_SIZE         16
#define IEEE80211HDR_SIZE    32

/* SNAP extension */
#define SNAP                    0xAA
/* Ethernet protocol ID's from Ether Type field */
#define	ETHERTYPE_ARP		    0x0806	        /* Address resolution */
#define	ETHERTYPE_RARP	        0x8035	        /* Reverse ARP */
#define	ETHERTYPE_VLAN		    0x8100	        /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_MPLS_UNI      0x8847          /* Multiprotocol Label Switching */
#define ETHERTYPE_MPLS_MULTI    0x8848

/* Value for Type and Subtype */
enum ieee80211_types
{
    W_MGMT = 0,
    W_CTRL,
    W_DATA,
};
// MGMT
#define M_BEACON  8
#define M_DISASS 10
#define M_B_ACK  10
// CTRL
#define C_RTS    11
#define C_ACK    13
// DATA
#define D_DATA    0
#define D_NULL    2
#define D_QOSD    8
#define D_QOSN   12


/* RADIOTAP_FLAGS */
   enum ieee80211_radiotap_flags
   {
       F_CFP      = 0x01,
       F_SHORTPRE = 0x02,
       F_WEP      = 0x04,
       F_FRAG     = 0x08,
       F_FCS      = 0x10,
       F_DATAPAD  = 0x20,
       F_BADFCS   = 0x40,
   };


  /* +++++++++++++++++ LLC SNAP header (IEEE 802.2) ++++++++++++ */
  struct llc_snap_hdr
  {
    /* llc, should be 0xaa 0xaa 0x03 for snap */
    uint8_t  dsap;
    uint8_t  ssap;
    uint8_t  control;
    /* snap */
    uint8_t  oui[3];
    uint16_t type;
  } __attribute__((__packed__));


  /* +++++++++++++++ 802.1Q header (Virtual LAN) +++++++++++++++ */
  struct vlan_hdr
  {
    uint16_t tci;
    uint16_t type;
  } __attribute__((__packed__));



  /* +++++++++++++++++++++++ MPLS header +++++++++++++++++++++++ */
  struct mpls_header
  {
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint32_t ttl:8, s:1, exp:3, label:20;
#elif (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    uint32_t label:20, exp:3, s:1, ttl:8;
#endif
  } __attribute__((__packed__));



  /* ++++++++++ Radio Tap header (for IEEE 802.11) +++++++++++++ */
  struct radiotap_hdr
  {
    uint8_t  version;         /* set to 0 */
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
  } __attribute__((__packed__));


  /* ++++++++++++ Wireless header (IEEE 802.11) ++++++++++++++++ */
  struct wifi_hdr
  {
    uint8_t  ts;
    uint8_t  flags;
    uint16_t duration;
    uint8_t  rcvr[6]; // these 3 fields
    uint8_t  trsm[6]; // should be
    uint8_t  dest[6]; // in a different order
    uint16_t fgsq;
    uint16_t seq_ctrl;
    /* u_int64_t ccmp - for data encription only - check fc.flag */
  } __attribute__((__packed__));

#ifdef __cplusplus
}
#endif

#endif
