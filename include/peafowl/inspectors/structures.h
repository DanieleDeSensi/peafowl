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
#define SNAP               0xAA

/* Ethernet protocol ID's from Ether Type field */
#define	ETHERTYPE_ARP		0x0806	        /* Address resolution */
#define	ETHERTYPE_RARP	        0x8035	        /* Reverse ARP */
#define	ETHERTYPE_VLAN		0x8100	        /* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_MPLS_UNI      0x8847          /* Multiprotocol Label Switching */
#define ETHERTYPE_MPLS_MULTI    0x8848

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)
/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */


  
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
  } __attribute__((__packed__));;
  
  
  
  /* +++++++++++++++++++++++ MPLS header +++++++++++++++++++++++ */
  struct mpls_header
  {
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint32_t ttl:8, s:1, exp:3, label:20;
#elif (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    uint32_t label:20, exp:3, s:1, ttl:8;
#endif
  } __attribute__((__packed__));;
  
  
  
  /* ++++++++++ Radio Tap header (for IEEE 802.11) +++++++++++++ */
  struct radiotap_hdr
  {
    uint8_t  version;         /* set to 0 */
    uint8_t  pad;
    uint16_t len;
    uint32_t present;
    uint8_t  flags;
  } __attribute__((__packed__));;
  
  
  /* ++++++++++++ Wireless header (IEEE 802.11) ++++++++++++++++ */
  struct wifi_hdr
  {
    uint16_t fc;
    uint16_t duration;
    uint8_t  rcvr[6];
    uint8_t  trsm[6];
    uint8_t  dest[6];
    uint16_t seq_ctrl;
    /* u_int64_t ccmp - for data encription only - check fc.flag */
  } __attribute__((__packed__));;
  
#ifdef __cplusplus
}
#endif

#endif
