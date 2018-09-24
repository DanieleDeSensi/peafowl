/**
 * @file  structures.h
 * @brief This is the main peafowl header to be included.
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

#ifdef __GNUC__
#define __attribute__ ((__packed__));
#endif

  /* +++++++++++++++++ LLC SNAP header (IEEE 802.2) ++++++++++++ */
  struct llc_snap_hdr
  {
    /* llc, should be 0xaa 0xaa 0x03 for snap */
    u_int8_t  dsap;
    u_int8_t  ssap;
    u_int8_t  control;
    /* snap */
    u_int8_t  oui[3];
    u_int16_t type;
  } __attribute__ ((__packed__));;
  
  
  /* +++++++++++++++ 802.1Q header (Virtual LAN) +++++++++++++++ */
  struct vlan_hdr
  {
    u_int16_t tci;
    u_int16_t type;
  } __attribute__ ((__packed__));;
  
  
  
  /* +++++++++++++++++++++++ MPLS header +++++++++++++++++++++++ */
  struct mpls_header
  {
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    u_int32_t ttl:8, s:1, exp:3, label:20;
#elif (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
    u_int32_t label:20, exp:3, s:1, ttl:8;
#endif
  } __attribute__((packed));
  
  
  
  /* ++++++++++ Radio Tap header (for IEEE 802.11) with timestamp +++++++++++++ */
  struct radiotap_hdr
  {
    u_int8_t  version;         /* set to 0 */
    u_int8_t  pad;
    u_int16_t len;
    u_int32_t present;
    u_int64_t MAC_timestamp;
    u_int8_t  flags;
  } __attribute__ ((__packed__));;
  
  
  /* ++++++++++++ Wireless header (IEEE 802.11) ++++++++++++++++ */
  struct wifi_hdr
  {
    u_int16_t fc;
    u_int16_t duration;
    u_int8_t  rcvr[6];
    u_int8_t  trsm[6];
    u_int8_t  dest[6];
    u_int16_t seq_ctrl;
    /* u_int64_t ccmp - for data encription only - check fc.flag */
  } __attribute__ ((__packed__));;
  
#ifdef __cplusplus
}
#endif

#endif
