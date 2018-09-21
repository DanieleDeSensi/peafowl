/*
 * inspectors.h
 *
 *  Created on: 23/09/2012
 *
 * =========================================================================
 *  Copyright (C) 2012-2013, Daniele De Sensi (d.desensi.software@gmail.com)
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

#ifndef INSPECTORS_H_
#define INSPECTORS_H_
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <peafowl/peafowl.h>
#include <peafowl/flow_table.h>
#include "protocols_identifiers.h"

uint8_t check_dhcp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t);
uint8_t check_dhcpv6(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                     const unsigned char* app_data, uint32_t data_length,
                     pfwl_tracking_informations_t* t);
uint8_t check_bgp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_dns(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_mdns(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t);
uint8_t check_ntp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);

uint8_t check_http(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t);
uint8_t check_sip(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_skype(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                    const unsigned char* app_data, uint32_t data_length,
                    pfwl_tracking_informations_t* t);
uint8_t check_rtp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_ssh(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_smtp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t);
uint8_t check_pop3(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                   const unsigned char* app_data, uint32_t data_length,
                   pfwl_tracking_informations_t* t);
uint8_t check_ssl(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_hangout(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_whatsapp(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_telegram(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_imap(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_dropbox(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);
uint8_t check_spotify(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t);

uint8_t invoke_callbacks_http(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                              const unsigned char* app_data,
                              uint32_t data_length,
                              pfwl_tracking_informations_t* tracking);
uint8_t invoke_callbacks_ssl(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                             const unsigned char* app_data,
                             uint32_t data_length,
                             pfwl_tracking_informations_t* tracking);


#endif /* INSPECTORS_H_ */
