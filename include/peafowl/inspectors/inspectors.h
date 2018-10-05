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

uint8_t check_dhcp(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_dhcpv6(const unsigned char* app_data,
                     uint32_t data_length,
                     pfwl_identification_result_t* pkt_info,
                     pfwl_tracking_informations_t* tracking_info,
                     pfwl_inspector_accuracy_t accuracy,
                     uint8_t* required_fields);

uint8_t check_bgp(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_identification_result_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_dns(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_identification_result_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_mdns(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_ntp(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_identification_result_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_http(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_sip(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_identification_result_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_skype(const unsigned char* app_data,
                    uint32_t data_length,
                    pfwl_identification_result_t* pkt_info,
                    pfwl_tracking_informations_t* tracking_info,
                    pfwl_inspector_accuracy_t accuracy,
                    uint8_t* required_fields);

uint8_t check_rtp(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_identification_result_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_ssh(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_identification_result_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_smtp(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_pop3(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_ssl(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_identification_result_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_hangout(const unsigned char* app_data,
                      uint32_t data_length,
                      pfwl_identification_result_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info,
                      pfwl_inspector_accuracy_t accuracy,
                      uint8_t* required_fields);

uint8_t check_whatsapp(const unsigned char* app_data,
                       uint32_t data_length,
                       pfwl_identification_result_t* pkt_info,
                       pfwl_tracking_informations_t* tracking_info,
                       pfwl_inspector_accuracy_t accuracy,
                       uint8_t* required_fields);

uint8_t check_telegram(const unsigned char* app_data,
                       uint32_t data_length,
                       pfwl_identification_result_t* pkt_info,
                       pfwl_tracking_informations_t* tracking_info,
                       pfwl_inspector_accuracy_t accuracy,
                       uint8_t* required_fields);

uint8_t check_imap(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_dropbox(const unsigned char* app_data,
                      uint32_t data_length,
                      pfwl_identification_result_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info,
                      pfwl_inspector_accuracy_t accuracy,
                      uint8_t* required_fields);

uint8_t check_spotify(const unsigned char* app_data,
                      uint32_t data_length,
                      pfwl_identification_result_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info,
                      pfwl_inspector_accuracy_t accuracy,
                      uint8_t* required_fields);

uint8_t invoke_callbacks_http(pfwl_state_t* state, pfwl_identification_result_t* pkt,
                              const unsigned char* app_data,
                              uint32_t data_length,
                              pfwl_tracking_informations_t* tracking);

#endif /* INSPECTORS_H_ */
