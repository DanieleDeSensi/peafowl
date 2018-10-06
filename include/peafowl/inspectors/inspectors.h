/*
 * inspectors.h
 *
 * =========================================================================
 * Copyright (c) 2012-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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
                   pfwl_dissection_info_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_dhcpv6(const unsigned char* app_data,
                     uint32_t data_length,
                     pfwl_dissection_info_t* pkt_info,
                     pfwl_tracking_informations_t* tracking_info,
                     pfwl_inspector_accuracy_t accuracy,
                     uint8_t* required_fields);

uint8_t check_bgp(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_dns(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_mdns(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_dissection_info_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_ntp(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_http(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_dissection_info_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_sip(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_skype(const unsigned char* app_data,
                    uint32_t data_length,
                    pfwl_dissection_info_t* pkt_info,
                    pfwl_tracking_informations_t* tracking_info,
                    pfwl_inspector_accuracy_t accuracy,
                    uint8_t* required_fields);

uint8_t check_rtp(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_ssh(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_smtp(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_dissection_info_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_pop3(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_dissection_info_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_ssl(const unsigned char* app_data,
                  uint32_t data_length,
                  pfwl_dissection_info_t* pkt_info,
                  pfwl_tracking_informations_t* tracking_info,
                  pfwl_inspector_accuracy_t accuracy,
                  uint8_t* required_fields);

uint8_t check_hangout(const unsigned char* app_data,
                      uint32_t data_length,
                      pfwl_dissection_info_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info,
                      pfwl_inspector_accuracy_t accuracy,
                      uint8_t* required_fields);

uint8_t check_whatsapp(const unsigned char* app_data,
                       uint32_t data_length,
                       pfwl_dissection_info_t* pkt_info,
                       pfwl_tracking_informations_t* tracking_info,
                       pfwl_inspector_accuracy_t accuracy,
                       uint8_t* required_fields);

uint8_t check_telegram(const unsigned char* app_data,
                       uint32_t data_length,
                       pfwl_dissection_info_t* pkt_info,
                       pfwl_tracking_informations_t* tracking_info,
                       pfwl_inspector_accuracy_t accuracy,
                       uint8_t* required_fields);

uint8_t check_imap(const unsigned char* app_data,
                   uint32_t data_length,
                   pfwl_dissection_info_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info,
                   pfwl_inspector_accuracy_t accuracy,
                   uint8_t* required_fields);

uint8_t check_dropbox(const unsigned char* app_data,
                      uint32_t data_length,
                      pfwl_dissection_info_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info,
                      pfwl_inspector_accuracy_t accuracy,
                      uint8_t* required_fields);

uint8_t check_spotify(const unsigned char* app_data,
                      uint32_t data_length,
                      pfwl_dissection_info_t* pkt_info,
                      pfwl_tracking_informations_t* tracking_info,
                      pfwl_inspector_accuracy_t accuracy,
                      uint8_t* required_fields);

uint8_t invoke_callbacks_http(pfwl_state_t* state, pfwl_dissection_info_t* pkt,
                              const unsigned char* app_data,
                              uint32_t data_length,
                              pfwl_tracking_informations_t* tracking);

#endif /* INSPECTORS_H_ */
