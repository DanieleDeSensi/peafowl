/*
 * inspectors.h
 *
 * =========================================================================
 * Copyright (c) 2012-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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

#ifndef INSPECTORS_H_
#define INSPECTORS_H_
#include "protocols_identifiers.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <peafowl/flow_table.h>
#include <peafowl/peafowl.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif
uint8_t pfwl_protocol_field_required(pfwl_state_t *state,
                                     pfwl_flow_info_private_t* flow_info_private,
                                     pfwl_field_id_t field);
void pfwl_field_string_set(pfwl_field_t *fields, pfwl_field_id_t id,
                           const unsigned char *s, size_t len);
void pfwl_field_number_set(pfwl_field_t *fields, pfwl_field_id_t id,
                           int64_t num);
/**
 * @brief pfwl_array_push_back Pushes a string into an array. The call
 * assumes there is space left in the array. The caller must guarantee that.
 * @param array The array.
 * @param s The string value.
 * @param len The string length.
 */
void pfwl_array_push_back_string(pfwl_array_t *array, const unsigned char *s,
                                 size_t len);

void pfwl_field_array_push_back_string(pfwl_field_t *fields, pfwl_field_id_t id,
                                       const unsigned char *s, size_t len);
void pfwl_field_array_get_length(pfwl_field_t *fields, pfwl_field_id_t id);

uint8_t check_dhcp(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private);

uint8_t check_dhcpv6(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_bgp(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private);

uint8_t check_dns(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private);

uint8_t check_mdns(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private);

uint8_t check_ntp(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private);

uint8_t check_http(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private);

uint8_t check_sip(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private);

uint8_t check_skype(pfwl_state_t *state, const unsigned char *app_data,
                    size_t data_length, pfwl_dissection_info_t *pkt_info,
                    pfwl_flow_info_private_t *flow_info_private);

uint8_t check_rtp(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private);

uint8_t check_ssh(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private);

uint8_t check_smtp(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private);

uint8_t check_pop3(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private);

uint8_t check_ssl(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private);

uint8_t check_rtcp(pfwl_state_t* state, const unsigned char* app_data,
                   size_t data_length, pfwl_dissection_info_t* pkt_info,
                   pfwl_flow_info_private_t* flow_info_private);

uint8_t check_ssh(pfwl_state_t* state, const unsigned char* app_data,
                  size_t data_length, pfwl_dissection_info_t* pkt_info,
                  pfwl_flow_info_private_t* flow_info_private);

uint8_t check_hangout(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private);

uint8_t check_whatsapp(pfwl_state_t *state, const unsigned char *app_data,
                       size_t data_length, pfwl_dissection_info_t *pkt_info,
                       pfwl_flow_info_private_t *flow_info_private);

uint8_t check_telegram(pfwl_state_t *state, const unsigned char *app_data,
                       size_t data_length, pfwl_dissection_info_t *pkt_info,
                       pfwl_flow_info_private_t *flow_info_private);

uint8_t check_imap(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private);

uint8_t check_dropbox(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private);

uint8_t check_spotify(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private);

uint8_t check_bitcoin(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private);

uint8_t check_ethereum(pfwl_state_t *state, const unsigned char *app_data,
                       size_t data_length, pfwl_dissection_info_t *pkt_info,
                       pfwl_flow_info_private_t *flow_info_private);

uint8_t check_zcash(pfwl_state_t *state, const unsigned char *app_data,
                    size_t data_length, pfwl_dissection_info_t *pkt_info,
                    pfwl_flow_info_private_t *flow_info_private);

uint8_t check_monero(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_jsonrpc(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_ssdp(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_stratum(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_stun(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_quic(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_quic5(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_mqtt(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_mysql(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_viber(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_kerberos(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);

uint8_t check_tor(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);  

uint8_t check_git(pfwl_state_t *state, const unsigned char *app_data,
                     size_t data_length, pfwl_dissection_info_t *pkt_info,
                     pfwl_flow_info_private_t *flow_info_private);  
#ifdef __cplusplus
}
#endif
#endif /* INSPECTORS_H_ */
