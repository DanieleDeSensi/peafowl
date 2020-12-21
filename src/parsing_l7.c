/*
 * peafowl_l7_parsing.c
 *
 * Created on: 19/09/2012
 * =========================================================================
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
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define PFWL_DEBUG 0

#define debug_print(fmt, ...)                                              \
  do {                                                                     \
  if (PFWL_DEBUG)                                                          \
  fprintf(stderr, fmt, __VA_ARGS__);                                       \
  } while (0)

// clang-format off
static const pfwl_protocol_l7_t pfwl_known_ports_tcp[PFWL_MAX_UINT_16 + 1] = {
  [0 ... PFWL_MAX_UINT_16] = PFWL_PROTO_L7_UNKNOWN,
  [port_dns] = PFWL_PROTO_L7_DNS,
  [port_http] = PFWL_PROTO_L7_HTTP,
  [port_bgp] = PFWL_PROTO_L7_BGP,
  [port_smtp_1] = PFWL_PROTO_L7_SMTP,
  [port_smtp_2] = PFWL_PROTO_L7_SMTP,
  [port_smtp_ssl] = PFWL_PROTO_L7_SMTP,
  [port_pop3] = PFWL_PROTO_L7_POP3,
  [port_pop3_ssl] = PFWL_PROTO_L7_POP3,
  [port_imap] = PFWL_PROTO_L7_IMAP,
  [port_imap_ssl] = PFWL_PROTO_L7_IMAP,
  [port_ssl] = PFWL_PROTO_L7_SSL,
  [port_tor] = PFWL_PROTO_L7_TOR,
  [port_hangout_19305] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19306] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19307] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19308] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19309] = PFWL_PROTO_L7_HANGOUT,
  [port_ssh] = PFWL_PROTO_L7_SSH,
  [port_bitcoin] = PFWL_PROTO_L7_BITCOIN,
  [port_monero_p2p_1] = PFWL_PROTO_L7_MONERO,
  [port_monero_p2p_2] = PFWL_PROTO_L7_MONERO,
  [port_monero_rpc_1] = PFWL_PROTO_L7_MONERO,
  [port_monero_rpc_2] = PFWL_PROTO_L7_MONERO,
  [port_stun] = PFWL_PROTO_L7_STUN,
  [port_stun_tls] = PFWL_PROTO_L7_STUN,
  [port_mqtt] = PFWL_PROTO_L7_MQTT,
  [port_mqtt_ssl] = PFWL_PROTO_L7_MQTT,
  [port_viber_1] = PFWL_PROTO_L7_VIBER,
  [port_viber_3] = PFWL_PROTO_L7_VIBER,
  [port_viber_4] = PFWL_PROTO_L7_VIBER,
  [port_viber_5] = PFWL_PROTO_L7_VIBER,
  [port_kerberos] = PFWL_PROTO_L7_KERBEROS,
  [port_git] = PFWL_PROTO_L7_GIT,
};

static const pfwl_protocol_l7_t pfwl_known_ports_udp[PFWL_MAX_UINT_16 + 1] = {
  [0 ... PFWL_MAX_UINT_16] = PFWL_PROTO_L7_UNKNOWN,
  [port_dns] = PFWL_PROTO_L7_DNS,
  [port_mdns] = PFWL_PROTO_L7_MDNS,
  [port_dhcp_1] = PFWL_PROTO_L7_DHCP,
  [port_dhcp_2] = PFWL_PROTO_L7_DHCP,
  [port_dhcpv6_1] = PFWL_PROTO_L7_DHCPv6,
  [port_dhcpv6_2] = PFWL_PROTO_L7_DHCPv6,
  [port_sip] = PFWL_PROTO_L7_SIP,
  [port_ntp] = PFWL_PROTO_L7_NTP,
  [port_hangout_19302] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19303] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19304] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19305] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19306] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19307] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19308] = PFWL_PROTO_L7_HANGOUT,
  [port_hangout_19309] = PFWL_PROTO_L7_HANGOUT,
  [port_dropbox] = PFWL_PROTO_L7_DROPBOX,
  [port_spotify] = PFWL_PROTO_L7_SPOTIFY,
  [port_ssdp] = PFWL_PROTO_L7_SSDP,
  [port_stun] = PFWL_PROTO_L7_STUN,
  [port_viber_1] = PFWL_PROTO_L7_VIBER,
  [port_viber_2] = PFWL_PROTO_L7_VIBER,
  [port_viber_3] = PFWL_PROTO_L7_VIBER,
  [port_viber_4] = PFWL_PROTO_L7_VIBER,
  [port_viber_5] = PFWL_PROTO_L7_VIBER,
  [port_kerberos] = PFWL_PROTO_L7_KERBEROS,
};
// clang-format on

typedef enum {
  PFWL_L7_TRANSPORT_TCP = 0,
  PFWL_L7_TRANSPORT_UDP,
  PFWL_L7_TRANSPORT_TCP_OR_UDP,
} pfwl_l7_transport_t;

/**
 * @brief A generic protocol dissector.
 * A generic protocol dissector.
 * @param state               A pointer to the peafowl internal state
 * @param app_data            A pointer to the application payload.
 * @param data_length         The length of the application payload.
 * @param identification_info Info about the identification done up to now (up
 * to L4 parsing).
 * @param flow_info_private   A pointer to the private flow information.
 * @return               PFWL_PROTOCOL_MATCHES if the protocol matches.
 *                       PFWL_PROTOCOL_NO_MATCHES if the protocol doesn't
 *                       matches.
 *                       PFWL_PROTOCOL_MORE_DATA_NEEDED if the dissector
 *                       needs more data to decide.
 *                       PFWL_ERROR if an error occurred.
 */
typedef uint8_t (*pfwl_dissector)(pfwl_state_t *state,
                                  const unsigned char *app_data,
                                  size_t data_length,
                                  pfwl_dissection_info_t *identification_info,
                                  pfwl_flow_info_private_t *flow_info_private);

typedef struct {
  const char *name;
  pfwl_dissector dissector;
  pfwl_l7_transport_t transport;
  pfwl_field_id_t* dependencies_fields;       ///< Fields (of other protocols) needed to identify this protocol. Last value in the array must always be PFWL_FIELDS_L7_NUM
} pfwl_protocol_descriptor_t;

static pfwl_field_id_t dep_fields_ethereum[]   = {PFWL_FIELDS_L7_JSON_RPC_METHOD, PFWL_FIELDS_L7_NUM};
static pfwl_field_id_t dep_fields_zcash[]      = {PFWL_FIELDS_L7_JSON_RPC_METHOD, PFWL_FIELDS_L7_NUM};
static pfwl_field_id_t dep_fields_monero[]     = {PFWL_FIELDS_L7_JSON_RPC_METHOD, PFWL_FIELDS_L7_NUM};
static pfwl_field_id_t dep_fields_stratum[]    = {PFWL_FIELDS_L7_JSON_RPC_METHOD, PFWL_FIELDS_L7_NUM};
static pfwl_field_id_t dep_fields_json_rpc[]   = {PFWL_FIELDS_L7_HTTP_HEADERS, PFWL_FIELDS_L7_HTTP_BODY, PFWL_FIELDS_L7_NUM};

// clang-format off
static const pfwl_protocol_descriptor_t protocols_descriptors[PFWL_PROTO_L7_NUM] = {
  [PFWL_PROTO_L7_DHCP]     = {"DHCP"    , check_dhcp    , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_DHCPv6]   = {"DHCPv6"  , check_dhcpv6  , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_DNS]      = {"DNS"     , check_dns     , PFWL_L7_TRANSPORT_TCP_OR_UDP, NULL},
  [PFWL_PROTO_L7_MDNS]     = {"MDNS"    , check_mdns    , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_SIP]      = {"SIP"     , check_sip     , PFWL_L7_TRANSPORT_TCP_OR_UDP, NULL},
  [PFWL_PROTO_L7_RTP]      = {"RTP"     , check_rtp     , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_RTCP]     = {"RTCP"    , check_rtcp    , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_SSH]      = {"SSH"     , check_ssh     , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_SKYPE]    = {"Skype"   , check_skype   , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_NTP]      = {"NTP"     , check_ntp     , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_BGP]      = {"BGP"     , check_bgp     , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_HTTP]     = {"HTTP"    , check_http    , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_SMTP]     = {"SMTP"    , check_smtp    , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_POP3]     = {"POP3"    , check_pop3    , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_IMAP]     = {"IMAP"    , check_imap    , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_SSL]      = {"SSL"     , check_ssl     , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_HANGOUT]  = {"Hangout" , check_hangout , PFWL_L7_TRANSPORT_TCP_OR_UDP, NULL},
  [PFWL_PROTO_L7_WHATSAPP] = {"WhatsApp", check_whatsapp, PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_TELEGRAM] = {"Telegram", check_telegram, PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_DROPBOX]  = {"Dropbox" , check_dropbox , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_SPOTIFY]  = {"Spotify" , check_spotify , PFWL_L7_TRANSPORT_TCP_OR_UDP, NULL},
  [PFWL_PROTO_L7_BITCOIN]  = {"Bitcoin" , check_bitcoin , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_ETHEREUM] = {"Ethereum", check_ethereum, PFWL_L7_TRANSPORT_TCP       , dep_fields_ethereum},
  [PFWL_PROTO_L7_ZCASH]    = {"Zcash"   , check_zcash   , PFWL_L7_TRANSPORT_TCP       , dep_fields_zcash},
  [PFWL_PROTO_L7_MONERO]   = {"Monero"  , check_monero  , PFWL_L7_TRANSPORT_TCP       , dep_fields_monero},
  [PFWL_PROTO_L7_STRATUM]  = {"Stratum" , check_stratum , PFWL_L7_TRANSPORT_TCP       , dep_fields_stratum},
  [PFWL_PROTO_L7_JSON_RPC] = {"JSON-RPC", check_jsonrpc , PFWL_L7_TRANSPORT_TCP_OR_UDP, dep_fields_json_rpc},
  [PFWL_PROTO_L7_SSDP]     = {"SSDP"    , check_ssdp    , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_STUN]     = {"STUN"    , check_stun    , PFWL_L7_TRANSPORT_TCP_OR_UDP, NULL},
  [PFWL_PROTO_L7_QUIC]     = {"QUIC"    , check_quic    , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_QUIC5]    = {"QUIC5"   , check_quic5   , PFWL_L7_TRANSPORT_UDP       , NULL},
  [PFWL_PROTO_L7_MQTT]     = {"MQTT"    , check_mqtt    , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_MYSQL]    = {"MySQL"   , check_mysql   , PFWL_L7_TRANSPORT_TCP       , NULL},
	[PFWL_PROTO_L7_VIBER]    = {"Viber"   , check_viber   , PFWL_L7_TRANSPORT_TCP_OR_UDP, NULL},
  [PFWL_PROTO_L7_KERBEROS] = {"Kerberos", check_kerberos, PFWL_L7_TRANSPORT_TCP_OR_UDP, NULL},
	[PFWL_PROTO_L7_TOR]      = {"Tor"     , check_tor     , PFWL_L7_TRANSPORT_TCP       , NULL},
  [PFWL_PROTO_L7_GIT]      = {"Git"     , check_git     , PFWL_L7_TRANSPORT_TCP       , NULL}
};
    
typedef struct {
  pfwl_protocol_l7_t protocol;
  const char* name;
  pfwl_field_type_t type;
  const char* description;
} pfwl_field_L7_descriptor_t;

//--PROTOFIELDSTART
static const pfwl_field_L7_descriptor_t field_L7_descriptors[] = {
  {PFWL_PROTO_L7_SIP     , "REQUEST_URI",                PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "METHOD",                     PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "CALLID",                     PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "REASON",                     PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "RTCPXR_CALLID",              PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "CSEQ",                       PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "CSEQ_METHOD_STRING",         PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "VIA",                        PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "CONTACT_URI",                PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "RURI_USER",                  PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "RURI_DOMAIN",                PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "FROM_USER",                  PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "FROM_DOMAIN",                PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "TO_USER",                    PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "TO_DOMAIN",                  PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "PAI_USER",                   PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "PAI_DOMAIN",                 PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "PID_URI",                    PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "FROM_URI",                   PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "TO_URI",                     PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "RURI_URI",                   PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "TO_TAG",                     PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_SIP     , "FROM_TAG",                   PFWL_FIELD_TYPE_STRING, ""},
  {PFWL_PROTO_L7_DNS     , "NAME_SRV",                   PFWL_FIELD_TYPE_STRING, "Server name"},
  {PFWL_PROTO_L7_DNS     , "NS_IP_1",                    PFWL_FIELD_TYPE_STRING, "Server name IP address"},
  {PFWL_PROTO_L7_DNS     , "NS_IP_2",                    PFWL_FIELD_TYPE_STRING, "Server name IP address"},
  {PFWL_PROTO_L7_DNS     , "AUTH_SRV",                   PFWL_FIELD_TYPE_STRING, "Authority name"},
  {PFWL_PROTO_L7_SSL     , "VERSION",                    PFWL_FIELD_TYPE_NUMBER, "SSL Version"},
  {PFWL_PROTO_L7_SSL     , "VERSION_HANDSHAKE",          PFWL_FIELD_TYPE_NUMBER, "SSL Handshake Version (for client and server hellos)"},
  {PFWL_PROTO_L7_SSL     , "HANDSHAKE_TYPE",             PFWL_FIELD_TYPE_NUMBER, "SSL Handshake type"},
  {PFWL_PROTO_L7_SSL     , "CIPHER_SUITES",              PFWL_FIELD_TYPE_STRING, "Cypher Suites, dash separated (grease extensions removed)"},
  {PFWL_PROTO_L7_SSL     , "EXTENSIONS",                 PFWL_FIELD_TYPE_STRING, "Extensions, dash separated (grease extensions removed)"},
  {PFWL_PROTO_L7_SSL     , "ELLIPTIC_CURVES",            PFWL_FIELD_TYPE_STRING, "Supported elliptic curves, dash separated (grease extensions removed)"},
  {PFWL_PROTO_L7_SSL     , "ELLIPTIC_CURVES_POINT_FMTS", PFWL_FIELD_TYPE_STRING, "Supported elliptic curves point formats, dash separated  (grease extensions removed)"},
  {PFWL_PROTO_L7_SSL     , "SNI",                        PFWL_FIELD_TYPE_STRING, "Server name extension found in client certificate"},
  {PFWL_PROTO_L7_SSL     , "CERTIFICATE",                PFWL_FIELD_TYPE_STRING, "Server name found in server certificate"},  
  {PFWL_PROTO_L7_SSL     , "JA3",                        PFWL_FIELD_TYPE_STRING, "SSL JA3 Fingerprint (https://github.com/salesforce/ja3). If HANDSHAKE_TYPE == 0x01, this is the client side JA3, if HANDSHAKE_TYPE == 0x02, this is the server side JA3S."},
  {PFWL_PROTO_L7_HTTP    , "VERSION_MAJOR",              PFWL_FIELD_TYPE_NUMBER, "HTTP Version - Major"},
  {PFWL_PROTO_L7_HTTP    , "VERSION_MINOR",              PFWL_FIELD_TYPE_NUMBER, "HTTP Version - Minor"},
  {PFWL_PROTO_L7_HTTP    , "METHOD",                     PFWL_FIELD_TYPE_NUMBER, "HTTP Method. For the possible values, please check HTTP_METHOD_MAP in file include/peafowl/inspectors/http_parser_joyent.h"},
  {PFWL_PROTO_L7_HTTP    , "STATUS_CODE",                PFWL_FIELD_TYPE_NUMBER, "HTTP Status code"},
  {PFWL_PROTO_L7_HTTP    , "MSG_TYPE",                   PFWL_FIELD_TYPE_NUMBER, "HTTP request or response. For the possible values, please check pfwl_http_message_type_t enumeration in file include/peafowl/inspectors/http_parser_joyent.h"},
  {PFWL_PROTO_L7_HTTP    , "BODY",                       PFWL_FIELD_TYPE_STRING, "HTTP Body"},
  {PFWL_PROTO_L7_HTTP    , "URL",                        PFWL_FIELD_TYPE_STRING, "HTTP URL"},
  {PFWL_PROTO_L7_HTTP    , "HEADERS",                    PFWL_FIELD_TYPE_MMAP  , "HTTP headers"},
  {PFWL_PROTO_L7_RTP     , "PTYPE",                      PFWL_FIELD_TYPE_NUMBER, "RTP Payload Type"},
  {PFWL_PROTO_L7_RTP     , "SEQNUM",                     PFWL_FIELD_TYPE_NUMBER, "RTP Sequence Number"},
  {PFWL_PROTO_L7_RTP     , "TIMESTP",                    PFWL_FIELD_TYPE_NUMBER, "RTP Timestamp"},
  {PFWL_PROTO_L7_RTP     , "SSRC",                       PFWL_FIELD_TYPE_NUMBER, "RTP Syncronization Source Identifier (Host byte order)"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_ALL",                 PFWL_FIELD_TYPE_NUMBER, "To extract all the Sender fields"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_SSRC",                PFWL_FIELD_TYPE_NUMBER, "RTCP Sender SSRC"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_TIME_MSW",            PFWL_FIELD_TYPE_NUMBER, "RTCP Sender timestamp MSW"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_TIME_LSW",            PFWL_FIELD_TYPE_NUMBER, "RTCP Sender timestamp LSW"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_TIME_RTP",            PFWL_FIELD_TYPE_NUMBER, "RTCP Sender timestamp RTP"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_PKT_COUNT",           PFWL_FIELD_TYPE_NUMBER, "RTCP Sender packet count"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_OCT_COUNT",           PFWL_FIELD_TYPE_NUMBER, "RTCP Sender octet count"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_ID",                  PFWL_FIELD_TYPE_NUMBER, "RTCP Sender Identifier"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_FLCNPL",              PFWL_FIELD_TYPE_NUMBER, "RTCP Sender Fraction lost + Cumulative pkt lost"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_EXT_SEQN_RCV",        PFWL_FIELD_TYPE_NUMBER, "RTCP Sender Extended highest sequence number received"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_INT_JITTER",          PFWL_FIELD_TYPE_NUMBER, "RTCP Sender Interarrival Jitter"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_LSR",                 PFWL_FIELD_TYPE_NUMBER, "RTCP Sender Last SR timestamp"},
  {PFWL_PROTO_L7_RTCP    , "SENDER_DELAY_LSR",           PFWL_FIELD_TYPE_NUMBER, "RTCP Sender Delay last SR timestamp"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_ALL",               PFWL_FIELD_TYPE_NUMBER, "To extract all the Receiver fields"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_SSRC",              PFWL_FIELD_TYPE_NUMBER, "RTCP Receiver SSRC"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_ID",                PFWL_FIELD_TYPE_NUMBER, "RTCP Receiver Identifier"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_FLCNPL",            PFWL_FIELD_TYPE_NUMBER, "RTCP Receiver Fraction lost + Cumulative pkt lost"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_EXT_SEQN_RCV",      PFWL_FIELD_TYPE_NUMBER, "RTCP Receiver Extended highest sequence number received"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_INT_JITTER",        PFWL_FIELD_TYPE_NUMBER, "RTCP Receiver Interarrival Jitter"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_LSR",               PFWL_FIELD_TYPE_NUMBER, "RTCP Receiver Last SR timestamp"},
  {PFWL_PROTO_L7_RTCP    , "RECEIVER_DELAY_LSR",         PFWL_FIELD_TYPE_NUMBER, "RTCP Receiver Delay last SR timestamp"},
  {PFWL_PROTO_L7_RTCP    , "SDES_CSRC",                  PFWL_FIELD_TYPE_NUMBER, "RTCP Source description CSRC ID"},
  {PFWL_PROTO_L7_RTCP    , "SDES_TEXT",                  PFWL_FIELD_TYPE_STRING, "RTCP Source description Text"},
  {PFWL_PROTO_L7_JSON_RPC, "FIRST",                      PFWL_FIELD_TYPE_NUMBER, "Dummy value to mark first JSON RPC field."},
  {PFWL_PROTO_L7_JSON_RPC, "VERSION",                    PFWL_FIELD_TYPE_NUMBER, "JSON-RPC version."},
  {PFWL_PROTO_L7_JSON_RPC, "MSG_TYPE",                   PFWL_FIELD_TYPE_NUMBER, "Msg type. 0 = Request, 1 = Response, 2 = Notification."},
  {PFWL_PROTO_L7_JSON_RPC, "ID",                         PFWL_FIELD_TYPE_STRING, "Id field."},
  {PFWL_PROTO_L7_JSON_RPC, "METHOD",                     PFWL_FIELD_TYPE_STRING, "Method field."},
  {PFWL_PROTO_L7_JSON_RPC, "PARAMS",                     PFWL_FIELD_TYPE_STRING, "Params field."},
  {PFWL_PROTO_L7_JSON_RPC, "RESULT",                     PFWL_FIELD_TYPE_STRING, "Result field."},
  {PFWL_PROTO_L7_JSON_RPC, "ERROR",                      PFWL_FIELD_TYPE_STRING, "Error field."},
  {PFWL_PROTO_L7_JSON_RPC, "LAST",                       PFWL_FIELD_TYPE_NUMBER, "Dummy value to mark last JSON RPC field."},
  {PFWL_PROTO_L7_QUIC    , "VERSION",                    PFWL_FIELD_TYPE_STRING, "Version."},
  {PFWL_PROTO_L7_QUIC    , "SNI",                        PFWL_FIELD_TYPE_STRING, "Server Name Indication."},
  {PFWL_PROTO_L7_QUIC    , "UAID",                       PFWL_FIELD_TYPE_STRING, "User Agent Identifier."},
  {PFWL_PROTO_L7_QUIC    , "JA3",                        PFWL_FIELD_TYPE_STRING, "Quic/TLS JA3 Fingerprint (https://github.com/salesforce/ja3)"},
  {PFWL_PROTO_L7_STUN    , "MAPPED_ADDRESS",             PFWL_FIELD_TYPE_STRING, "Mapped address (or xor-mapped address) (format x.y.z.w for IPv4 and a:b:c:d:e:f:g:h for IPv6)."},
  {PFWL_PROTO_L7_STUN    , "MAPPED_ADDRESS_PORT",        PFWL_FIELD_TYPE_NUMBER, "Mapped address port (or xor-mapped port) ."},
  {PFWL_PROTO_L7_NUM     , "NUM",                        PFWL_FIELD_TYPE_STRING, "Dummy value to indicate number of fields. Must be the last field specified."},
};
//--PROTOFIELDEND
// clang-format on

static int inspect_protocol(pfwl_protocol_l4_t protocol_l4,
                            const pfwl_protocol_descriptor_t *descr) {
  return descr->transport == PFWL_L7_TRANSPORT_TCP_OR_UDP ||
      (protocol_l4 == IPPROTO_TCP &&
       descr->transport == PFWL_L7_TRANSPORT_TCP) ||
      (protocol_l4 == IPPROTO_UDP &&
       descr->transport == PFWL_L7_TRANSPORT_UDP);
}

void pfwl_dissect_L7_sub(pfwl_state_t *state, const unsigned char *pkt,
                         size_t length, pfwl_dissection_info_t *diss_info,
                         pfwl_flow_info_private_t *flow_info_private) {
  const pfwl_protocol_l7_t *well_known_ports;
  pfwl_protocol_l7_t i;
  uint8_t check_result = PFWL_PROTOCOL_NO_MATCHES;

  if (!flow_info_private->identification_terminated) {
    // Set next protocol as not yet determined
    flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num] = PFWL_PROTO_L7_NOT_DETERMINED;
    debug_print("%s\n", "Still some protocols to identify.");
    if (diss_info->l4.protocol == IPPROTO_TCP) {
      well_known_ports = pfwl_known_ports_tcp;
    } else {
      well_known_ports = pfwl_known_ports_udp;
    }

    pfwl_protocol_l7_t first_to_check;
    pfwl_protocol_l7_t checked = 0;

    if ((first_to_check = well_known_ports[diss_info->l4.port_src]) ==
        PFWL_PROTO_L7_UNKNOWN &&
        (first_to_check = well_known_ports[diss_info->l4.port_dst]) ==
        PFWL_PROTO_L7_UNKNOWN) {
      first_to_check = 0;
    }

    for (i = first_to_check; checked < PFWL_PROTO_L7_NUM;
         i = (i + 1) % PFWL_PROTO_L7_NUM, ++checked) {
      if (BITTEST(flow_info_private->possible_matching_protocols, i)) {
        pfwl_protocol_descriptor_t descr = protocols_descriptors[i];
        if (inspect_protocol(diss_info->l4.protocol, &descr)) {
          debug_print("Checking: %s, possible matches %d\n", pfwl_get_L7_protocol_name(i), flow_info_private->possible_protocols);
          check_result = (*(descr.dissector))(state, pkt, length, diss_info,
                                              flow_info_private);
          if (check_result == PFWL_PROTOCOL_MATCHES) {
            flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num++] = i;

            // Reset values
            if(state->protocol_dependencies[i]){
              for(size_t j = 0; j < PFWL_PROTO_L7_NUM; j++){
                BITCLEAR(flow_info_private->possible_matching_protocols, j);
              }
              flow_info_private->trials = state->max_trials;

              size_t j = 0;
              flow_info_private->possible_protocols = 0;
              pfwl_protocol_l7_t dep;
              while((dep = state->protocol_dependencies[i][j]) != PFWL_PROTO_L7_NUM){
                if(BITTEST(state->protocols_to_inspect, dep)){
                  BITSET(flow_info_private->possible_matching_protocols, dep);
                }
                ++j;
              }
              flow_info_private->possible_protocols = j;
              debug_print("%s\n", "Going to dissect sub protocols.");
              pfwl_dissect_L7_sub(state, pkt, length, diss_info, flow_info_private);
            }else{
              debug_print("%s\n", "Marking identification as terminated.");
              flow_info_private->identification_terminated = 1;
              flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num] = PFWL_PROTO_L7_UNKNOWN;
              if(!flow_info_private->info_public->protocols_l7_num){
                ++flow_info_private->info_public->protocols_l7_num;
              }
            }
            break;
          } else if (check_result == PFWL_PROTOCOL_NO_MATCHES) {
            BITCLEAR(flow_info_private->possible_matching_protocols, i);
            --(flow_info_private->possible_protocols);
          }
        } else {
          BITCLEAR(flow_info_private->possible_matching_protocols, i);
          --(flow_info_private->possible_protocols);
        }
      }
    }
  }
}

static int8_t pfwl_keep_inspecting(pfwl_state_t* state, pfwl_flow_info_private_t *flow_info_private,
                                   pfwl_protocol_l7_t protocol){
  if(flow_info_private->info_public->protocols_l7_num &&
     flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] == PFWL_PROTO_L7_UNKNOWN){
    return state->fields_to_extract_num[protocol];
  }else{
    return state->fields_support_num[protocol] || state->fields_to_extract_num[protocol];
  }
}

const char* pfwl_field_string_tag_get(void* db, pfwl_string_t* value);
const char* pfwl_field_mmap_tag_get(void* db, pfwl_string_t* key, pfwl_string_t* value);

pfwl_status_t pfwl_dissect_L7(pfwl_state_t *state, const unsigned char *pkt,
                              size_t length, pfwl_dissection_info_t *diss_info,
                              pfwl_flow_info_private_t *flow_info_private) {
  debug_print("%s\n", "Going to dissect L7.");
  state->scratchpad_next_byte = 0;
  ++((pfwl_flow_info_t *) flow_info_private->info_public)
      ->num_packets_l7[diss_info->l4.direction];
  ((pfwl_flow_info_t *) flow_info_private->info_public)
      ->num_bytes_l7[diss_info->l4.direction] += length;
  ++((pfwl_flow_info_t *) flow_info_private->info_public)
      ->statistics[PFWL_STAT_L7_PACKETS][diss_info->l4.direction];
  ((pfwl_flow_info_t *) flow_info_private->info_public)
      ->statistics[PFWL_STAT_L7_BYTES][diss_info->l4.direction] += length;

  diss_info->flow_info.num_packets_l7[diss_info->l4.direction] =
      flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][diss_info->l4.direction];
  diss_info->flow_info.num_bytes_l7[diss_info->l4.direction] =
      flow_info_private->info_public->statistics[PFWL_STAT_L7_BYTES][diss_info->l4.direction];

  diss_info->flow_info.statistics[PFWL_STAT_L7_PACKETS][diss_info->l4.direction] =
      flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][diss_info->l4.direction];
  diss_info->flow_info.statistics[PFWL_STAT_L7_BYTES][diss_info->l4.direction] =
      flow_info_private->info_public->statistics[PFWL_STAT_L7_BYTES][diss_info->l4.direction];

  if ((diss_info->l4.protocol == IPPROTO_TCP && !state->active_protocols[0]) ||
      (diss_info->l4.protocol == IPPROTO_UDP && !state->active_protocols[1])) {
    return PFWL_STATUS_OK;
  }

  // Extract the fields for all the protocols we identified
  pfwl_protocol_descriptor_t descr;
  for(size_t i = 0; i < diss_info->l7.protocols_num; i++){
    pfwl_protocol_l7_t proto = diss_info->l7.protocols[i];
    if (proto < PFWL_PROTO_L7_NOT_DETERMINED &&
        pfwl_keep_inspecting(state, flow_info_private, proto)) {
      debug_print("Extracting fields for protocol %d\n", proto);
      descr = protocols_descriptors[proto];
      (*(descr.dissector))(state, pkt, length, diss_info, flow_info_private);
    }
  }

  if(!flow_info_private->info_public->protocols_l7_num ||
     flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num - 1] != PFWL_PROTO_L7_UNKNOWN){
    pfwl_dissect_L7_sub(state, pkt, length, diss_info, flow_info_private);

    /**
     * If all the protocols don't match or if we still have
     * ambiguity after the maximum number of trials, then the
     * library was unable to identify the protocol.
     **/
    if (flow_info_private->possible_protocols == 0 ||
        (state->max_trials &&
         unlikely(++flow_info_private->trials == state->max_trials))) {
      
      flow_info_private->identification_terminated = 1;

      pfwl_protocol_l7_t guessed = PFWL_PROTO_L7_UNKNOWN;
      if(!flow_info_private->info_public->protocols_l7_num){
          guessed = pfwl_guess_protocol(*diss_info);
      }
      if(guessed != PFWL_PROTO_L7_UNKNOWN){
        flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num++] = guessed;
      }else{
        flow_info_private->info_public->protocols_l7[flow_info_private->info_public->protocols_l7_num] = PFWL_PROTO_L7_UNKNOWN;
        if(!flow_info_private->info_public->protocols_l7_num){
          ++flow_info_private->info_public->protocols_l7_num;
        }
      }
    }
  }

  for(size_t i = 0; i < flow_info_private->info_public->protocols_l7_num; i++){
    diss_info->l7.protocols[i] = flow_info_private->info_public->protocols_l7[i];
  }
  diss_info->l7.protocols_num = flow_info_private->info_public->protocols_l7_num;
  diss_info->l7.protocol = flow_info_private->info_public->protocols_l7[0];

  // Set tags
  if(state->tags_matchers_num){
    for(size_t i = 0; i < PFWL_FIELDS_L7_NUM; i++){
      pfwl_field_t field = diss_info->l7.protocol_fields[i];
      if(state->tags_matchers[i] &&
         field.present){

        if(pfwl_get_L7_field_type(i) == PFWL_FIELD_TYPE_STRING){
          const char* tag = pfwl_field_string_tag_get(state->tags_matchers[i], &field.basic.string);
          if(tag){
            diss_info->l7.tags[diss_info->l7.tags_num++] = tag;
            if(diss_info->l7.tags_num == PFWL_TAGS_MAX){
              break;
            }
          }
        }else if(pfwl_get_L7_field_type(i) == PFWL_FIELD_TYPE_MMAP){
          for(size_t j = 0; j < field.mmap.length; j++){
            pfwl_pair_t pair = ((pfwl_pair_t*)field.mmap.values)[j];
            const char* tag = pfwl_field_mmap_tag_get(state->tags_matchers[i], &pair.first.string, &pair.second.string);
            if(tag){
              diss_info->l7.tags[diss_info->l7.tags_num++] = tag;
              if(diss_info->l7.tags_num == PFWL_TAGS_MAX){
                break;
              }
            }
          }
        }
      }
    }
  }

  diss_info->flow_info = *flow_info_private->info_public; // To be DEPRECATED. flow_info should become a pointer to avoid copying
  return PFWL_STATUS_OK;
}

// TODO: Deprecate and pass reference or pointer
pfwl_protocol_l7_t
pfwl_guess_protocol(pfwl_dissection_info_t identification_info) {
  pfwl_protocol_l7_t r = PFWL_PROTO_L7_UNKNOWN;
  if (identification_info.l4.protocol == IPPROTO_TCP) {
    r = pfwl_known_ports_tcp[identification_info.l4.port_src];
    if (r == PFWL_PROTO_L7_UNKNOWN)
      r = pfwl_known_ports_tcp[identification_info.l4.port_dst];
  } else if (identification_info.l4.protocol == IPPROTO_UDP) {
    r = pfwl_known_ports_udp[identification_info.l4.port_src];
    if(r == PFWL_PROTO_L7_UNKNOWN){
      r = pfwl_known_ports_udp[identification_info.l4.port_dst];
    }
  } else {
    r = PFWL_PROTO_L7_UNKNOWN;
  }
  return r;
}

const char *pfwl_get_L7_protocol_name(pfwl_protocol_l7_t protocol) {
  if (protocol < PFWL_PROTO_L7_NUM) {
    return protocols_descriptors[protocol].name;
  } else {
    return "Unknown";
  }
}

pfwl_protocol_l7_t pfwl_get_L7_protocol_id(const char *const string) {
  size_t i;
  for (i = 0; i < (size_t) PFWL_PROTO_L7_NUM; i++) {
    if (!strcasecmp(string, protocols_descriptors[i].name)) {
      return (pfwl_protocol_l7_t) i;
    }
  }
  return PFWL_PROTO_L7_NUM;
}

static const char *protocols_strings[PFWL_PROTO_L7_NUM];

const char **const pfwl_get_L7_protocols_names() {
  size_t i;
  for (i = 0; i < (size_t) PFWL_PROTO_L7_NUM; i++) {
    protocols_strings[i] = protocols_descriptors[i].name;
  }
  return protocols_strings;
}

uint8_t pfwl_field_add_L7_internal(pfwl_state_t *state, pfwl_field_id_t field,
                                   uint8_t* fields_to_extract, uint8_t* fields_to_extract_num);

pfwl_protocol_l7_t pfwl_get_L7_field_protocol(pfwl_field_id_t field) {
  return field_L7_descriptors[field].protocol;
}

uint8_t pfwl_protocol_l7_enable(pfwl_state_t *state,
                                pfwl_protocol_l7_t protocol) {
  if (state && protocol < PFWL_PROTO_L7_NUM) {
    pfwl_protocol_descriptor_t descr = protocols_descriptors[protocol];
    // Increment counter only if it was not set, otherwise
    // calling twice enable_protocol on the same protocol
    // would lead to a wrong number of active protocols
    if (!BITTEST(state->protocols_to_inspect, protocol)) {
      if (descr.transport == PFWL_L7_TRANSPORT_TCP ||
          descr.transport == PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        ++state->active_protocols[0];
      }
      if (descr.transport == PFWL_L7_TRANSPORT_UDP ||
          descr.transport == PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        ++state->active_protocols[1];
      }

      // Enable dependent fields and build dependencies array
      if(descr.dependencies_fields){
        size_t i = 0;
        uint8_t dependencies[PFWL_PROTO_L7_NUM];
        memset(dependencies, 0, sizeof(dependencies));
        while(descr.dependencies_fields[i] != PFWL_FIELDS_L7_NUM){
          pfwl_field_id_t field = descr.dependencies_fields[i];
          pfwl_protocol_l7_t dep_protocol = pfwl_get_L7_field_protocol(field);
          dependencies[dep_protocol] = 1;
          pfwl_field_add_L7_internal(state, field, state->fields_support, state->fields_support_num);
          ++i;
        }

        for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
          if(dependencies[i]){
            // If dependencies[i] == 1, 'protocol' depends on i
            // Add this protocol to protocols depending on protocol i
            for(size_t j = 0; j < PFWL_PROTO_L7_NUM; j++){
              if(state->protocol_dependencies[i][j] == PFWL_PROTO_L7_NUM){
                state->protocol_dependencies[i][j] = protocol;
                state->protocol_dependencies[i][j + 1] = PFWL_PROTO_L7_NUM;
                break;
              }
            }
          }
        }
      }
    }
    BITSET(state->protocols_to_inspect, protocol);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_protocol_l7_disable(pfwl_state_t *state,
                                 pfwl_protocol_l7_t protocol) {
  if (state && protocol < PFWL_PROTO_L7_NUM) {
    // Decrement counter only if it was set, otherwise
    // calling twice disable_protocol on the same protocol
    // would lead to a wrong number of active protocols
    if (BITTEST(state->protocols_to_inspect, protocol)) {
      if (protocols_descriptors[protocol].transport == PFWL_L7_TRANSPORT_TCP ||
          protocols_descriptors[protocol].transport ==
          PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        --state->active_protocols[0];
      }
      if (protocols_descriptors[protocol].transport == PFWL_L7_TRANSPORT_UDP ||
          protocols_descriptors[protocol].transport ==
          PFWL_L7_TRANSPORT_TCP_OR_UDP) {
        --state->active_protocols[1];
      }
    }
    BITCLEAR(state->protocols_to_inspect, protocol);
    return 0;
  } else {
    return 1;
  }
}

uint8_t pfwl_protocol_l7_enable_all(pfwl_state_t *state) {
  for (size_t i = 0; i < PFWL_PROTO_L7_NUM; i++) {
    if (pfwl_protocol_l7_enable(state, i)) {
      return 1;
    }
  }
  return 0;
}

uint8_t pfwl_protocol_l7_disable_all(pfwl_state_t *state) {
  for (size_t i = 0; i < PFWL_PROTO_L7_NUM; i++) {
    if (pfwl_protocol_l7_disable(state, i)) {
      return 1;
    }
  }
  return 0;
}

uint8_t pfwl_set_timestamp_unit(pfwl_state_t *state, pfwl_timestamp_unit_t unit){
  state->ts_unit = unit;
  return 0;
}

pfwl_field_type_t pfwl_get_L7_field_type(pfwl_field_id_t field){
  return field_L7_descriptors[field].type;
}

const char* pfwl_get_L7_field_name(pfwl_field_id_t field){
   return field_L7_descriptors[field].name;
}

pfwl_field_id_t pfwl_get_L7_field_id(pfwl_protocol_l7_t protocol, const char* field_name){
  for(size_t i = 0; i < PFWL_FIELDS_L7_NUM; i++){
    if(field_L7_descriptors[i].protocol == protocol && !strcmp(field_name, field_L7_descriptors[i].name)){
      return (pfwl_field_id_t) i;
    }    
  }
  return PFWL_FIELDS_L7_NUM;
}
