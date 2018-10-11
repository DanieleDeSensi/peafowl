/**
 * peafowl.h
 *
 * @file
 * @brief This is the main peafowl header.
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
 *
 * Peafowl is a flexible and extensible DPI framework which can be used to identify the application protocols
 * carried by IP (IPv4 and IPv6) packets and to extract and process data and metadata carried by those protocols.
 *
 * For example, is possible to write applications that process any possible kind of data and metadata carried by an
 * HTTP connection (e.g. Host, User-Agent, Content-Type, HTTP body, etc..). It's important to notice that the
 * application programmer needs only to focus on the way these information are processed, since their extraction
 * is completely and transparently performed by the framework. Accordingly, using Peafowl is possible to implement
 * different kinds of applications like:
 *
 * + URL filtering (for parental control or access control)
 * + User-Agent or Content-Type filtering (e.g. block traffic for mobile users, block video traffic, etc...)
 * + Security controls (e.g. block the traffic containing some malicious signatures or patterns)
 * + Data leak prevention
 * + Quality of Service and Traffic shaping (e.g. to give higher priority to VoIP traffic)
 *
 * Peafowl is not tied to any specific technology for packet capture. Accordingly, you can capture the packets using
 * pcap, sockets, PF_RING or whatever technology you prefer.
 *
 * To correctly identify the protocol also when its data is split among multiple IP fragments and/or TCP segments
 * and to avoid the possibility of evasion attacks, if required, the framework can perform IP defragmentation and
 * TCP stream reassembly.
 *
 *
 * Main features:
 *
 *  + Protocol identification and extraction of application level protocol fields.
 *
 * 	+ Support for IPv6 and tunneling: 6in6, 4in4, 6in4, 4in6
 *
 * 	+ Robust IPv4 and IPv6 defragmentation support tested against a
 * 	 large number of possible attacks.
 *
 * 	+ TCP stream reassembly.
 *
 * 	+ Possibility to decide at a fine grain which protocol fields should be extracted.
 *
 *  + The framework can be used in two different modes: stateful (by default) and stateless.
 *      + Stateful: is suited for applications which don't have a
 *       concept of 'flow'. In this case the user simply pass to
 *       the library a stream of packets without concerning about
 *       how to store the flow. All the flow management and storing
 *       will be done by the library.
 *
 *      + Stateless: is suited for applications which already have a
 *       concept of 'flow'. In this case the framework demand the
 *       storage of the flow data to the application. The user
 *       application should be modified in order to store with
 *       their own flow informations also the informations needed by
 *       the framework to identify the protocols.
 */

#ifndef PFWL_API_H
#define PFWL_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <peafowl/inspectors/protocols_identifiers.h>
#include <peafowl/inspectors/fields.h>
#include <peafowl/utils.h>

#include <sys/types.h>

/// @cond EXTERNAL
typedef struct pfwl_flow_info pfwl_flow_info_t;
typedef struct pfwl_reassembly_fragment pfwl_reassembly_fragment_t;
typedef struct pfwl_tracking_informations pfwl_flow_info_private_t;
/// @endcond

/** Statuses */
typedef enum pfwl_status {
  /** Errors **/
  PFWL_ERROR_L2_PARSING = -7,             ///< L2 data unsupported, truncated or corrupted
  PFWL_ERROR_L3_PARSING = -6,             ///< L3 data unsupported, truncated or corrupted
  PFWL_ERROR_L4_PARSING = -5,             ///< L4 data unsupported, truncated or corrupted
  PFWL_ERROR_MAX_FLOWS = -4,              ///< Maximum number of flows reached
  PFWL_ERROR_IPV6_HDR_PARSING = -3,       ///< Error while parsing IPv6 headers
  PFWL_ERROR_IPSEC_NOTSUPPORTED = -2,     ///< IPsec packet, not supported currently
  PFWL_ERROR_WRONG_IPVERSION = -1,        ///< L3 protocol was neither IPv4 nor IPv6
  PFWL_STATUS_OK = 0,                     ///< Normal processing scenario.
  PFWL_STATUS_IP_FRAGMENT,                ///< Received a fragment of an IP packet.
                                          ///< If IP reassambly is enabled, the fragment
                                          ///< has been stored and the data will be recompacted
                                          ///< and analyzed when all the fragments will be
                                          ///< received.
  PFWL_STATUS_IP_LAST_FRAGMENT,           ///< The received datagram allowed the library to reconstruct a fragmented
                                          ///< datagram.
                                          ///< This status may only be returned if pfwl_parse_L3_L4 is explicitely called.
                                          ///< In this case, dissection_info->pkt_refragmented
                                          ///< will contain a pointer to the recomposed datagram.
                                          ///< This pointer will be different
                                          ///< from the packet provided by the user.
                                          ///< The user should free() this pointer when it is no
                                          ///< more needed (e.g. after calling pfwl_parse_L3_L4(..)).
  PFWL_STATUS_TCP_OUT_OF_ORDER,           ///< Received an out of order TCP segment.
                                          ///< If TCP defragmentation is enabled, the
                                          ///< segment has been stored, and
                                          ///< will be recomposed and analyzed when
                                          ///< the other segments will be received.
  PFWL_STATUS_TCP_CONNECTION_TERMINATED,  ///< FINs has been sent by both peers of the connection.
                                          ///< This status is not set for connections closed by RST.
} pfwl_status_t;

/**
 * L2 datalink protocols supported by peafowl.
 **/
typedef enum pfwl_datalink_type {
  PFWL_DLT_EN10MB = 0,       ///< IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up)
  PFWL_DLT_LINUX_SLL,        ///< Linux "cooked" capture encapsulation
  PFWL_DLT_IEEE802_11_RADIO, ///< Radiotap link-layer information followed by an 802.11 header
  PFWL_DLT_IEEE802_11,       ///< IEEE 802.11
  PFWL_DLT_IEEE802,          ///< IEEE 802.5 Token Ring
  PFWL_DLT_SLIP,             ///< SLIP, encapsulated with a LINKTYPE_SLIP header
  PFWL_DLT_PPP,              ///< PPP, as per RFC 1661 and RFC 1662
  PFWL_DLT_FDDI,             ///< FDDI, as specified by ANSI INCITS 239-1994
  PFWL_DLT_RAW,              ///< Raw IP
  PFWL_DLT_LOOP,             ///< OpenBSD loopback encapsulation
  PFWL_DLT_NULL,             ///< BSD loopback encapsulation
  PFWL_DLT_NOT_SUPPORTED     ///< Special value to indicate an unsupported datalink type
}pfwl_protocol_l2_t;

/**
 * L3 (IP) protocol.
 **/
typedef enum{
  PFWL_IP_VERSION_4 = 0x4, ///< IPv4
  PFWL_IP_VERSION_6 = 0x6 ///< IPv6
}pfwl_protocol_l3_t;

typedef uint8_t pfwl_protocol_l4_t; ///< L4 protocol. Values defined in include/netinet/in.h (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, etc...)

/**
 * L7 (application level) protocol.
 **/
typedef enum {
  PFWL_PROTOCOL_DNS = 0,         ///< DNS
  PFWL_PROTOCOL_MDNS,            ///< MDNS
  PFWL_PROTOCOL_DHCP,            ///< DHCP
  PFWL_PROTOCOL_DHCPv6,          ///< DHCPv6
  PFWL_PROTOCOL_NTP,             ///< NTP
  PFWL_PROTOCOL_SIP,             ///< SIP
  PFWL_PROTOCOL_RTP,             ///< RTP
  PFWL_PROTOCOL_SSH,             ///< SSH
  PFWL_PROTOCOL_SKYPE,           ///< Skype
  PFWL_PROTOCOL_HTTP,            ///< HTTP
  PFWL_PROTOCOL_BGP,             ///< BGP
  PFWL_PROTOCOL_SMTP,            ///< SMTP
  PFWL_PROTOCOL_POP3,            ///< POP3
  PFWL_PROTOCOL_IMAP,            ///< IMAP
  PFWL_PROTOCOL_SSL,             ///< SSL
  PFWL_PROTOCOL_HANGOUT,         ///< Hangout
  PFWL_PROTOCOL_WHATSAPP,        ///< WhatsApp
  PFWL_PROTOCOL_TELEGRAM,        ///< Telegram
  PFWL_PROTOCOL_DROPBOX,         ///< Dropbox
  PFWL_PROTOCOL_SPOTIFY,         ///< Spotify
  PFWL_NUM_PROTOCOLS,            ///< Dummy value to indicate the number of protocols
  PFWL_PROTOCOL_NOT_DETERMINED,  ///< Dummy value to indicate that the protocol has not been identified yet
  PFWL_PROTOCOL_UNKNOWN          ///< Dummy value to indicate that the protocol has not been identified
}pfwl_protocol_l7_t;

/**
 * An IP address.
 **/
typedef union pfwl_ip_addr {
  uint32_t ipv4;        ///< The IPv4 address
  struct in6_addr ipv6; ///< The IPv6 address
} pfwl_ip_addr_t;       ///< IP address


/**
 * Public information about the flow.
 * If stateless version is used, when the first packet
 * arrives, this structure must be initialized by
 * the user with the 'pfwl_init_flow_info' call.
 **/
typedef struct pfwl_flow_info {
  uint64_t num_packets[2];     ///< Number of packets, one value for each direction. Multiple IP fragments count like a single packet. One value for each direction.
  uint64_t num_bytes[2];       ///< Number of bytes (from L3 start to end of packet). One value for each direction.
  uint64_t num_packets_l7[2];  ///< Number of packets with a non-zero L7 payload. One value for each direction
  uint64_t num_bytes_l7[2];    ///< Number of L7 bytes. One value for each direction.
  void** udata;                ///< This data can be used by the user to store flow-specific
                               ///< information, i.e. information which must be preserved
                               ///< between successive packets of the same flow.
  uint32_t timestamp_first[2]; ///< Timestamp (seconds) of the first packet received for this flow. One value for each direction.
  uint32_t timestamp_last[2];  ///< Timestamp (seconds) of the last packet received for this flow. One value for each direction.
} pfwl_flow_info_t;

/**
 * The result of the identification process.
 **/
typedef struct pfwl_dissection_info {
  // General info
  pfwl_status_t status;              ///< The status of the operation. It gives additional informations
                                     ///< about the processing of the request. If lower than 0, an
                                     ///< error occurred. pfwl_get_status_msg() can be used to get a
                                     ///< textual representation of the status. If greater or equal
                                     ///< than 0 then it should not be interpreted as an error but
                                     ///< simply gives additional informations (e.g. if the packet was
                                     ///< IP fragmented, if it was out of order in the TCP stream, if is
                                     ///< a segment of a larger application request, etc..).
  // Information known after L2 parsing
  struct{
    size_t length;                   ///< Length of L2 header
    pfwl_protocol_l2_t protocol;     ///< L2 (datalink) protocol
  }l2;
  // Information known after L3 parsing
  struct{
    size_t length;                   ///< Length of L3 header.
    pfwl_ip_addr_t addr_src;         ///< Source address, in network byte order.
    pfwl_ip_addr_t addr_dst;         ///< Destination address, in network byte order.
    const unsigned char* refrag_pkt; ///< Refragmented IP packet (starting from fist byte of L3 packet).
    size_t refrag_pkt_len;           ///< Length of the refragmented packet (without L2 trailer).
    pfwl_protocol_l3_t protocol;    ///< IP version, PFWL_IP_VERSION_4 if IPv4, PFWL_IP_VERSION_6 in IPv6.
  }l3;
  // Information known after L4 parsing
  struct{
    size_t length;                   ///< Length of L4 header.
    uint16_t port_src;               ///< Source port, in network byte order.
    uint16_t port_dst;               ///< Destination port, in network byte order.
    uint8_t direction;               ///< Direction of the packet:
                                     ///< 0: From source to dest. 1: From dest to source
                                     ///< (with respect to src and dst stored in the flow).
                                     ///< This is only valid for TCP and UDP packets.
    const unsigned char* resegmented_pkt; ///< Resegmented TCP payload.
    size_t resegmented_pkt_len;      ///< The length of the resegmented TCP payload.
    pfwl_protocol_l4_t protocol;     ///< The Level 4 protocol.
  }l4;
  // Information known after L7 parsing
  struct{
    size_t length;                   ///< Length of L7 data.
    pfwl_protocol_l7_t protocol;     ///< The level 7 protocol.
    pfwl_field_t protocol_fields[PFWL_FIELDS_NUM];  ///< Fields extracted by the dissector. Some of these fields
                                                    ///< (e.g. strings) are only valid until
                                                    ///< another packet for the same flow is processed. I.e.
                                                    ///< if another packet for this flow is received, this
                                                    ///< data will not be valid anymore.
                                                    ///< If the user needs to preserve the data for a longer time,
                                                    ///< a copy of each needed field needs to be done.
  }l7;
  pfwl_flow_info_t flow_info;        ///< Information about the flow.
} pfwl_dissection_info_t;

/**
 * @brief Callback for flow cleaning.
 * This callback is called when the flow is expired and deleted. It can be
 * used by the user to clear flow_specific_user_data
 * @param flow_specific_user_data A pointer to the user data specific to this
 * flow.
 */
typedef void(pfwl_flow_cleaner_callback_t)(void* flow_specific_user_data);

/// @cond Private structures
typedef struct pfwl_state pfwl_state_t;
/// @endcond

/**
 * Some dissector can run at a different
 * accuracy level. This represent the level
 * of accuracy that may be required to a dissector.
 **/
typedef enum {
  PFWL_INSPECTOR_ACCURACY_LOW = 0, ///< Low accuracy
  PFWL_INSPECTOR_ACCURACY_MEDIUM,  ///< Medium accuracy
  PFWL_INSPECTOR_ACCURACY_HIGH,    ///< High accuracy
} pfwl_inspector_accuracy_t;

/// @cond Private structures
/**
 * @brief A generic protocol dissector.
 * A generic protocol dissector.
 * @param state               A pointer to the peafowl internal state
 * @param app_data            A pointer to the application payload.
 * @param data_length         The length of the application payload.
 * @param identification_info Info about the identification done up to now (up to L4 parsing).
 * @param flow_info_private   A pointer to the private flow information.
 * @return               PFWL_PROTOCOL_MATCHES if the protocol matches.
 *                       PFWL_PROTOCOL_NO_MATCHES if the protocol doesn't
 *                       matches.
 *                       PFWL_PROTOCOL_MORE_DATA_NEEDED if the inspector
 *                       needs more data to decide.
 *                       PFWL_ERROR if an error occurred.
 */
typedef uint8_t (*pfwl_dissector)(
    pfwl_state_t* state,
    const unsigned char* app_data,
    size_t data_length,
    pfwl_dissection_info_t* identification_info,
    pfwl_flow_info_private_t* flow_info_private
    );
/// @endcond


/**
 * @brief Initializes Peafowl.
 * Initializes the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols
 * to be active.
 * @return A pointer to the state of the library.
 */
pfwl_state_t* pfwl_init(void);

/**
 * Initializes the state of the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols active.
 * @return A pointer to the state of the library.
 */
pfwl_state_t* pfwl_init_stateless(void);

/**
 * Terminates the library.
 * @param state A pointer to the state of the library.
 */
void pfwl_terminate(pfwl_state_t* state);

/**
 * @brief Sets the number of simultaneously active flows to be expected.
 * @param state A pointer to the state of the library.
 * @param flows The number of simultaneously active flows.
 * @param strict If 1, when that number of active flows is reached,
 * an error will be returned (PFWL_ERROR_MAX_FLOWS) and new flows
 * will not be created. If 0, there will not be any limit to the number
 * of simultaneously active flows.
 * @return 0 if succeeded, 1 otherwise.
 */
uint8_t pfwl_set_expected_flows(pfwl_state_t* state,
                                uint32_t flows,
                                uint8_t strict);

/**
 * Sets the maximum number of times that the library tries to guess the
 * protocol. During the flow protocol identification, after this number
 * of trials, in the case in which it cannot decide between two or more
 * protocols, one of them will be chosen, otherwise PFWL_PROTOCOL_UNKNOWN
 * will be returned.
 * @param state A pointer to the state of the library.
 * @param max_trials Maximum number of trials. Zero will be consider as
 *                   infinity.
 *
 * @return 0 if succeeded, 1 otherwise.
 */
uint8_t pfwl_set_max_trials(pfwl_state_t* state, uint16_t max_trials);

/**
 * Enable IPv4 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv4
 *                     fragments informations.
 *
 * @return 0 if succeeded, 1
 *         otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_enable(pfwl_state_t* state,
                                      uint16_t table_size);

/**
 * Enable IPv6 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv6
 *                     fragments informations.
 *
 * @return 0 if succeeded, 1
 *         otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_enable(pfwl_state_t* state,
                                      uint16_t table_size);

/**
 * Sets the amount of memory that a single host can use for IPv4
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                any IPv4 host can use.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_set_per_host_memory_limit(
    pfwl_state_t* state, uint32_t per_host_memory_limit);

/**
 * Sets the amount of memory that a single host can use for IPv6
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                 any IPv6 host can use.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_set_per_host_memory_limit(
    pfwl_state_t* state, uint32_t per_host_memory_limit);

/**
 * Sets the total amount of memory that can be used for IPv4
 * defragmentation.
 * If fragmentation is disabled and then enabled, this information must be
 * passed again.
 * Otherwise default value will be used.
 * @param state               A pointer to the state of the library
 * @param total_memory_limit  The maximum amount of memory that can be used
 *                            for IPv4 defragmentation.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_set_total_memory_limit(
    pfwl_state_t* state, uint32_t total_memory_limit);

/**
 * Sets the total amount of memory that can be used for IPv6
 * defragmentation. If fragmentation is disabled and then enabled, this
 * information must be passed again. Otherwise default value will be used.
 * @param state               A pointer to the state of the library
 * @param total_memory_limit  The maximum amount of memory that can be
 *                            used for IPv6 defragmentation.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_set_total_memory_limit(
    pfwl_state_t* state, uint32_t total_memory_limit);

/**
 * Sets the maximum time (in seconds) that can be spent to reassembly an
 * IPv4 fragmented datagram. Is the maximum time gap between the first and
 * last fragments of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_set_reassembly_timeout(
    pfwl_state_t* state, uint8_t timeout_seconds);

/**
 * Sets the maximum time (in seconds) that can be spent to reassembly an
 * IPv6 fragmented datagram. Is the maximum time gap between the first and
 * last fragments of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_set_reassembly_timeout(
    pfwl_state_t* state, uint8_t timeout_seconds);

/**
 * Disable IPv4 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_disable(pfwl_state_t* state);

/**
 * Disable IPv6 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_disable(pfwl_state_t* state);

/**
 * If enabled, the library will reorder out of order TCP packets
 * (enabled by default).
 * @param state  A pointer to the state of the library.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_tcp_reordering_enable(pfwl_state_t* state);

/**
 * If it is called, the library will not reorder out of order TCP packets.
 * Out-of-order segments will be delivered to the inspector as they
 * arrive. This means that the inspector may not be able to identify the
 * application protocol. Moreover, if there are callbacks saved for TCP
 * based protocols, if TCP reordering is disabled, the extracted
 * informations could be erroneous or incomplete.
 * @param state A pointer to the state of the library.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_tcp_reordering_disable(pfwl_state_t* state);

/**
 * Enable a protocol inspector.
 * @param state         A pointer to the state of the library.
 * @param protocol      The protocol to enable.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_enable_protocol(pfwl_state_t* state,
                            pfwl_protocol_l7_t protocol);

/**
 * Disable a protocol inspector.
 * @param state       A pointer to the state of the library.
 * @param protocol    The protocol to disable.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_disable_protocol(pfwl_state_t* state,
                             pfwl_protocol_l7_t protocol);

/**
 * Enable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_inspect_all(pfwl_state_t* state);

/**
 * Disable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_inspect_nothing(pfwl_state_t* state);

/**
 * Skips the L7 parsing for packets traveling on some ports for some L4
 * protocol.
 * @param state A pointer to the state of the library.
 * @param l4prot The L4 protocol.
 * @param port The port.
 * @param id The protocol id that will be assigned to packets that matches with
 * this rule. If
 * id >= PFWL_PROTOCOL_UNKNOWN, it would be considered as a custom user protocol.
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_skip_L7_parsing_by_port(pfwl_state_t* state, uint8_t l4prot,
                                    uint16_t port, pfwl_protocol_l7_t id);

/**
 * Try to detect the application protocol starting from the beginning of the L2 (datalink) packet.
 * @param state The state of the library.
 * @param pkt The pointer to the beginning of datalink header.
 * @param length Length of the packet.
 * @param timestamp The current time in seconds.
 * @param datalink_type The datalink type. They match 1:1 the pcap datalink types.
 * You can convert a PCAP datalink type to a Peafowl datalink type by calling the
 * function 'pfwl_convert_pcap_dlt'.
 * @return  Dissection information from L2 up to L7.
 */
pfwl_dissection_info_t pfwl_dissect_from_L2(pfwl_state_t* state, const unsigned char* pkt,
                                            size_t length, uint32_t timestamp,
                                            pfwl_protocol_l2_t datalink_type);

/**
 * Try to detect the application protocol starting from the beginning of the L3 (IP) packet.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   length Length of the packet (from the beginning of the IP header).
 * @param   timestamp The current time in seconds.
 * @param   dissection_info The result of the dissection. All its bytes must be
 *          set to 0 before calling this call.
 *          Dissection information from L3 to L7 will be filled in by this call.
 */
void pfwl_dissect_from_L3(pfwl_state_t* state, const unsigned char* pkt,
                          size_t length, uint32_t timestamp,
                          pfwl_dissection_info_t* dissection_info);

/**
 * Extracts from the packet the L2 information.
 * @param packet A pointer to the packet.
 * @param datalink_type The datalink type. They match 1:1 the pcap datalink types.
 * You can convert a PCAP datalink type to a Peafowl datalink type by calling the
 * function 'pfwl_convert_pcap_dlt'.
 * @param dissection_info The result of the dissection. All its bytes must be
 *        set to 0 before calling this call.
 *        Dissection information about L2 headers will be filled in by this call.
 */
void pfwl_parse_L2(const unsigned char* packet,
                   pfwl_protocol_l2_t datalink_type,
                   pfwl_dissection_info_t* dissection_info);

/**
 * Extracts from the packet the L3 information.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   length Length of the packet (from the beginning of the IP header).
 * @param   timestamp The current time in seconds. It must be
 *          non-decreasing between two consecutive calls.
 * @param dissection_info The result of the dissection. All its bytes must be
 *        set to 0 before calling this call.
 *        Dissection information about L3 headers will be filled in by this call.
 * @return  The identification result.
 */
void pfwl_parse_L3(pfwl_state_t* state,
                      const unsigned char* pkt,
                      size_t length,
                      uint32_t timestamp,
                      pfwl_dissection_info_t* dissection_info);

/**
 * Extracts from the packet the L4 information.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of UDP or TCP header.
 * @param   length Length of the packet (from the beginning of the UDP or TCP header).
 * @param   timestamp The current time in seconds. It must be
 *          non-decreasing between two consecutive calls.
 * @param   dissection_info The result of the dissection. All its bytes must be
 *          set to 0 before calling this call.
 *          Dissection information about L3 headers must be filled in by the caller.
 *          l4.protocol must be filled in by the caller as well.
 *          Dissection information about L4 headers will be filled in by this call.
 * @return  The identification result.
 */
void pfwl_parse_L4(pfwl_state_t* state,
                   const unsigned char* pkt,
                   size_t length,
                   uint32_t timestamp,
                   pfwl_dissection_info_t* dissection_info);

/**
 * Try to detect the application protocol. Before calling it, a check on
 * L4 protocol should be done and the function should be called only if
 * the packet is TCP or UDP. It should be used if the application already
 * has the concept of 'flow'. In this case the first time that the flow is
 * passed to the call, it must be initialized with
 * pfwl_init_flow_info(...).
 * Information in dissection_info->flow are not set in this case.
 * @param   state The pointer to the library state.
 * @param   pkt The pointer to the beginning of application data.
 * @param   length Length of the packet (from the beginning of the
 *          L7 header).
 * @param   timestamp The current time in seconds. It must be
 *          non-decreasing between two consecutive calls.
 * @param   dissection_info The result of the dissection. All its bytes must be
 *          set to 0 before calling this call.
 *          Dissection information about L3 and L4 headers must be filled in by the caller.
 *          Dissection information about L7 packet will be filled in by this call.
 * @param   flow_info_private The private information about the flow. It must be
 *          stored by the user and itialized with the pfwl_init_flow_info(...) call.
 */
void pfwl_parse_L7(pfwl_state_t* state,
                   const unsigned char* pkt,
                   size_t length,
                   uint32_t timestamp,
                   pfwl_dissection_info_t* dissection_info,
                   pfwl_flow_info_private_t *flow_info_private);

/**
 * Initialize the flow informations passed as argument.
 * @param state             A pointer to the state of the library.
 * @param flow_info_private The private flow information, will be initialized
 * by the library.
 */
void pfwl_init_flow_info(pfwl_state_t* state, pfwl_flow_info_private_t* flow_info_private);

/**
 * Try to guess the protocol looking only at source/destination ports.
 * This could be erroneous because sometimes protocols run over ports
 * which are not their well-known ports.
 * @param identification_info Info about the identification done up to now (up to L4 parsing).
 * @return   Returns the possible matching protocol.
 */
pfwl_protocol_l7_t pfwl_guess_protocol(pfwl_dissection_info_t identification_info);

/**
 * Get the string representing the status message associated to the
 * specified status_code.
 * @param   status_code The status code.
 * @return  The status message.
 */
const char* const pfwl_get_status_msg(pfwl_status_t status_code);

/**
 * Returns the string represetation of a protocol.
 * @param   protocol The protocol identifier.
 * @return  The string representation of the protocol with id 'protocol'.
 */
const char* const pfwl_get_protocol_string(pfwl_protocol_l7_t protocol);

/**
 * Returns the protocol id corresponding to a protocol string.
 * @param string The protocols tring.
 * @return The protocol id corresponding to a protocol string.
 */
pfwl_protocol_l7_t pfwl_get_protocol_id(const char* const string);

/**
 * Returns the string represetations of the protocols.
 * @return  An array A of string, such that A[i] is the
 * string representation of the protocol with id 'i'.
 */
const char** const pfwl_get_protocols_strings();

/**
 * Sets the callback that will be called when a flow expires.
 * (Valid only if stateful API is used).
 * @param state     A pointer to the state of the library.
 * @param cleaner   The callback used to clear the user state.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_set_flow_cleaner_callback(pfwl_state_t* state,
                                      pfwl_flow_cleaner_callback_t* cleaner);

/**
 * Enable the extraction of a specific field for a given protocol.
 * When a protocol is identified the default
 * behavior is to not inspect the packets belonging to that flow anymore
 * and keep simply returning the same protocol identifier.
 *
 * If at least one field extraction is enabled for a certain protocol,
 * then we keep inspecting all the new packets of that flow to extract
 * such field. Moreover, if the application protocol uses TCP, then we have
 * the additional cost of TCP reordering for all the segments. Is highly
 * recommended to enable TCP reordering if it is not already enabled
 * (remember that is enabled by default). Otherwise the informations
 * extracted could be erroneous/incomplete.
 *
 * Please note that this is only a suggestion given by the user to peafowl,
 * and that in some cases the dissector could still extract the field,
 * even if this has not been requested by the user. Indeed, in some cases
 * the extraction of some fields may be needed for the correct identification
 * of the protocol.
 *
 * @param state        A pointer to the state of the library.
 * @param field        The field to extract.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 *
 **/
uint8_t pfwl_protocol_field_add(pfwl_state_t* state,
                                pfwl_field_id_t field);

/**
 * Disable the protocol field callback. udata is not freed/modified.
 * @param state   A pointer to the state of the library.
 * @param field   The field identifier.
 *
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_protocol_field_remove(pfwl_state_t* state, pfwl_field_id_t field);

/**
 * Checks if the extraction of a specific field for a given protocol has been
 * required.
 * @param state   A pointer to the state of the library.
 * @param field   The field identifier.
 * @return 1 if the field has been required, 0 otherwise.
 */
uint8_t pfwl_protocol_field_required(pfwl_state_t* state, pfwl_field_id_t field);

/**
 * Some protocols inspector (e.g. SIP) can be applied with a different
 * level of accuracy (and of processing time). By using this call
 * the user can decide if running the inspector in its most accurate
 * version (at the cost of a higher processing latency).
 * @param state       A pointer to the state of the library.
 * @param protocol    The protocol for which we want to change the accuracy.
 * @param accuracy    The accuracy level.
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_set_protocol_accuracy(pfwl_state_t* state,
                                  pfwl_protocol_l7_t protocol,
                                  pfwl_inspector_accuracy_t accuracy);

/**
 * @brief pfwl_field_string_get Extracts a specific string field from a list of fields.
 * @param fields The list of fields.
 * @param id The field identifier.
 * @param string The extracted field.
 * @return 0 if the field was present, 1 otherwise. If 1 is returned, 'string' is not set.
 */
uint8_t pfwl_field_string_get(pfwl_field_t* fields, pfwl_field_id_t id, pfwl_string_t* string);


/**
 * @brief pfwl_field_number_get Extracts a specific numeric field from a list of fields.
 * @param fields The list of fields.
 * @param id The field identifier.
 * @param number The extracted field.
 * @return 0 if the field was present, 1 otherwise. If 1 is returned, 'number' is not set.
 */
uint8_t pfwl_field_number_get(pfwl_field_t* fields, pfwl_field_id_t id, int64_t* number);


/**
 * @brief pfwl_field_array_length Returns the size of a field representing an array of strings.
 * @param fields The list of fields.
 * @param id The field identifier.
 * @param length The returned length.
 * @return 0 if the field was present, 1 otherwise. If 1 is returned, 'size' is not set.
 */
uint8_t pfwl_field_array_length(pfwl_field_t* fields, pfwl_field_id_t id, size_t* length);

/**
 * @brief pfwl_field_array_get_pair Extracts a pair in a specific position, from a specific array field.
 * @param fields The list of fields.
 * @param id The field identifier.
 * @param position The position in the array.
 * @param pair The returned pair.
 * @return 0 if the field was present, 1 otherwise. If 1 is returned, 'pair' is not set.
 */
uint8_t pfwl_field_array_get_pair(pfwl_field_t* fields, pfwl_field_id_t id, size_t position, pfwl_pair_t* pair);

/**
 * @brief pfwl_http_get_header Extracts a specific HTTP header from the dissection info.
 * @param dissection_info The dissection info.
 * @param header_name The name of the header ('\0' terminated).
 * @param header_value The returned header value.
 * @return 0 if the http header was present, 1 otherwise. If 1 is returned, 'header_value' is not set.
 */
uint8_t pfwl_http_get_header(pfwl_dissection_info_t* dissection_info, const char* header_name, pfwl_string_t* header_value);

/**
 * @brief pfwl_convert_pcap_dlt Converts a pcap datalink type (which can be obtained with the pcap_datalink(...) call),
 * to a pfwl_datalink_type_t.
 * @param dlt The pcap datalink type.
 * @return The peafowl datalink type. PFWL_DLT_NOT_SUPPORTED is returned if the specified datalink type is not supported
 * by peafowl.
 */
pfwl_protocol_l2_t pfwl_convert_pcap_dlt(int dlt);

/****************************************/
/** Only to be used directly by mcdpi. **/
/****************************************/
/// @cond MC
pfwl_state_t* pfwl_init_stateful_num_partitions(uint32_t expected_flows, uint8_t strict, uint16_t num_table_partitions);

void mc_pfwl_parse_L3_header(pfwl_state_t* state,
                             const unsigned char* p_pkt,
                             size_t p_length,
                             uint32_t current_time, int tid,
                             pfwl_dissection_info_t* dissection_info);


void mc_pfwl_parse_L4_header(pfwl_state_t* state,
                             const unsigned char* p_pkt,
                             size_t p_length,
                             uint32_t timestamp, int tid,
                             pfwl_dissection_info_t* dissection_info);
/// @endcond


/// @cond Private structures
typedef struct pfwl_l7_skipping_info pfwl_l7_skipping_info_t;

/**
 * Please do not rely on this structure. It is meant for private internal use
 * to the library and may significantly change between different commits.
 **/
typedef struct pfwl_state {
  /********************************************************************/
  /** Created by pfwl_init_state and never modified                  **/
  /********************************************************************/
  void* flow_table; ///< A pointer to the table containing IPv4 flows

  void* protocols_internal_state[PFWL_NUM_PROTOCOLS]; // For each protocol, an internal state to be shared among flows

  /********************************************************************/
  /** Can be modified during the execution but only using the state  **/
  /** update functions. They are never modified in other places      **/
  /********************************************************************/
  char protocols_to_inspect[BITNSLOTS(PFWL_NUM_PROTOCOLS)];

  pfwl_protocol_l7_t active_protocols;

  uint16_t max_trials;

  /** Field extraction. **/
  /**
   * One flag per field.
   * If 1, the field is extracted. If 0, it is not extracted.
   **/
  uint8_t fields_to_extract[PFWL_FIELDS_NUM];
  /**
   * Number of fields to extract, per protocol.
   **/
  uint8_t fields_to_extract_num[PFWL_NUM_PROTOCOLS];

  uint8_t tcp_reordering_enabled : 1;

  /** L7 skipping information. **/
  pfwl_l7_skipping_info_t* l7_skip;

  pfwl_inspector_accuracy_t inspectors_accuracy[PFWL_NUM_PROTOCOLS];

  /********************************************************************/
  /** The content of these structures can be modified during the     **/
  /** execution also in functions different from the state update    **/
  /** functions. This is the reason why when multiprocessor support  **/
  /** is used, we need to have one copy of these structures for each **/
  /** worker or we need to protect the access with mutual exclusion  **/
  /** mechanisms (e.g. locks).                                       **/
  /********************************************************************/
  void* ipv4_frag_state;
  void* ipv6_frag_state;
} pfwl_state_t;

/// @endcond

#ifdef __cplusplus
}
#endif

#endif
