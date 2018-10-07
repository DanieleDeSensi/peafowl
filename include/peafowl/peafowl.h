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
 *  Provided features:
 *		+Support for IPv6 and its optional headers
 *  	+Tunneling: 6in6, 4in4, 6in4, 4in6
 *  	+Protection against truncated or corrupted L3 and L4 packets.
 *  	 It can be enabled by PFWL_ENABLE_L3_TRUNCATION_PROTECTION or
 *  	 PFWL_ENABLE_L4_TRUNCATION_PROTECTION in the cases in which
 *  	 is not provided by the lower layers. This check is not done
 *  	 computing the checksum but only looking at the header/payload
 *  	 lengths.
 *  	+Robust IPv4 and IPv6 defragmentation support tested against a
 *  	 large number of possible attacks.
 *  	+TCP stream reassembly.
 *  	+Possibility to activate and deactivate protocol inspector and
 *  	 callbacks at runtime.
 *      +The framework can be used in two different modes: Stateful and
 *       Stateless.
 *           +Stateful: is suited for applications which don't have a
 *            concept of 'flow'. In this case the user simply pass to
 *            the library a stream of packets without concerning about
 *            how to store the flow. All the flow management and storing
 *            will be done by the library.
 *           +Stateless: is suited for applications which already have a
 *            concept of 'flow'. In this case the framework demand the
 *            storage of the flow data to the application. The user
 *            application should be modified in order to store with
 *            their own flow informations also the informations needed by
 *            the framework to identify the protocols.
 *      +The protocol recognition can be done with
 *       pfwl_stateful_identify_application_protocol(...) giving simply a
 *       pointer to the packet, or separating the two stages and using in
 *       sequence pfwl_parse_L3_L4_headers(...) and then
 *       pfwl_stateful_get_app_protocol_v4(...) (or _v6). The latter
 *       solution gives to the user the possibility to use the L3 and L4
 *       informations that maybe he already has (skipping the L3 and L4
 *       info extraction) and to explicitly get a pointer to the beginning
 *       of application flow in the case in which he wants to invoke its
 *       own processing routines on the flow payload.
 *      +Support for user defined callbacks on any HTTP header field and
 *       HTTP body.
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

/** Errors **/
#define PFWL_ERROR_WRONG_IPVERSION -1                  ///< Neither IPv4 nor IPv6
#define PFWL_ERROR_IPSEC_NOTSUPPORTED -2               ///< IPsec packet, not supported currently
#define PFWL_ERROR_L3_TRUNCATED_PACKET -3              ///< L3 data truncated or corrupted
#define PFWL_ERROR_L4_TRUNCATED_PACKET -4              ///< L4 data truncated or corrupted
#define PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED -5  ///< Transport protocol (L4) not supported
#define PFWL_ERROR_MAX_FLOWS -6                        ///< Maximum number of flows reached
#define PFWL_ERROR_L2_PARSING -7                       ///< Error while parsing L2 header.

/// @cond EXTERNAL
typedef struct pfwl_flow_info pfwl_flow_info_t;
typedef struct pfwl_reassembly_fragment pfwl_reassembly_fragment_t;
typedef struct pfwl_tracking_informations pfwl_tracking_informations_t;
/// @endcond

/** Statuses */
typedef enum pfwl_status {
  PFWL_STATUS_OK = 0,                     ///< Normal processing scenario.
  PFWL_STATUS_IP_FRAGMENT,                ///< Received a fragment of an IP packet.
                                          ///< If IP reassambly is enabled, the fragment
                                          ///< has been stored and the data will be recompacted
                                          ///< and analyzed when all the fragments will be
                                          ///< received.
  PFWL_STATUS_IP_LAST_FRAGMENT,           ///< The received datagram allowed the library to reconstruct a fragmented
                                          ///< datagram. In this case, dissection_info->pkt_refragmented
                                          ///< will contain a pointer to the recomposed datagram. This pointer will be different
                                          ///< from the packet provided. The user should free() this pointer when it is no
                                          ///< more needed (e.g. after calling pfwl_parse_L3_L4(..)).
                                          ///< This status may only be returned if pfwl_parse_L3_L4 is explicitely called.
  PFWL_STATUS_TCP_OUT_OF_ORDER,           ///< Received an out of order TCP segment.
                                          ///< If TCP defragmentation is enabled, the
                                          ///< segment has been stored, and
                                          ///< will be recomposed and analyzed when
                                          ///< the other segments will be received.
  PFWL_STATUS_TCP_CONNECTION_TERMINATED,  ///< Terminated means FIN received. This
                                          ///< status is not set for connection
                                          ///< closed by RST
} pfwl_status_t;

/**
 * An IP address.
 **/
typedef union pfwl_ip_addr {
  uint32_t ipv4;        ///< The IPv4 address
  struct in6_addr ipv6; ///< The IPv6 address
} pfwl_ip_addr_t;       ///< IP address

/**
 * The result of the identification process.
 **/
typedef struct pfwl_dissection_info {
  pfwl_status_t status;           ///< The status of the operation. It gives additional informations
                                  ///< about the processing of the request. If lesser than 0, an
                                  ///< error occurred. pfwl_get_error_msg() can be used to get a
                                  ///< textual representation of the error. If greater or equal
                                  ///< than 0 then it should not be interpreted as an error but
                                  ///< simply gives additional informations (e.g. if the packet was
                                  ///< IP fragmented, if it was out of order in the TCP stream, if is
                                  ///< a segment of a larger application request, etc..).
                                  ///< pfwl_get_status_msg() can be used to get a textual
                                  ///< representation of the status. Status and error codes are
                                  ///< defined above in this header file.
  uint32_t timestamp;             ///< Time when the library started the processing (in seconds).
  void** user_flow_data;          ///< User-defined data associated to the specific flow.
  // Information known after L2 parsing
  uint16_t offset_l3;             ///< Offset where L3 packet starts.
  // Information known after L3 parsing
  pfwl_ip_addr_t addr_src;        ///< Source address, in network byte order.
  pfwl_ip_addr_t addr_dst;        ///< Destination address, in network byte order.
  uint8_t ip_version;             ///< IP version, 4 if IPv4, 6 in IPv6.
  uint8_t direction;              ///< Direction of the packet:
                                  ///< 0: From source to dest. 1: From dest to source
                                  ///< (with respect to src and dst stored in the flow).
                                  ///< This is only valid for TCP and UDP packets.
  pfwl_protocol_l4_t protocol_l4; ///< The Level 4 protocol.
  uint16_t offset_l4;             ///< Offset where L4 packet starts.
  const unsigned char* pkt_refragmented; ///< Refragmented IP packet. If the packet was not refragmented,
                                         ///< this is equal to the packet provided to peafowl.
  // Information known after L4 parsing
  uint16_t port_src;              ///< Source port, in network byte order.
  uint16_t port_dst;              ///< Destination port, in network byte order.
  uint16_t offset_l7;             ///< Offset where L7 packet starts.
  uint32_t data_length_l7;        ///< Length of the application data
                                  ///< (from the end of L4 header to the end).
  const unsigned char* data_l7;   ///< (Resegmented) Application data.
  // Information known after L7 parsing
  pfwl_protocol_l7_t protocol_l7; ///< The level 7 protocol.
  pfwl_field_t protocol_fields[PFWL_FIELDS_NUM];  ///< Fields extracted by the dissector. Some of these fields
                                                  ///< (e.g. strings) are only valid until
                                                  ///< another packet for the same flow is processed. I.e.
                                                  ///< If another packet for this flow is received, this
                                                  ///< data will not be valid anymore.
                                                  ///< If the user needs to preserve the data for a longer time,
                                                  ///< a copy of each needed field needs to be done.
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

/**
 * @brief A generic protocol dissector.
 * A generic protocol inspector.
 * @param app_data       A pointer to the application payload.
 * @param data_length    The length of the application payload.
 * @param identification_info Info about the identification done up to now (up to L4 parsing).
 * @param tracking_info  A pointer to the protocols tracking informations.
 * @param accuracy       The required accuracy for the dissector
 * @param required_fields The fields which must be extracted by the dissector.
 *                        E.g. if the dissector is the HTTP dissector, and
 *                        required_fields[DPI_FIELDS_HTTP_URL] == 1, then
 *                        the dissector should extract the URL of the packet.
 * @return               PFWL_PROTOCOL_MATCHES if the protocol matches.
 *                       PFWL_PROTOCOL_NO_MATCHES if the protocol doesn't
 *                       matches.
 *                       PFWL_PROTOCOL_MORE_DATA_NEEDED if the inspector
 *                       needs more data to decide.
 *                       PFWL_ERROR if an error occurred.
 */
typedef uint8_t (*pfwl_dissector)(
    const unsigned char* app_data,
    uint32_t data_length,
    pfwl_dissection_info_t* identification_info,
    pfwl_tracking_informations_t* tracking_info,
    pfwl_inspector_accuracy_t accuracy,
    uint8_t* required_fields
    );

/**
 * @brief Initializes Peafowl.
 * Initializes the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols
 * to be active.
 * @return A pointer to the state of the library.
 */
pfwl_state_t* pfwl_init();

/**
 * Initializes the state of the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols active.
 * @return A pointer to the state of the library.
 */
pfwl_state_t* pfwl_init_stateless();

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
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of datalink header.
 * @param   length Length of the packet.
 * @param   timestamp The current time in seconds.
 * @param datalink_type The datalink type, as defined by libpcap. This can be
 * obtained by calling pcap_datalink(...) on a PCAP handle.
 * If you do not use libpcap to capture packets, a list of allowed datalink_type
 * values can be found with 'man pcap-linktype'.
 * @return  Dissection information from L2 up to L7.
 */
pfwl_dissection_info_t pfwl_dissect_from_L2(pfwl_state_t* state, const unsigned char* pkt,
                                                  uint32_t length, uint32_t timestamp, int datalink_type);

/**
 * Try to detect the application protocol starting from the beginning of the L3 (IP) packet.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   length Length of the packet (from the beginning of the IP
 *          header, without L2 headers/trailers).
 * @param   timestamp The current time in seconds.
 * @param   dissection_info The result of the dissection.
 *          Dissection information from L3 to L7 will be filled by this call.
 */
void pfwl_dissect_from_L3(pfwl_state_t* state, const unsigned char* pkt,
                          uint32_t length, uint32_t timestamp,
                          pfwl_dissection_info_t* dissection_info);

/**
 * Parses the datalink header.
 * @brief pfwl_parse_L2
 * @param packet A pointer to the packet.
 * @param datalink_type The datalink type, as defined by libpcap. This can be
 * obtained by calling pcap_datalink(...) on a PCAP handle.
 * If you do not use libpcap to capture packets, a list of allowed datalink_type
 * values can be found with 'man pcap-linktype'.
 * @param dissection_info The result of the dissection (up to L2 parsing). It will be filled by this call.
 */
void pfwl_parse_L2(const unsigned char* packet, int datalink_type, pfwl_dissection_info_t* dissection_info);

/**
 * Extracts from the packet the informations about source and destination
 * addresses, source and destination ports, L4 protocol and the offset
 * where the application data starts.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   length Length of the packet (from the beginning of the
 *          IP header, without L2 headers/trailers).
 * @param   current_time The current time in seconds. It must be
 *          non-decreasing between two consecutive calls.
 * @param   dissection_info Info about the dissection done up to now (up to L2 parsing).
 *          It will be filled by the library with additional info about L3 and L4 dissection.
 * @return  The identification result.
 */
void pfwl_parse_L3_L4(pfwl_state_t* state, const unsigned char* pkt, uint32_t length,
                      uint32_t current_time, pfwl_dissection_info_t* dissection_info);

/**
 * Try to detect the application protocol. Before calling it, a check on
 * L4 protocol should be done and the function should be called only if
 * the packet is TCP or UDP.
 * @param   state The pointer to the library state.
 * @param   dissection_info Info about the dissection done up to now (up to L4 parsing).
 *          It will be filled by the library with additional info about L7 dissection.
 */
void pfwl_parse_L7(pfwl_state_t* state, pfwl_dissection_info_t* dissection_info);

/**
 * Try to detect the application protocol. Before calling it, a check on
 * L4 protocol should be done and the function should be called only if
 * the packet is TCP or UDP. It should be used if the application already
 * has the concept of 'flow'. In this case the first time that the flow is
 * passed to the call, it must be initialized with
 * pfwl_init_flow_info(...).
 * @param   state The pointer to the library state.
 * @param   flow The informations about the flow. They must be kept by the
 *               user.
 * @param identification_info Info about the identification done up to now (up to L4 parsing).
 *          It will be filled by the library with additional info about L7 dissection.
 */
void pfwl_parse_L7_stateless(pfwl_state_t* state, pfwl_dissection_info_t* identification_info, pfwl_flow_info_t* flow);

/**
 * Initialize the flow informations passed as argument.
 * @param state       A pointer to the state of the library.
 * @param flow_info  The informations that will be initialized by the
 *                    library.
 */
void pfwl_init_flow_info(pfwl_state_t* state, pfwl_flow_info_t* flow_info);

/**
 * Try to guess the protocol looking only at source/destination ports.
 * This could be erroneous because sometimes protocols run over ports
 * which are not their well-known ports.
 * @param identification_info Info about the identification done up to now (up to L4 parsing).
 * @return   Returns the possible matching protocol.
 */
pfwl_protocol_l7_t pfwl_guess_protocol(pfwl_dissection_info_t identification_info);

/**
 * Get the string representing the error message associated to the
 * specified error_code.
 * @param   error_code The error code.
 * @return  The error message.
 */
const char* const pfwl_get_error_msg(int8_t error_code);

/**
 * Get the string representing the status message associated to the
 * specified status_code.
 * @param   status_code The status code.
 * @return  The status message.
 */
const char* const pfwl_get_status_msg(int8_t status_code);

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
 * Initializes the exporter to Prometheus DB.
 * @param state       A pointer to the state of the library.
 * @param port        The port on which the server should listen.
 * @return 0 if succeeded,
 *         1 otherwise.
 */
uint8_t pfwl_prometheus_init(pfwl_state_t* state, uint16_t port);

/****************************************/
/** Only to be used directly by mcdpi. **/
/****************************************/
/// @cond MC
pfwl_state_t* pfwl_init_stateful_num_partitions(uint32_t expected_flows, uint8_t strict, uint16_t num_table_partitions);

void mc_pfwl_parse_L3_L4_header(pfwl_state_t* state,
                                const unsigned char* p_pkt,
                                uint32_t p_length,
                                uint32_t current_time, int tid,
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
