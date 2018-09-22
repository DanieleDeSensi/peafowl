/**
 * @file  peafowl.h
 * @brief This is the main peafowl header to be included.
 *
 * Created on: 19/09/2012
 *
 * =========================================================================
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

#include <peafowl/inspectors/http_parser_joyent.h>
#include <peafowl/inspectors/protocols_identifiers.h>
#include <peafowl/inspectors/fields.h>
#include <peafowl/utils.h>
#include <peafowl/external/utils/uthash.h>

#include <sys/types.h>

/** Errors **/
#define PFWL_ERROR_WRONG_IPVERSION -1
#define PFWL_ERROR_IPSEC_NOTSUPPORTED -2
#define PFWL_ERROR_L3_TRUNCATED_PACKET -3
#define PFWL_ERROR_L4_TRUNCATED_PACKET -4
#define PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED -5
#define PFWL_ERROR_MAX_FLOWS -6

typedef struct pfwl_flow_infos pfwl_flow_infos_t;
typedef struct pfwl_reassembly_fragment pfwl_reassembly_fragment_t;
typedef struct pfwl_tracking_informations pfwl_tracking_informations_t;

/** Statuses */
typedef enum pfwl_status {
  PFWL_STATUS_OK = 0,
  PFWL_STATUS_IP_FRAGMENT,
  PFWL_STATUS_IP_LAST_FRAGMENT,
  PFWL_STATUS_TCP_OUT_OF_ORDER,
  PFWL_STATUS_TCP_CONNECTION_TERMINATED,  // Terminated means FIN received. This
                                         // status is not set for connection
                                         // closed by RST
} pfwl_status_t;

enum pfwl_state_update_status {
  PFWL_STATE_UPDATE_SUCCESS = 0,
  PFWL_STATE_UPDATE_FAILURE = 1
};

/**
 * The result of the identification process.
 **/
typedef struct pfwl_identification_result {
  // The status of the identification.
  int8_t status;
  // The Level 4 protocol
  pfwl_protocol_l4 protocol_l4;
  // The level 7 protocol
  pfwl_protocol_l7 protocol_l7;
  // Fields extracted by the dissector
  pfwl_field_t* protocol_fields;
  // Number of fields extracted by the dissector
  size_t protocol_fields_num;
  // User-defined data associated to the specific flow
  void* user_flow_data;  
} pfwl_identification_result_t;

/**
 * Summary information about the packet.
 **/
typedef struct pfwl_pkt_infos {
  uint16_t srcport;   /** In network byte order. **/
  uint16_t dstport;   /** In network byte order. **/
  uint8_t ip_version; /** 4 if IPv4, 6 in IPv6. **/
  /**
  * 0: From source to dest. 1: From dest to source
  * (with respect to src and dst stored in the flow).
  **/
  uint8_t direction;
  /**
  * Id corresponds to the id defined for IPv4 protocol
  * field (IPv6 next header field).
  **/
  uint8_t l4prot;

  const unsigned char* pkt;
  uint16_t l4offset;
  uint16_t l7offset;
  /**
   * Length of the application data (from the end of L4 header to the
   * end).
   **/
  uint32_t data_length;
  /** Source address, in network byte order. **/
  union src_addr {
    struct in6_addr ipv6_srcaddr;
    uint32_t ipv4_srcaddr;
  } src_addr_t;
  /** Destination address, in network byte order. **/
  union dst_addr {
    struct in6_addr ipv6_dstaddr;
    uint32_t ipv4_dstaddr;
  } dst_addr_t;
  /** Time when the library started the processing (in seconds). **/
  uint32_t processing_time;
} pfwl_pkt_infos_t;

enum pfwl_http_message_type {
  PFWL_HTTP_REQUEST = HTTP_REQUEST,
  PFWL_HTTP_RESPONSE = HTTP_RESPONSE
};

enum pfwl_http_methods {
#define XX(num, name, string) PFWL_HTTP_##name = num,
  HTTP_METHOD_MAP(XX)
#undef XX
};

  
typedef struct pfwl_http_message_informations {
  uint8_t http_version_major;
  uint8_t http_version_minor;
  /**
   * HTTP method identifier if request_or_response==PFWL_HTTP_REQUEST,
   * otherwise is the HTTP status code. The method identifiers are
   * named PFWL_HTTP_METHOD_GET, PFWL_HTTP_METHOD_POST, etc.
   */
  uint16_t method_or_code;
  /**
   * PFWL_HTTP_REQUEST if the header field belongs to an HTTP request,
   * PFWL_HTTP_RESPONSE otherwise.
   **/
  uint8_t request_or_response;
} pfwl_http_message_informations_t;

  
/**
 * @brief Callback for flow cleaning.
 * This callback is called when the flow is expired and deleted. It can be
 * used by the user to clear flow_specific_user_data
 * @param flow_specific_user_data A pointer to the user data specific to this
 * flow.
 */
typedef void(pfwl_flow_cleaner_callback)(void* flow_specific_user_data);

  
/**
 * Called when ssl inspector seen certificate
**/
typedef void(pfwl_ssl_certificate_callback)(char* certificate, int size,
                                           void* user_data,
                                           pfwl_pkt_infos_t* pkt);

  
/**
 * This callback is called when the corresponding header field is found.
 * If the field is divided into more TCP segments it is reconstructed by
 * the library and this callback is called only one time on the
 * reconstructed field. In any case, the pointer to the value is valid
 * only for the lifetime of the callback. It must be copied if the user
 * needs it.
 *
 * @param url A pointer to the string representing the value of the url
 *            It is valid only for the callback lifetime.
 * @param url_length The length of the string representing the url.
 * @param pkt_informations A pointer to the parsed packet.
 * @param flow_specific_user_data A pointer to the user data specific
 *                                to this flow.
 * @param user_data A pointer to the global HTTP user data.
 */
typedef void(pfwl_http_header_url_callback)(const unsigned char* url,
                                           uint32_t url_length,
                                           pfwl_pkt_infos_t* pkt_informations,
                                           void** flow_specific_user_data,
                                           void* user_data);

  
/**
 * This callback is called when the corresponding header field is found.
 * If the field is divided into more TCP segments it is reconstructed by
 * the library and this callback is called only one time on the
 * reconstructed field. In any case, the pointer to the value is valid
 * only for the lifetime of the callback. It must be copied if the user
 * needs it.
 *
 * @param http_message_informations   A pointer to the struct containing
 *                                    the message informations (method,
 *                                    http version, etc..). The pointer
 *                                    is valid only for the callback
 *                                    lifetime.
 * @param header_value                A pointer to the string representing
 *                                    the value of the header field (NOTE:
 *                                    Is not \0 terminated). It is valid
 *                                    only for the callback lifetime.
 * @param header_value_length         The length of the string representing
 *                                    the value of the header field.
 * @param pkt_informations            A pointer to the parsed packet.
 * @param flow_specific_user_data     A pointer to the user data specific
 *                                    to this flow.
 * @param user_data                   A pointer to the global HTTP user data.
 */
typedef void(pfwl_http_header_field_callback)(
    pfwl_http_message_informations_t* http_message_informations,
    const unsigned char* header_value, uint32_t header_value_length,
    pfwl_pkt_infos_t* pkt_informations, void** flow_specific_user_data,
    void* user_data);

  
/**
 * This callback is called when an HTTP body is found. If the body is
 * divided in multiple TCP segments, then for each segment this callback
 * is called with the content of that specific segment. When the last
 * segment of the body arrives, the field last_chunk will be different
 * from 0. The pointer to the body chunk is valid only for the lifetime
 * of the callback.
 *
 * @param http_message_informations   A pointer to the struct containing
 *                                    the message informations (method,
 *                                    http version, etc..). The pointer
 *                                    is valid only for the callback
 *                                    lifetime.
 * @param body_chunk A pointer to a chunk of the HTTP body present in the
 *                   segment. It is valid only for the callback lifetime.
 * @param body_chunk_length           The length of the chunk.
 * @param pkt_informations            A pointer to the parsed packet.
 * @param flow_specific_user_data     A pointer to the user data specific
 *                                    to this flow.
 * @param user_data A pointer to the global HTTP user data.
 * @param last_chunk 0 if it is not the last chunk 1 otherwise.
 */
typedef void(pfwl_http_body_callback)(
    pfwl_http_message_informations_t* http_message_informations,
    const unsigned char* body_chunk, uint32_t body_chunk_length,
    pfwl_pkt_infos_t* pkt_informations, void** flow_specific_user_data,
    void* user_data, uint8_t last_chunk);

typedef struct pfwl_http_callbacks {
  /** Called on the HTTP request-URI. **/
  pfwl_http_header_url_callback* header_url_callback;

  /** The names of the headers types that the user wants to inspect. **/
  const char** header_names;

  /** The number of headers types that the user wants to inspect. **/
  uint8_t num_header_types;

  /**
   * The callbacks that will be invoked for the specified header fields.
   * header_types_callbacks[i] will be invoked when an header with name
   * header_names[i] is found. The user cannot make any assumption on
   * the order in which the callbacks will be invoked.
   */
  pfwl_http_header_field_callback** header_types_callbacks;

  /** Called on the entire HTTP body. **/
  pfwl_http_body_callback* http_body_callback;
} pfwl_http_callbacks_t;

typedef struct pfwl_http_internal_informations {
  pfwl_http_callbacks_t* callbacks;
  pfwl_pkt_infos_t* pkt_informations;
  void** flow_specific_user_data;
  void* user_data;
  char* temp_buffer;
  size_t temp_buffer_size;
} pfwl_http_internal_informations_t;

typedef struct pfwl_ssl_callbacks {
  pfwl_ssl_certificate_callback* certificate_callback;
} pfwl_ssl_callbacks_t;

typedef struct pfwl_ssl_internal_information {
  pfwl_ssl_callbacks_t* callbacks;
  void* callbacks_user_data;
  uint8_t* pkt_buffer;
  int pkt_size;
  uint8_t ssl_detected;
} pfwl_ssl_internal_information_t;

typedef struct pfwl_state pfwl_state_t;

  
/**
 * @brief A generic protocol inspector.
 * A generic protocol inspector.
 * @param state          A pointer to the state of the library.
 * @param pkt            A pointer to the parsed packet.
 * @param app_data       A pointer to the application payload.
 * @param data_length    The length of the application payload.
 * @param tracking       A pointer to the protocols tracking informations.
 * @return               PFWL_PROTOCOL_MATCHES if the protocol matches.
 *                       PFWL_PROTOCOL_NO_MATCHES if the protocol doesn't
 *                       matches.
 *                       PFWL_PROTOCOL_MORE_DATA_NEEDED if the inspector
 *                       needs more data to decide.
 *                       PFWL_ERROR if an error occurred.
 */
typedef uint8_t (*pfwl_inspector_callback)(
    pfwl_state_t* state, pfwl_pkt_infos_t* pkt,
    const unsigned char* app_data, uint32_t data_length,
    pfwl_tracking_informations_t* tracking);

typedef struct pfwl_l7_skipping_infos pfwl_l7_skipping_infos_t;

typedef enum {
  PFWL_INSPECTOR_ACCURACY_LOW = 0,
  PFWL_INSPECTOR_ACCURACY_MEDIUM,
  PFWL_INSPECTOR_ACCURACY_HIGH,
} pfwl_inspector_accuracy;

  
/**
 * Fields to be extracted for a given protocol.
 **/
typedef struct {
  /**
   * One flag per field.
   * If 1, the field is extracted. If 0, it is not extracted.
   **/
  uint8_t* fields;
  /**
   * Number of fields to extract.
   **/
  uint8_t fields_num;
} pfwl_fields_extraction_t;

  
/**
 * The handle to the library.
 **/
typedef struct pfwl_state {
  /********************************************************************/
  /** Created by pfwl_init_state and never modified                   **/
  /********************************************************************/
  void* db4;
  void* db6;

  /********************************************************************/
  /** Can be modified during the execution but only using the state  **/
  /** update functions. They are never modified in other places      **/
  /********************************************************************/
  char protocols_to_inspect[BITNSLOTS(PFWL_NUM_PROTOCOLS)];
  char active_callbacks[BITNSLOTS(PFWL_NUM_PROTOCOLS)]; // TODO: Remove, replaced with field_callbacks_lengths

  pfwl_protocol_l7 active_protocols;

  uint16_t max_trials;

  pfwl_flow_cleaner_callback* flow_cleaner_callback;

  void* callbacks_udata;

  /** HTTP callbacks. **/
  void* http_callbacks;
  void* http_callbacks_user_data;

  /** SSL callbacks **/
  void* ssl_callbacks;
  void* ssl_callbacks_user_data;

  /** SIP callbacks **/
  void* sip_callbacks;
  void* sip_callbacks_user_data;

  /** Field callbacks. **/
  pfwl_fields_extraction_t fields_extraction[PFWL_NUM_PROTOCOLS];

  uint8_t tcp_reordering_enabled : 1;

  /** L7 skipping information. **/
  pfwl_l7_skipping_infos_t* l7_skip;

  pfwl_inspector_accuracy inspectors_accuracy[PFWL_NUM_PROTOCOLS];

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
#ifdef WITH_PROMETHEUS
  void* prometheus_stats;
#endif
} pfwl_state_t;

  
/**
 * @brief Initializes Peafowl.
 * Initializes the state of the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols active.
 * @param size_v4 Size of the array of pointers used to build the database
 *                for v4 flows.
 * @param size_v6 Size of the array of pointers used to build the database
 *                for v6 flows.
 * @param max_active_v4_flows The maximum number of IPv4 flows which can
 *        be active at any time. After reaching this threshold, new flows
 *        will not be created.
 * @param max_active_v6_flows The maximum number of IPv6 flows which can
 *        be active at any time. After reaching this threshold, new flows
 *        will not be created.
 * @return A pointer to the state of the library otherwise.
 */
pfwl_state_t* pfwl_init_stateful(uint32_t size_v4, uint32_t size_v6,
                                       uint32_t max_active_v4_flows,
                                       uint32_t max_active_v6_flows);

  
/**
 * Initializes the state of the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols active.
 * @return A pointer to the state of the library otherwise.
 */
pfwl_state_t* pfwl_init_stateless(void);

  
/**
 * Terminates the library.
 * @param state A pointer to the state of the library.
 */
void pfwl_terminate(pfwl_state_t* state);

  
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
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded, PFWL_STATE_UPDATE_FAILURE
 *         otherwise.
 */
uint8_t pfwl_set_max_trials(pfwl_state_t* state, uint16_t max_trials);

  
/**
 * Enable IPv4 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv4
 *                     fragments informations.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded, PFWL_STATE_UPDATE_FAILURE
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
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded, PFWL_STATE_UPDATE_FAILURE
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
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_set_per_host_memory_limit(pfwl_state_t* state,
							  uint32_t per_host_memory_limit);

  
/**
 * Sets the amount of memory that a single host can use for IPv6
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                 any IPv6 host can use.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_set_per_host_memory_limit(pfwl_state_t* state,
							  uint32_t per_host_memory_limit);

  
/**
 * Sets the total amount of memory that can be used for IPv4
 * defragmentation.
 * If fragmentation is disabled and then enabled, this information must be
 * passed again.
 * Otherwise default value will be used.
 * @param state               A pointer to the state of the library
 * @param totel_memory_limit  The maximum amount of memory that can be used
 *                            for IPv4 defragmentation.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_set_total_memory_limit(pfwl_state_t* state,
						       uint32_t total_memory_limit);

  
/**
 * Sets the total amount of memory that can be used for IPv6
 * defragmentation. If fragmentation is disabled and then enabled, this
 * information must be passed again. Otherwise default value will be used.
 * @param state               A pointer to the state of the library
 * @param total_memory_limit  The maximum amount of memory that can be
 *                            used for IPv6 defragmentation.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_set_total_memory_limit(pfwl_state_t* state,
						       uint32_t total_memory_limit);

  
/**
 * Sets the maximum time (in seconds) that can be spent to reassembly an
 * IPv4 fragmented datagram. Is the maximum time gap between the first and
 * last fragments of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_set_reassembly_timeout(pfwl_state_t* state,
						       uint8_t timeout_seconds);

  
/**
 * Sets the maximum time (in seconds) that can be spent to reassembly an
 * IPv6 fragmented datagram. Is the maximum time gap between the first and
 * last fragments of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_set_reassembly_timeout(
    pfwl_state_t* state, uint8_t timeout_seconds);

  
/**
 * Disable IPv4 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv4_fragmentation_disable(pfwl_state_t* state);

  
/**
 * Disable IPv6 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ipv6_fragmentation_disable(pfwl_state_t* state);

  
/**
 * If enabled, the library will reorder out of order TCP packets
 * (enabled by default).
 * @param state  A pointer to the state of the library.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
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
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_tcp_reordering_disable(pfwl_state_t* state);

  
/**
 * Enable a protocol inspector.
 * @param state         A pointer to the state of the library.
 * @param protocol      The protocol to enable.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_enable_protocol(pfwl_state_t* state,
                            pfwl_protocol_l7 protocol);

  
/**
 * Disable a protocol inspector.
 * @param state       A pointer to the state of the library.
 * @param protocol    The protocol to disable.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_disable_protocol(pfwl_state_t* state,
			      pfwl_protocol_l7 protocol);

  
/**
 * Enable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_inspect_all(pfwl_state_t* state);

  
/**
 * Disable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
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
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_skip_L7_parsing_by_port(pfwl_state_t* state, uint8_t l4prot,
				     uint16_t port, pfwl_protocol_l7 id);

  
/**
 * Try to detect the application protocol.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   data_length Length of the packet (from the beginning of the IP
 *          header, without L2 headers/trailers).
 * @param   current_time The current time in seconds.
 * @return  The status of the operation.  It gives additional informations
 *          about the processing of the request. If lesser than 0, an error
 *          occurred. pfwl_get_error_msg() can be used to get a textual
 *          representation of the error. If greater or equal than 0 then
 *          it should not be interpreted as an error but simply gives
 *          additional informations (e.g. if the packet was IP fragmented,
 *          if it was out of order in the TCP stream, if is a segment of a
 *          larger application request, etc..). pfwl_get_status_msg() can
 *          be used to get a textual representation of the status. Status
 *          and error codes are defined above in this header file. If an
 *          error occurred, the other returned fields are not meaningful.
 *
 *          The application protocol identifier plus the transport
 *          protocol identifier. The application protocol identifier is
 *          relative to the specific transport protocol.
 *
 * 			The flow specific user data (possibly manipulated by the
 * 			user callbacks).
 */
pfwl_identification_result_t pfwl_get_protocol(pfwl_state_t* state,
					       const unsigned char* pkt,
					       uint32_t length,
					       uint32_t current_time);

  
/**
 * Extract from the packet the informations about source and destination
 * addresses, source and destination ports, L4 protocol and the offset
 * where the application data starts.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   data_length Length of the packet (from the beginning of the
 *          IP header, without L2 headers/trailers).
 * @param   pkt_infos The pointer to the packet infos. It will be filled
 *          by the library.
 * @param   current_time The current time in seconds. It must be
 *          non-decreasing between two consecutive calls.
 * @return  The status of the operation. It gives additional informations
 *          about the processing of the request. If lesser than 0, an
 *          error occurred. pfwl_get_error_msg() can be used to get a
 *          textual representation of the error. If greater or equal
 *          than 0 then it should not be interpreted as an error but
 *          simply gives additional informations (e.g. if the packet was
 *          IP fragmented, if it was out of order in the TCP stream, if is
 *          a segment of a larger application request, etc..).
 *          pfwl_get_status_msg() can be used to get a textual
 *          representation of the status. Status and error codes are
 *          defined above in this header file.
 *
 *          The status is PFWL_STATUS_IP_FRAGMENT if the datagram is a
 *          fragment. In this case, if IP fragmentation support is enabled,
 *          the library copied the content of the datagram, so if the user
 *          wants, he can release the resources used to store the datagram.
 *
 *          The status is PFWL_STATUS_IP_LAST_FRAGMENT if the received
 *          datagram allows the library to reconstruct a fragmented
 *          datagram. In this case, pkt_infos->pkt will contain a pointer
 *          to the recomposed datagram. This pointer will be different
 *          from p_pkt. The user should free() this pointer when it is no
 *          more needed (e.g. after calling
 *          pfwl_state*_get_app_protocol(..)).
 */
int8_t pfwl_parse_L3_L4_headers(pfwl_state_t* state,
				const unsigned char* p_pkt, uint32_t p_length,
				pfwl_pkt_infos_t* pkt_infos,
				uint32_t current_time);

  
/**
 * Try to detect the application protocol. Before calling it, a check on
 * L4 protocol should be done and the function should be called only if
 * the packet is TCP or UDP.
 * @param   state The pointer to the library state.
 * @param   pkt_infos The pointer to the packet infos.
 * @return  The status of the operation. It gives additional informations
 *          about the processing of the request. If lesser than 0, an
 *          error occurred. pfwl_get_error_msg() can be used to get a
 *          textual representation of the error. If greater or equal
 *          than 0 then it should not be interpreted as an error but
 *          simply gives additional informations (e.g. if the packet was
 *          IP fragmented, if it was out of order in the TCP stream, if is
 *          a segment of a larger application request, etc..).
 *          pfwl_get_status_msg() can be used to get a textual
 *          representation of the status. Status and error codes are
 *          defined above in this header file.
 *
 *          The status is PFWL_STATUS_IP_FRAGMENT if the datagram is a
 *          fragment. In this case, if IP fragmentation support is
 *          enabled, the library copied the content of the datagram, so if
 *          the user wants, he can release the resources used to store the
 *          datagram.
 *
 *          The status is PFWL_STATUS_IP_LAST_FRAGMENT if the received
 *          datagram allows the library to reconstruct a fragmented
 *          datagram. In this case, pkt_infos->pkt will contain a pointer
 *          to the recomposed datagram. This pointer will be different
 *          from p_pkt. The user should free() this pointer when it is no
 *          more needed (e.g. after calling
 *          pfwl_state*_get_app_protocol(..)).
 */
pfwl_identification_result_t pfwl_stateful_get_app_protocol(pfwl_state_t* state,
							    pfwl_pkt_infos_t* pkt_infos);

  
/**
 * Try to detect the application protocol. Before calling it, a check on
 * L4 protocol should be done and the function should be called only if
 * the packet is TCP or UDP. It should be used if the application already
 * has the concept of 'flow'. In this case the first time that the flow is
 * passed to the call, it must be initialized with
 * pfwl_init_flow_infos(...).
 * @param   state The pointer to the library state.
 * @param   flow The informations about the flow. They must be kept by the
 *               user.
 * @param   pkt_infos The pointer to the packet infos.
 * @return  The status of the operation. It gives additional informations
 *          about the processing of the request. If lesser than 0, an error
 *          occurred. pfwl_get_error_msg() can be used to get a textual
 *          representation of the error. If greater or equal than 0 then
 *          it should not be interpreted as an error but simply gives
 *          additional informations (e.g. if the packet was IP fragmented,
 *          if it was out of order in the TCP stream, if is a segment of
 *          a larger application request, etc..). pfwl_get_status_msg()
 *          can be used to get a textual representation of the status.
 *          Status and error codes are defined above in this header file.
 *
 *          The status is PFWL_STATUS_IP_FRAGMENT if the datagram is a
 *          fragment. In this case, if IP fragmentation support is
 *          enabled, the library copied the content of the datagram, so if
 *          the user wants, he can release the resources used to store the
 *          datagram.
 *
 *          The status is PFWL_STATUS_IP_LAST_FRAGMENT if the received
 *          datagram allows the library to reconstruct a fragmented
 *          datagram. In this case, pkt_infos->pkt will contain a pointer
 *          to the recomposed datagram. This pointer will be different
 *          from p_pkt. The user should free() this pointer when it is no
 *          more needed (e.g. after calling
 *          pfwl_state*_get_app_protocol(..)).
 */
  pfwl_identification_result_t pfwl_stateless_get_app_protocol(pfwl_state_t* state,
							       pfwl_flow_infos_t* flow,
							       pfwl_pkt_infos_t* pkt_infos);

  
/**
 * Initialize the flow informations passed as argument.
 * @param state       A pointer to the state of the library.
 * @param flow_infos  The informations that will be initialized by the
 *                    library.
 * @param l4prot      The transport protocol identifier.
 */
void pfwl_init_flow_infos(pfwl_state_t* state,
                         pfwl_flow_infos_t* flow_infos, uint8_t l4prot);

  
/**
 * Try to guess the protocol looking only at source/destination ports.
 * This could be erroneous because sometimes protocols run over ports
 * which are not their well-known ports.
 * @param    pkt_infos The pointer to the packet infos.
 * @return   Returns the possible matching protocol.
 */
pfwl_protocol_l7 pfwl_guess_protocol(pfwl_pkt_infos_t* pkt_infos);

  
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
const char* const pfwl_get_protocol_string(pfwl_protocol_l7 protocol);

  
/**
 * Returns the protocol id corresponding to a protocol string.
 * @param string The protocols tring.
 * @return The protocol id corresponding to a protocol string.
 */
pfwl_protocol_l7 pfwl_get_protocol_id(const char* const string);

  
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
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_set_flow_cleaner_callback(pfwl_state_t* state,
                                      pfwl_flow_cleaner_callback* cleaner);

  
/**
 * Activate HTTP callbacks. When a protocol is identified the default
 * behavior is to not inspect the packets belonging to that flow anymore
 * and keep simply returning the same protocol identifier.
 *
 * If a callback is enabled for a certain protocol, then we keep
 * inspecting all the new flows with that protocol in order to invoke
 * the callbacks specified by the user on the various parts of the
 * message. Moreover, if the application protocol uses TCP, then we have
 * the additional cost of TCP reordering for all the segments. Is highly
 * recommended to enable TCP reordering if it is not already enabled
 * (remember that is enabled by default). Otherwise the informations
 * extracted could be erroneous/incomplete.
 *
 * The pointers to the data passed to the callbacks are valid only for the
 * duration of the callback.
 *
 * @param state       A pointer to the state of the library.
 * @param callbacks   A pointer to HTTP callbacks.
 * @param user_data   A pointer to global user HTTP data. This pointer
 *                    will be passed to any HTTP callback when it is
 *                    invoked.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 *
 **/
uint8_t pfwl_http_activate_callbacks(pfwl_state_t* state,
                                    pfwl_http_callbacks_t* callbacks,
                                    void* user_data);

  
/**
 * Disable the HTTP callbacks. user_data is not freed/modified.
 * @param state       A pointer to the state of the library.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_http_disable_callbacks(pfwl_state_t* state);

  
/**
    SSL callbacks.
**/
/**
 * Activate SSL callbacks. When a protocol is identified the default
 * behavior is to not inspect the packets belonging to that flow anymore
 * and keep simply returning the same protocol identifier.
 *
 * If a callback is enabled for a certain protocol, then we keep
 * inspecting all the new flows with that protocol in order to invoke
 * the callbacks specified by the user on the various parts of the
 * message. Moreover, if the application protocol uses TCP, then we have
 * the additional cost of TCP reordering for all the segments. Is highly
 * recommended to enable TCP reordering if it is not already enabled
 * (remember that is enabled by default). Otherwise the informations
 * extracted could be erroneous/incomplete.
 *
 * The pointers to the data passed to the callbacks are valid only for the
 * duration of the callback.
 *
 * @param state       A pointer to the state of the library.
 * @param callbacks   A pointer to SSL callbacks.
 * @param user_data   A pointer to global user SSL data. This pointer
 *                    will be passed to any SSL callback when it is
 *                    invoked.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 *
 **/
uint8_t pfwl_ssl_activate_callbacks(pfwl_state_t* state,
                                   pfwl_ssl_callbacks_t* callbacks,

				    void* user_data);
/**
 * Disable the SSL callbacks. user_data is not freed/modified.
 * @param state       A pointer to the state of the library.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_ssl_disable_callbacks(pfwl_state_t* state);

  
/**
 * Set a field callback for a given protocol.
 * When a protocol is identified the default
 * behavior is to not inspect the packets belonging to that flow anymore
 * and keep simply returning the same protocol identifier.
 *
 * If a callback is enabled for a certain protocol, then we keep
 * inspecting all the new packets of that flow in order to invoke
 * the callbacks specified by the user on the various parts of the
 * message. Moreover, if the application protocol uses TCP, then we have
 * the additional cost of TCP reordering for all the segments. Is highly
 * recommended to enable TCP reordering if it is not already enabled
 * (remember that is enabled by default). Otherwise the informations
 * extracted could be erroneous/incomplete.
 *
 * The pointers to the data passed to the callbacks are valid only for the
 * duration of the callback. If the user needs to preserve the data, a copy
 * needs to be done.
 *
 * @param state        A pointer to the state of the library.
 * @param protocol     The protocol.
 * @param field_type   The field (check the enum for that specific protocol).
 * @param callback     The callback.
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 *
 **/
uint8_t pfwl_protocol_field_add(pfwl_state_t* state,
                                pfwl_protocol_l7 protocol,
                                int field_type);

  
/**
 * Disable the protocol field callback. udata is not freed/modified.
 * @param state        A pointer to the state of the library.
 * @param protocol     The protocol.
 * @param field_type   The field (check the enum for that specific protocol).
 *
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_protocol_field_remove(pfwl_state_t* state,
                                    pfwl_protocol_l7 protocol,
                                    int field_type);

  
/**
 * Checks if the extraction of a specific field for a given protocol has been
 * required.
 * @param state        A pointer to the state of the library.
 * @param protocol     The protocol.
 * @param field_type   The field (check the enum for that specific protocol).
 * @return 1 if the field has been required, 0 otherwise.
 */
uint8_t pfwl_protocol_field_required(pfwl_state_t* state,
                                      pfwl_protocol_l7 protocol,
                                      int field_type);

  
/**
 * Adds a pointer to some data which will be passed as parameter to all
 * the fields callbacks.
 * @param state A pointer to the state of the library.
 * @param udata
 * @return
 */
uint8_t pfwl_callbacks_fields_set_udata(pfwl_state_t* state,
                                 void* udata);


/**
 * Some protocols inspector (e.g. SIP) can be applied with a different
 * level of accuracy (and of processing time). By using this call
 * the user can decide if running the inspector in its most accurate
 * version (at the cost of a higher processing latency).
 * @param state       A pointer to the state of the library.
 * @param protocol    The protocol for which we want to change the accuracy.
 * @param accuracy    The accuracy level.
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_set_protocol_accuracy(pfwl_state_t* state,
                                  pfwl_protocol_l7 protocol,
                                  pfwl_inspector_accuracy accuracy);

  
/**
 * Initializes the exporter to Prometheus DB.
 * @param state       A pointer to the state of the library.
 * @param port        The port on which the server should listen.
 * @return PFWL_STATE_UPDATE_SUCCESS if succeeded,
 *         PFWL_STATE_UPDATE_FAILURE otherwise.
 */
uint8_t pfwl_prometheus_init(pfwl_state_t* state, uint16_t port);

/****************************************/
/** Only to be used directly by mcdpi. **/
/****************************************/

/**
 * Initializes the state of the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols active.
 * Using this API, the hash table is divided in num_table_partitions
 * partitions. These partitions can be accessed concurrently in a thread
 * safe way from different threads if and only if each thread access only
 * to its partition.
 * @param size_v4 Size of the array of pointers used to build the database
 *        for v4 flows.
 * @param size_v6 Size of the array of pointers used to build the database
 *        for v6 flows.
 * @param max_active_v4_flows The maximum number of IPv4 flows which can
 *        be active at any time. After reaching this threshold, new flows
 *        will not be created.
 * @param max_active_v6_flows The maximum number of IPv6 flows which can
 *        be active at any time. After reaching this threshold, new flows
 *        will not be created.
 * @param num_table_partitions The number of partitions of the hash table.
 * @return A pointer to the state of the library otherwise.
 */
pfwl_state_t* pfwl_init_stateful_num_partitions(uint32_t size_v4,
						uint32_t size_v6,
						uint32_t max_active_v4_flows,
						uint32_t max_active_v6_flows,
						uint16_t num_table_partitions);


/**
 * Extract from the packet the informations about source and destination
 * addresses, source and destination ports, L4 protocol and the offset
 * where the application data starts.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   data_length Length of the packet (from the beginning of the
 *          IP header, without L2 headers/trailers).
 * @param   pkt_infos The pointer to the packet infos. It will be filled
 *          by the library.
 * @param   current_time The current time in seconds. It must be
 *          non-decreasing between two consecutive calls.
 * @param	tid The thread identifier.
 * @return  The status of the operation. It gives additional informations
 *          about the processing of the request. If lesser than 0, an
 *          error occurred. pfwl_get_error_msg() can be used to get a
 *          textual representation of the error. If greater or equal than
 *          0 then it should not be interpreted as an error but simply
 *          gives additional informations (e.g. if the packet was IP
 *          fragmented, if it was out of order in the TCP stream, if is a
 *          segment of a larger application request, etc..).
 *          pfwl_get_status_msg() can be used to get a textual
 *          representation of the status. Status and error codes are
 *          defined above in this header file.
 *
 *          The status is PFWL_STATUS_IP_FRAGMENT if the datagram is a
 *          fragment. In this case, if IP fragmentation support is
 *          enabled, the library copied the content of the datagram, so if
 *          the user wants, he can release the resources used to store the
 *          datagram.
 *
 *          The status is PFWL_STATUS_IP_LAST_FRAGMENT if the received
 *          datagram allows the library to reconstruct a fragmented
 *          datagram. In this case, pkt_infos->pkt will contain a pointer
 *          to the recomposed datagram. This pointer will be different
 *          from p_pkt. The user should free() this pointer when it is no
 *          more needed (e.g. after calling
 *          pfwl_state*_get_app_protocol(..)).
 */
int8_t mc_pfwl_extract_packet_infos(pfwl_state_t* state,
                                   const unsigned char* p_pkt,
                                   uint32_t p_length,
                                   pfwl_pkt_infos_t* pkt_infos,
                                   uint32_t current_time, int tid);

/**
 * Given a packet, return the ip offset after dissecting the datalink header.
 * @param  packet         The pointer to the raw packet
 * @param  packet header  The struct representing the packet header
 * @return the length of the ip offset (aka the size of datalink header)
 */
uint32_t pfwl_parse_datalink(const u_char* packet, struct pcap_pkthdr header);
  

#ifdef __cplusplus
}
#endif

#endif
