/*
 * flow_table.h
 *
 * Created on: 22/10/2012
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

#ifndef FLOW_TABLE_H_
#define FLOW_TABLE_H_

#include <peafowl/peafowl.h>
#include <peafowl/config.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dpi_sip_miprtcpstatic {
  char media_ip_s[30];
  int media_ip_len;
  int media_port;
  char rtcp_ip_s[30];
  int rtcp_ip_len;
  int rtcp_port;
  int prio_codec;
} dpi_sip_miprtcpstatic_t;

typedef struct {
  const char* s;
  size_t len;
} pfwl_field_t;

typedef struct dpi_sip_miprtcp {
  pfwl_field_t media_ip;
  int media_port;
  pfwl_field_t rtcp_ip;
  int rtcp_port;
  int prio_codec;
} dpi_sip_miprtcp_t;

struct dip_sip_codecmap;

typedef struct dip_sip_codecmap {
  char name[120];
  int id;
  int rate;
  struct dip_sip_codecmap* next;
} dpi_sip_codecmap_t;

typedef enum {
  UNKNOWN = 0,
  CANCEL = 1,
  ACK = 2,
  INVITE = 3,
  BYE = 4,
  INFO = 5,
  REGISTER = 6,
  SUBSCRIBE = 7,
  NOTIFY = 8,
  MESSAGE = 9,
  OPTIONS = 10,
  PRACK = 11,
  UPDATE = 12,
  REFER = 13,
  PUBLISH = 14,
  RESPONSE = 15,
  SERVICE = 16
} dpi_sip_method_t;

#define DPI_SIP_MAX_MEDIA_HOSTS 20

typedef struct {
  const char* name;
  pfwl_field_t value;
  UT_hash_handle hh;         /* makes this structure hashable */
} pfwl_sip_indexed_field_t;

typedef struct dpi_sip_internal_information {
  unsigned int responseCode;
  pfwl_sip_indexed_field_t* indexed_fields;
  uint8_t isRequest;
  uint8_t validMessage;
  dpi_sip_method_t methodType;
  uint8_t hasSdp;
  dpi_sip_codecmap_t cdm[DPI_SIP_MAX_MEDIA_HOSTS];
  dpi_sip_miprtcpstatic_t mrp[DPI_SIP_MAX_MEDIA_HOSTS];
  int cdm_count;
  unsigned int mrp_size;
  unsigned int contentLength;
  unsigned int len;
  unsigned int cSeqNumber;
  uint8_t hasVqRtcpXR;
  dpi_sip_method_t cSeqMethod;

  pfwl_field_t callId;
  pfwl_field_t reason;
  pfwl_field_t rtcpxr_callid;
  pfwl_field_t cSeqMethodString;
  pfwl_field_t cSeq;
  pfwl_field_t via;
  pfwl_field_t contactURI;
  /* extra */
  pfwl_field_t ruriUser;
  pfwl_field_t ruriDomain;
  pfwl_field_t fromUser;
  pfwl_field_t fromDomain;
  pfwl_field_t toUser;
  pfwl_field_t toDomain;
  pfwl_field_t paiUser;
  pfwl_field_t paiDomain;
  pfwl_field_t pidURI;
  pfwl_field_t fromURI;
  pfwl_field_t toURI;
  pfwl_field_t ruriURI;
  pfwl_field_t toTag;
  pfwl_field_t fromTag;
} dpi_sip_internal_information_t;

/** This must be initialized to zero before use. **/
typedef struct dpi_tracking_informations {
  /**
   *  This data is passed to the user when a callback is invoked. It can
   *  be used by the user to read/write flow specific informations or
   *  informations which must be passed from one callback to another
   *  (E.g. subprotocols informations). It is returned to the user when
   *  dpi_state*_identify_application_protocol() is invoked.
   **/
  void* flow_specific_user_data;

  size_t num_packets; // Number of packets received for the flow

  /*********************************/
  /** TCP Tracking informations.  **/
  /*********************************/
  /**
   * The expected sequence numbers in the two directions.
   * (Stored in host byte order).
   **/
  uint32_t expected_seq_num[2];
  /** A pointer to out of order segments. **/
  dpi_reassembly_fragment_t* segments[2];

  /** Three-way handshake tracking informations. **/
  uint8_t seen_syn : 1;
  uint8_t seen_syn_ack : 1;
  uint8_t seen_ack : 1;

  /** Connection termination tracking informations. **/
  uint8_t seen_fin : 2;
  uint8_t seen_rst : 1;

  uint8_t first_packet_arrived : 2;
  uint32_t highest_ack[2];

  /************************************/
  /* Protocol inspectors support data */
  /************************************/

  /*********************************/
  /** DNS Tracking informations. **/
  /*********************************/
  uint8_t dns_stage : 2;
  /* TODO dns infos */

  /*********************************/
  /** SSH Tracking informations. **/
  /*********************************/
  uint8_t ssh_stage : 2;
  char *ssh_client_signature, *ssh_server_signature;

  /*********************************/
  /** HTTP Tracking informations. **/
  /*********************************/
  /** One HTTP parser per direction. **/
  http_parser http[2];
  dpi_http_internal_informations_t http_informations[2];

  /*********************************/
  /** SMTP Tracking informations. **/
  /*********************************/
  uint8_t num_smtp_matched_messages : 2;

  /*********************************/
  /** SIP Tracking informations.  **/
  /*********************************/
  dpi_sip_internal_information_t sip_informations;

  /*********************************/
  /** POP3 Tracking informations. **/
  /*********************************/
  uint8_t num_pop3_matched_messages : 2;

  /**********************************/
  /** IMAP Tracking informations.  **/
  /**********************************/
  uint8_t imap_starttls : 2;
  uint8_t imap_stage : 3;

  /*********************************/
  /** SSL Tracking informations. **/
  /*********************************/
  dpi_ssl_internal_information_t ssl_information[2];

  /**************************************/
  /** WhatsApp Tracking informations.  **/
  /**************************************/
  size_t whatsapp_matched_sequence;

  /**********************************/
  /** Protocols extracted fields.  **/
  /**********************************/
  pfwl_field_t extracted_fields_sip[DPI_FIELDS_SIP_NUM];
} dpi_tracking_informations_t;

/**
 * If stateless version is used, this structure the first time must be
 * initialized with 'dpi_init_flow_infos'.
 **/
typedef struct dpi_flow_infos {
  /** The possible number of l7 protocols that match with this flow. **/
  uint8_t possible_protocols;

  /**
   * The protocol of this flow. It can be DPI_PROTOCOL_NOT_DETERMINED if
   * it is not been yet determined; DPI_PROTOCOL_UNKNOWN if it is unknown
   * or the matching protocol identifier.
   */
  dpi_l7_prot_id l7prot;

  /** Number of times that the library tried to guess the protocol. **/
  uint16_t trials;
  /**
   * Contains the possible matching protocols for the flow (At the first
   * iteration the mask contains all the active protocols. During the
   * successive iterations we remove from the mask the protocols which
   * surely don't match).
   **/
  char possible_matching_protocols[BITNSLOTS(DPI_NUM_PROTOCOLS)];

  /**
   * In this way if a flow was created when TCP reordering was enabled,
   * we will continue doing TCP reordering for this flow also if it is
   * disabled. Basically the change in TCP reordering enabling/disabling
   * will be applied only to new flows.
   */
  uint8_t tcp_reordering_enabled : 1;
  dpi_tracking_informations_t tracking;
#ifdef WITH_PROMETHEUS
  void* prometheus_counter_packets;
  void* prometheus_counter_bytes;
#endif
} dpi_flow_infos_t;

typedef struct ipv4_flow ipv4_flow_t;
typedef struct ipv6_flow ipv6_flow_t;

struct ipv4_flow {
  uint16_t srcport;
  uint16_t dstport;
  uint32_t srcaddr;
  uint32_t dstaddr;
  uint8_t l4prot;

  ipv4_flow_t* prev;
  ipv4_flow_t* next;
  dpi_flow_infos_t infos;
  uint32_t last_timestamp;
};

struct ipv6_flow {
  uint16_t srcport;
  uint16_t dstport;
  struct in6_addr srcaddr;
  struct in6_addr dstaddr;
  uint8_t l4prot;

  ipv6_flow_t* prev;
  ipv6_flow_t* next;
  dpi_flow_infos_t infos;
  uint32_t last_timestamp;
};

typedef struct dpi_flow_DB_v4 dpi_flow_DB_v4_t;
typedef struct dpi_flow_DB_v6 dpi_flow_DB_v6_t;

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
dpi_flow_DB_v4_t* dpi_flow_table_create_v4(uint32_t size,
                                           uint32_t max_active_v4_flows,
                                           uint16_t num_partitions,
                                           uint32_t start_pool_size);
dpi_flow_DB_v6_t* dpi_flow_table_create_v6(uint32_t size,
                                           uint32_t max_active_v6_flows,
                                           uint16_t num_partitions,
                                           uint32_t start_pool_size);

#else
dpi_flow_DB_v4_t* dpi_flow_table_create_v4(uint32_t size,
                                           uint32_t max_active_v4_flows,
                                           uint16_t num_partitions);
dpi_flow_DB_v6_t* dpi_flow_table_create_v6(uint32_t size,
                                           uint32_t max_active_v6_flows,
                                           uint16_t num_partitions);
#endif

void dpi_flow_table_delete_v4(dpi_flow_DB_v4_t* db,
                              dpi_flow_cleaner_callback* flow_cleaner_callback);
void dpi_flow_table_delete_v6(dpi_flow_DB_v6_t* db,
                              dpi_flow_cleaner_callback* flow_cleaner_callback);

/**
 * Search for a flow in the table.
 * @param state A pointer to the state of the library.
 * @param index The hash index of the flow to search.
 * @param pkt_infos The L3 and L4 packet's parsed informations.
 * @return A pointer to the flow if it is present, NULL otherwise.
 */
ipv4_flow_t* dpi_flow_table_find_flow_v4(dpi_library_state_t* state,
                                         uint32_t index,
                                         dpi_pkt_infos_t* pkt_infos);

/**
 * Search for a flow in the table.
 * @param state A pointer to the state of the library.
 * @param index The hash index of the flow to search.
 * @param pkt_infos The L3 and L4 packet's parsed informations.
 * @return A pointer to the flow if it is present, NULL otherwise.
 */
ipv6_flow_t* dpi_flow_table_find_flow_v6(dpi_library_state_t* state,
                                         uint32_t index,
                                         dpi_pkt_infos_t* pkt_infos);

/**
 * Find the flow to which pkt_infos belongs or creates it if doesn't
 * exists. Updates pkt_infos->direction field according to the direction
 * of the stored flow.
 * @return The informations about the flow.
 */
ipv4_flow_t* dpi_flow_table_find_or_create_flow_v4(dpi_library_state_t* state,
                                                   dpi_pkt_infos_t* pkt_infos);
ipv6_flow_t* dpi_flow_table_find_or_create_flow_v6(dpi_library_state_t* state,
                                                   dpi_pkt_infos_t* pkt_infos);

void dpi_flow_table_delete_flow_v4(
    dpi_flow_DB_v4_t* db, dpi_flow_cleaner_callback* flow_cleaner_callback,
    ipv4_flow_t* to_delete);

void dpi_flow_table_delete_flow_v6(
    dpi_flow_DB_v6_t* db, dpi_flow_cleaner_callback* flow_cleaner_callback,
    ipv6_flow_t* to_delete);

/**
 * They are used directly only in mc_dpi. Should never be used directly
 * by the user.
 **/
uint32_t dpi_compute_v4_hash_function(dpi_flow_DB_v4_t* db,
                                      const dpi_pkt_infos_t* const pkt_infos);

uint32_t dpi_compute_v6_hash_function(dpi_flow_DB_v6_t* db,
                                      const dpi_pkt_infos_t* const pkt_infos);

ipv4_flow_t* mc_dpi_flow_table_find_or_create_flow_v4(
    dpi_library_state_t* state, uint16_t partition_id, uint32_t index,
    dpi_pkt_infos_t* pkt_infos);

ipv6_flow_t* mc_dpi_flow_table_find_or_create_flow_v6(
    dpi_library_state_t* state, uint16_t partition_id, uint32_t index,
    dpi_pkt_infos_t* pkt_infos);

void dpi_flow_table_setup_partitions_v4(dpi_flow_DB_v4_t* table,
                                        uint16_t num_partitions);

void dpi_flow_table_setup_partitions_v6(dpi_flow_DB_v6_t* table,
                                        uint16_t num_partitions);

void mc_dpi_flow_table_delete_flow_v4(
    dpi_flow_DB_v4_t* db, dpi_flow_cleaner_callback* flow_cleaner_callback,
    uint16_t partition_id, ipv4_flow_t* to_delete);

void mc_dpi_flow_table_delete_flow_v6(
    dpi_flow_DB_v6_t* db, dpi_flow_cleaner_callback* flow_cleaner_callback,
    uint16_t partition_id, ipv6_flow_t* to_delete);

#ifdef __cplusplus
}
#endif

#endif /* FLOW_TABLE_H_ */
