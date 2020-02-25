/*
 * flow_table.h
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

#ifndef FLOW_TABLE_H_
#define FLOW_TABLE_H_

#include <peafowl/config.h>
#include <peafowl/external/utils/uthash.h>
#include <peafowl/inspectors/http_parser_joyent.h>
#include <peafowl/peafowl.h>
#include <peafowl/reassembly.h>

#ifdef __cplusplus
extern "C" {
#endif

/******************* SIP ********************/
typedef struct pfwl_sip_miprtcpstatic {
  char media_ip_s[30];
  int media_ip_len;
  int media_port;
  char rtcp_ip_s[30];
  int rtcp_ip_len;
  int rtcp_port;
  int prio_codec;
} pfwl_sip_miprtcpstatic_t;

typedef struct pfwl_sip_miprtcp {
  pfwl_field_t media_ip;
  int media_port;
  pfwl_field_t rtcp_ip;
  int rtcp_port;
  int prio_codec;
} pfwl_sip_miprtcp_t;

struct dip_sip_codecmap;

typedef struct dip_sip_codecmap {
  char name[120];
  int id;
  int rate;
  struct dip_sip_codecmap *next;
} pfwl_sip_codecmap_t;

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
} pfwl_sip_method_t;

#define PFWL_SIP_MAX_MEDIA_HOSTS 20

typedef struct {
  const char *name;
  pfwl_field_t value;
  UT_hash_handle hh; /* makes this structure hashable */
} pfwl_sip_indexed_field_t;

typedef struct pfwl_sip_internal_information {
  unsigned int responseCode;
  pfwl_sip_indexed_field_t *indexed_fields;
  uint8_t isRequest;
  uint8_t validMessage;
  pfwl_sip_method_t methodType;
  uint8_t hasSdp;
  pfwl_sip_codecmap_t cdm[PFWL_SIP_MAX_MEDIA_HOSTS];
  pfwl_sip_miprtcpstatic_t mrp[PFWL_SIP_MAX_MEDIA_HOSTS];
  int cdm_count;
  unsigned int mrp_size;
  unsigned int contentLength;
  unsigned int len;
  unsigned int cSeqNumber;
  uint8_t hasVqRtcpXR;
  pfwl_sip_method_t cSeqMethod;
  uint8_t hasTo;
  uint8_t hasFrom;
  uint8_t hasCseq;
  uint8_t hasCallid;
} pfwl_sip_internal_information_t;
/***************** SIP (end) ******************/

/********************** DNS ************************/
typedef struct pfwl_dns_internal_information {
  uint8_t Type;     // query type (0 query 1 answer)
  uint8_t aType;    // host answer type
  uint8_t authType; // authoritative answer type
  uint8_t rCode;    // response type to the query (0-5)

} pfwl_dns_internal_information_t;
/******************** DNS (end) ******************/

/********************** HTTP ************************/
typedef struct pfwl_http_internal_informations {
  unsigned char *temp_buffer;
  size_t temp_buffer_size;
  uint8_t temp_buffer_dirty;
  pfwl_pair_t headers[PFWL_HTTP_MAX_HEADERS];
  size_t headers_length;
} pfwl_http_internal_informations_t;
/********************** HTTP (END) ************************/

/********************** SSL ************************/
typedef enum{
  PFWL_SSLV2 = 0,
  PFWL_SSLV3,
  PFWL_TLSV1_2
}pfwl_ssl_version_t;

typedef struct pfwl_ssl_internal_information_new {
  uint8_t stage;
  uint8_t certificate_num_checks;
  uint8_t certificates_detected;
  unsigned char first_bytes[2][6];
  uint8_t next_first_bytes[2];
  uint32_t processed_bytes[2];
  uint32_t next_server_extension;
  uint32_t remaining_extension_len;
  pfwl_ssl_version_t version;
} pfwl_ssl_internal_information_t;
/********************** SSL (END) ************************/

typedef struct pfwl_flow pfwl_flow_t;

typedef void (*pfwl_flow_cleaner_dissectors)(pfwl_flow_info_private_t *flow_info_private);

/** This must be initialized to zero before use. **/
typedef struct pfwl_flow_info_private {
  void *udata_private;

  /************************/
  /** Misc information.  **/
  /************************/
  pfwl_flow_info_t *info_public;
  pfwl_flow_t *flow;
  uint8_t identification_terminated;

  /** Number of times that the library tried to guess the protocol. **/
  uint16_t trials;
  /** The possible number of l7 protocols that match with this flow. **/
  uint8_t possible_protocols;

  /**
   * Contains the possible matching protocols for the flow (At the first
   * iteration the mask contains all the active protocols. During the
   * successive iterations we remove from the mask the protocols which
   * surely don't match).
   **/
  char possible_matching_protocols[BITNSLOTS(PFWL_PROTO_L7_NUM)];

  const unsigned char *last_rebuilt_ip_fragments; // For internal use only.

  /********************************/
  /** TCP Tracking information.  **/
  /********************************/
  const unsigned char *last_rebuilt_tcp_data;
  /**
   * The expected sequence numbers in the two directions.
   * (Stored in host byte order).
   **/
  uint32_t expected_seq_num[2];

  /** Last sequence number saw in each direction. **/
  uint32_t last_seq[2];

  /** Last ack number saw in each direction. **/
  uint32_t last_ack[2];

  /** A pointer to out of order segments. **/
  pfwl_reassembly_fragment_t *segments[2];

  /**
   * In this way if a flow was created when TCP reordering was enabled,
   * we will continue doing TCP reordering for this flow also if it is
   * disabled. Basically the change in TCP reordering enabling/disabling
   * will be applied only to new flows.
   */
  uint8_t tcp_reordering_enabled : 1;
  /** Three-way handshake tracking informations. **/
  uint8_t seen_syn : 1;
  uint8_t seen_syn_ack : 1;
  uint8_t seen_ack : 1;

  /** Connection termination tracking informations. **/
  uint8_t seen_fin : 2;
  uint8_t seen_rst : 1;
  uint8_t seen_fin_ack : 1;

  uint8_t first_packet_arrived : 2;
  uint32_t highest_ack[2];

  uint32_t synack_acknum; 

  double timestamp_last_payload[2]; // Timestamp of the last non-zero payload packet received

  /************************************/
  /* Protocol inspectors support data */
  /************************************/
  pfwl_flow_cleaner_dissectors flow_cleaners_dissectors[PFWL_PROTO_L7_NUM];

  /*********************************/
  /** DNS Tracking information   **/
  /*********************************/
  pfwl_dns_internal_information_t dns_informations;

  /*********************************/
  /** SSH Tracking information   **/
  /*********************************/
  uint8_t ssh_stage : 2;
  char *ssh_client_signature, *ssh_server_signature;

  /*********************************/
  /** HTTP Tracking information   **/
  /*********************************/
  /** One HTTP parser per direction. **/
  http_parser http[2];
  pfwl_http_internal_informations_t http_informations[2];

  /*********************************/
  /** SMTP Tracking information   **/
  /*********************************/
  uint8_t num_smtp_matched_messages : 2;

  /*********************************/
  /** SIP Tracking information    **/
  /*********************************/
  pfwl_sip_internal_information_t sip_informations;

  /*********************************/
  /** POP3 Tracking information   **/
  /*********************************/
  uint8_t num_pop3_matched_messages : 2;

  /**********************************/
  /** IMAP Tracking information    **/
  /**********************************/
  uint8_t imap_starttls : 2;
  uint8_t imap_stage : 3;

  /*********************************/
  /** SSL Tracking information    **/
  /*********************************/
  pfwl_ssl_internal_information_t ssl_information;

  /**************************************/
  /** WhatsApp Tracking information    **/
  /**************************************/
  size_t whatsapp_matched_sequence;

  /*****************************************/
  /** JSON-RPC and depending protos info. **/
  /*****************************************/
  void* json_parser;
  void* json_stringbuffers[PFWL_FIELDS_L7_JSON_RPC_LAST - PFWL_FIELDS_L7_JSON_RPC_FIRST - 1];

  /***************************************/
  /** STUN tracking information         **/
  /***************************************/
  char stun_mapped_address[INET6_ADDRSTRLEN];
} pfwl_flow_info_private_t;

struct pfwl_flow {
  pfwl_flow_t *prev;
  pfwl_flow_t *next;
  pfwl_flow_info_t info;
  pfwl_flow_info_private_t info_private;
};

typedef struct pfwl_flow_table pfwl_flow_table_t;

#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
pfwl_flow_table_t *pfwl_flow_table_create(uint32_t size,
                                          uint32_t max_active_v4_flows,
                                          uint16_t num_partitions,
                                          uint32_t start_pool_size);

#else
pfwl_flow_table_t *pfwl_flow_table_create(uint32_t expected_flows,
                                          pfwl_flows_strategy_t strategy,
                                          uint16_t num_partitions);
#endif

void pflw_flow_table_set_flow_cleaner_callback(
    pfwl_flow_table_t *db, pfwl_flow_cleaner_callback_t *flow_cleaner_callback);

void pflw_flow_table_set_flow_termination_callback(
    pfwl_flow_table_t *db, pfwl_flow_termination_callback_t *flow_termination_callback);

void pfwl_flow_table_delete(pfwl_flow_table_t *db, pfwl_timestamp_unit_t unit);


pfwl_flow_t *pfwl_flow_table_find_flow(pfwl_flow_table_t *db, uint32_t index,
                                       pfwl_dissection_info_t *pkt_info);

pfwl_flow_t *pfwl_flow_table_find_or_create_flow(pfwl_flow_table_t *db, pfwl_dissection_info_t *pkt_info,
    char *protocols_to_inspect, uint8_t tcp_reordering_enabled,
    double timestamp, uint8_t syn, pfwl_timestamp_unit_t unit);

void pfwl_flow_table_delete_flow(pfwl_flow_table_t *db, pfwl_flow_t *to_delete, pfwl_timestamp_unit_t unit);
void pfwl_flow_table_delete_flow_later(pfwl_flow_table_t *db,
                                       pfwl_flow_t *to_delete);

/**
 * They are used directly only in mc_dpi. Should never be used directly
 * by the user.
 **/
uint32_t
pfwl_compute_v4_hash_function(pfwl_flow_table_t *db,
                              const pfwl_dissection_info_t *const pkt_info);

uint32_t
pfwl_compute_v6_hash_function(pfwl_flow_table_t *db,
                              const pfwl_dissection_info_t *const pkt_info);

void pfwl_init_flow_info_internal(pfwl_flow_info_private_t *flow_info_private,
                                  char *protocols_to_inspect,
                                  uint8_t tcp_reordering_enabled);
void pfwl_init_flow(pfwl_flow_t* flow,
                    const pfwl_dissection_info_t *dissection_info,
                    char *protocols_to_inspect,
                    uint8_t tcp_reordering_enabled,
                    uint64_t id,
                    uint32_t id_hash,
                    uint16_t thread_id);

void pfwl_flow_table_setup_partitions(pfwl_flow_table_t *table,
                                      uint16_t num_partitions);

void mc_pfwl_flow_table_delete_flow_later(pfwl_flow_table_t *db,
                                          uint16_t partition_id,
                                          pfwl_flow_t *to_delete);

#ifdef __cplusplus
}
#endif

#endif /* FLOW_TABLE_H_ */
