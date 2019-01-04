/*
 * flow_table.c
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
#include <peafowl/tcp_stream_management.h>
#include <peafowl/utils.h>

#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#if PFWL_NUMA_AWARE
#include <numa.h>
#endif

#define PFWL_CACHE_LINES_PADDING_REQUIRED(size)                                \
  (size % PFWL_CACHE_LINE_SIZE == 0 ? 0 : PFWL_CACHE_LINE_SIZE -               \
                                              (size % PFWL_CACHE_LINE_SIZE))

#define PFWL_DEBUG_FLOW_TABLE 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_FLOW_TABLE)                                                 \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

#define PFWL_FLOW_TABLE_MAX_IDLE_TIME 30 /** In seconds. **/
#define PFWL_FLOW_TABLE_WALK_TIME 1      /** In seconds. **/

static inline pfwl_flow_t *v4_flow_alloc() {
  void *r;
#if PFWL_NUMA_AWARE
  r = numa_alloc_onnode(sizeof(ipv4_flow_t), PFWL_NUMA_AWARE_FLOW_TABLE_NODE);
  assert(r);
#else
#if PFWL_FLOW_TABLE_ALIGN_FLOWS
  int tmp =
      posix_memalign((void **) &r, PFWL_CACHE_LINE_SIZE, sizeof(ipv4_flow_t));
  if (tmp) {
    assert("Failure on posix_memalign" == 0);
  }
#else
  r = malloc(sizeof(pfwl_flow_t));
  assert(r);
#endif
#endif
  return (pfwl_flow_t *) r;
}

static inline void pfwl_flow_free(pfwl_flow_t *flow) {
#if PFWL_NUMA_AWARE
  numa_free(flow, sizeof(ipv4_flow_t));
#else
  free(flow);
#endif
}

typedef uint32_t(pfwl_fnv_hash_function)(pfwl_dissection_info_t *in,
                                         uint8_t log);

typedef struct pfwl_flow_DB_partition_specific_informations {
  /** This table part is in the range [lowest_index, highest_index]. **/
  uint32_t lowest_index;
  uint32_t highest_index;
  uint32_t last_walk;
  uint32_t active_flows;
  uint32_t max_active_flows;
  pfwl_flow_t
      *delayed_deletion_flow; // This is a flow that received the TCP FIN but we
                              // do not clean immediately, to give the user the
                              // possibility to get the last data found.
} pfwl_flow_DB_partition_specific_informations_t;

typedef struct pfwl_flow_table_partition {
  struct pfwl_flow_table_real_partition {
    pfwl_flow_DB_partition_specific_informations_t informations;
#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
    /**
     * If an integer x is contained in this array, then
     * memory_chunk_lower_bound[i] can be used.
     **/
    uint32_t *pool;
    uint32_t pool_size;
    pfwl_flow_t *memory_chunk_lower_bound;
    pfwl_flow_t *memory_chunk_upper_bound;
#endif
  } partition;
  /**
   * Using padding each partition will go in a separate cache line
   * avoiding false sharing between threads working on different
   * partitions.
   **/
  char padding[PFWL_CACHE_LINES_PADDING_REQUIRED(
      sizeof(struct pfwl_flow_table_real_partition))];
} pfwl_flow_table_partition_t;

struct pfwl_flow_table {
  /**
   *  The flow table may be shared among multiple threads. In this
   *  case each thread will access to a different part of 'table'.
   *  We also have one pfwl_flow_DB_v*_partition_t per thread containing
   *  the thread's partition specific informations.
   */
  pfwl_flow_t *table;
  pfwl_flow_cleaner_callback_t *flow_cleaner_callback;
  pfwl_flow_termination_callback_t *flow_termination_callback;
#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_MURMUR3_HASH
  uint32_t seed;
#endif
  uint32_t total_size;
  pfwl_flow_table_partition_t *partitions;
  uint16_t num_partitions;
  uint32_t max_active_flows;
  uint32_t max_active_flows_strict;
#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
  uint32_t individual_pool_size;
  uint32_t start_pool_size;
#endif
};

#ifndef PFWL_DEBUG
static
#endif
    uint8_t
    v4_equals(pfwl_flow_t *flow, pfwl_dissection_info_t *pkt_info) {
  return ((flow->addr_src.ipv4 == pkt_info->l3.addr_src.ipv4 &&
           flow->addr_dst.ipv4 == pkt_info->l3.addr_dst.ipv4 &&
           flow->port_src == pkt_info->l4.port_src &&
           flow->port_dst == pkt_info->l4.port_dst) ||
          (flow->addr_src.ipv4 == pkt_info->l3.addr_dst.ipv4 &&
           flow->addr_dst.ipv4 == pkt_info->l3.addr_src.ipv4 &&
           flow->port_src == pkt_info->l4.port_dst &&
           flow->port_dst == pkt_info->l4.port_src)) &&
         flow->l4prot == pkt_info->l4.protocol;
}

#ifndef PFWL_DEBUG
static
#endif
    uint8_t
    v6_equals(pfwl_flow_t *flow, pfwl_dissection_info_t *pkt_info) {
  uint8_t i;

  /*1: src=src and dst=dst. 2: src=dst and dst=src. */
  uint8_t direction = 0;

  for (i = 0; i < 16; i++) {
    if (direction != 2 &&
        pkt_info->l3.addr_src.ipv6.s6_addr[i] ==
            flow->addr_src.ipv6.s6_addr[i] &&
        pkt_info->l3.addr_dst.ipv6.s6_addr[i] ==
            flow->addr_dst.ipv6.s6_addr[i]) {
      direction = 1;
    } else if (direction != 1 &&
               pkt_info->l3.addr_src.ipv6.s6_addr[i] ==
                   flow->addr_dst.ipv6.s6_addr[i] &&
               pkt_info->l3.addr_dst.ipv6.s6_addr[i] ==
                   flow->addr_src.ipv6.s6_addr[i]) {
      direction = 2;
    } else
      return 0;
  }

  if (direction == 1)
    return flow->port_src == pkt_info->l4.port_src &&
           flow->port_dst == pkt_info->l4.port_dst &&
           flow->l4prot == pkt_info->l4.protocol;
  else if (direction == 2)
    return flow->port_src == pkt_info->l4.port_dst &&
           flow->port_dst == pkt_info->l4.port_src &&
           flow->l4prot == pkt_info->l4.protocol;
  else
    return 0;
}

#ifndef PFWL_DEBUG
static
#endif
    uint8_t
    flow_equals(pfwl_flow_t *flow, pfwl_dissection_info_t *pkt_info) {
  if (pkt_info->l3.protocol == PFWL_PROTO_L3_IPV4) {
    return v4_equals(flow, pkt_info);
  } else {
    return v6_equals(flow, pkt_info);
  }
}

#ifndef PFWL_DEBUG
static
#endif
    void
    pfwl_flow_table_initialize_informations(
        pfwl_flow_DB_partition_specific_informations_t *table_informations,
        uint32_t lowest_index, uint32_t highest_index,
        uint32_t max_active_flows) {
  table_informations->lowest_index = lowest_index;
  table_informations->highest_index = highest_index;
  table_informations->max_active_flows = max_active_flows;

  table_informations->last_walk = 0;
  table_informations->active_flows = 0;
  table_informations->delayed_deletion_flow = NULL;
}

static void pfwl_flow_table_update_flow_count(pfwl_flow_table_t *db) {
  pfwl_flow_t *cur;
  if (db != NULL) {
    if (db->table != NULL) {
      for (uint16_t j = 0; j < db->num_partitions; ++j) {
        db->partitions[j].partition.informations.active_flows = 0;
        for (uint32_t i = db->partitions[j].partition.informations.lowest_index;
             i <= db->partitions[j].partition.informations.highest_index; ++i) {
          cur = db->table[i].next;
          while (cur != &(db->table[i])) {
            cur = cur->next;
            ++db->partitions[j].partition.informations.active_flows;
          }
        }
      }
    }
  }
}

#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
pfwl_flow_DB_v4_t *pfwl_flow_table_create(uint32_t size,
                                          uint32_t max_active_v4_flows,
                                          uint16_t num_partitions,
                                          uint32_t start_pool_size) {
#else
pfwl_flow_table_t *pfwl_flow_table_create(uint32_t expected_flows,
                                          uint8_t strict,
                                          uint16_t num_partitions) {
#endif
  pfwl_flow_table_t *table = NULL;
  if(expected_flows < PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE){
    expected_flows = PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE;
  }
  uint32_t size = expected_flows / PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE;
  if (size != 0) {
    table = (pfwl_flow_table_t *) malloc(sizeof(pfwl_flow_table_t));
    assert(table);
    table->table = (pfwl_flow_t *) malloc(sizeof(pfwl_flow_t) * size);
    assert(table->table);
    table->total_size = size;
    table->num_partitions = num_partitions;
    table->max_active_flows = expected_flows;
    table->max_active_flows_strict = strict;
    table->flow_cleaner_callback = NULL;
    table->flow_termination_callback = NULL;
#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
    table->start_pool_size = start_pool_size;
#endif

    for (uint32_t i = 0; i < table->total_size; i++) {
      /** Creation of sentinel node. **/
      table->table[i].next = &(table->table[i]);
      table->table[i].prev = &(table->table[i]);
    }

#if PFWL_NUMA_AWARE
    table->partitions = numa_alloc_onnode(sizeof(pfwl_flow_DB_v4_partition_t) *
                                              table->num_partitions,
                                          PFWL_NUMA_AWARE_FLOW_TABLE_NODE);
    assert(table->partitions);
#else
    int tmp = posix_memalign(
        (void **) &(table->partitions), PFWL_CACHE_LINE_SIZE,
        sizeof(pfwl_flow_table_partition_t) * table->num_partitions);
    if (tmp) {
      assert("Failure on posix_memalign" == 0);
    }
#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_MURMUR3_HASH
    srand((unsigned int) time(NULL));
    table->seed = rand();
#endif

    pfwl_flow_table_setup_partitions(table, table->num_partitions);
  } else
    table = NULL;
  return table;
}

void pflw_flow_table_set_flow_cleaner_callback(
    pfwl_flow_table_t *db,
    pfwl_flow_cleaner_callback_t *flow_cleaner_callback) {
  db->flow_cleaner_callback = flow_cleaner_callback;
}

void pflw_flow_table_set_flow_termination_callback(
    pfwl_flow_table_t *db, pfwl_flow_termination_callback_t *flow_termination_callback){
  db->flow_termination_callback = flow_termination_callback;
}

void pfwl_flow_table_setup_partitions(pfwl_flow_table_t *table,
                                      uint16_t num_partitions) {
  table->num_partitions = num_partitions;
  /** Partitions management. **/
  uint32_t partition_size =
      ceil((float) table->total_size / (float) table->num_partitions);
  uint32_t partition_max_active_v4_flows =
      table->max_active_flows / table->num_partitions;

  uint16_t j;
  uint32_t lowest_index = 0;
  uint32_t highest_index = lowest_index + partition_size - 1;
  for (j = 0; j < table->num_partitions; ++j) {
    debug_print("[flow_table.c]: Created partition "
                "[%" PRIu32 ", %" PRIu32 "]\n",
                lowest_index, highest_index);
    pfwl_flow_table_initialize_informations(
        &(table->partitions[j].partition.informations), lowest_index,
        highest_index, partition_max_active_v4_flows);
    lowest_index = highest_index + 1;
    /**
     * The last partition gets the entries up to the end of the
     * table. Indeed, when the size is not a multiple of the
     * number of partitions, the last partition may be smaller.
     */
    if (j == table->num_partitions - 2)
      highest_index = table->total_size - 1;
    else
      highest_index += partition_size;

#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
    ipv4_flow_t *flow_pool;
    uint32_t i;
    table->individual_pool_size =
        table->start_pool_size / table->num_partitions;
#if PFWL_NUMA_AWARE
    flow_pool =
        numa_alloc_onnode(sizeof(ipv4_flow_t) * table->individual_pool_size,
                          PFWL_NUMA_AWARE_FLOW_TABLE_NODE);
    assert(flow_pool);
    table->partitions[j].partition.pool =
        numa_alloc_onnode(sizeof(uint32_t) * table->individual_pool_size,
                          PFWL_NUMA_AWARE_FLOW_TABLE_NODE);
    assert(table->partitions[j].partition.pool);
#else
    int tmp =
        posix_memalign((void **) &flow_pool, PFWL_CACHE_LINE_SIZE,
                       (sizeof(ipv4_flow_t) * table->individual_pool_size) +
                           PFWL_CACHE_LINE_SIZE);
    if (tmp) {
      assert("Failure on posix_memalign" == 0);
    }
    tmp = posix_memalign((void **) &(table->partitions[j].partition.pool),
                         PFWL_CACHE_LINE_SIZE,
                         (sizeof(uint32_t) * table->individual_pool_size) +
                             PFWL_CACHE_LINE_SIZE);
    if (tmp) {
      assert("Failure on posix_memalign" == 0);
    }
#endif
    for (i = 0; i < table->individual_pool_size; i++) {
      table->partitions[j].partition.pool[i] = i;
    }
    table->partitions[j].partition.pool_size = table->individual_pool_size;
    table->partitions[j].partition.memory_chunk_lower_bound = flow_pool;
    table->partitions[j].partition.memory_chunk_upper_bound =
        flow_pool + table->individual_pool_size;
#endif
  }
  debug_print("%s\n", "[flow_table.c]: Computing active v4 flows.");
  pfwl_flow_table_update_flow_count(table);
  debug_print("%s\n", "[flow_table.c]: Active v4 flows computation finished.");
}

void jsonrpc_delete_parser(void* parser);

void mc_pfwl_flow_table_delete_flow(pfwl_flow_table_t *db,
                                    uint16_t partition_id,
                                    pfwl_flow_t *to_delete) {
  to_delete->prev->next = to_delete->next;
  to_delete->next->prev = to_delete->prev;

  if (db->flow_cleaner_callback){
    (*(db->flow_cleaner_callback))(*(to_delete->info.udata));
  }

  if (db->flow_termination_callback){
    (*(db->flow_termination_callback))(&(to_delete->info));
  }
  --db->partitions[partition_id].partition.informations.active_flows;
  free(to_delete->info_private.http_informations[0].temp_buffer);
  free(to_delete->info_private.http_informations[1].temp_buffer);
  pfwl_reordering_tcp_delete_all_fragments(&(to_delete->info_private));
  if (to_delete->info_private.last_rebuilt_tcp_data) {
    free((void *) to_delete->info_private.last_rebuilt_tcp_data);
  }
  if (to_delete->info_private.last_rebuilt_ip_fragments) {
    free((void *) to_delete->info_private.last_rebuilt_ip_fragments);
  }
  for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
    if(to_delete->info_private.flow_cleaners_dissectors[i]){
      to_delete->info_private.flow_cleaners_dissectors[i](&(to_delete->info_private));
    }
  }

#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
  if (likely(
          to_delete >=
              db->partitions[partition_id].partition.memory_chunk_lower_bound &&
          to_delete < db->partitions[partition_id]
                          .partition.memory_chunk_upper_bound)) {
    debug_print("%s\n", "[flow_table.c]: Reinserting the flow"
                        " in the pool.");
    db->partitions[partition_id]
        .partition.pool[db->partitions[partition_id].partition.pool_size] =
        to_delete -
        db->partitions[partition_id].partition.memory_chunk_lower_bound;
    ++db->partitions[partition_id].partition.pool_size;
  } else {
    debug_print("%s\n", "[flow_table.c]: Poolsize exceeded,"
                        " removing the flow.");
    v4_flow_free(to_delete);
  }
#else
  pfwl_flow_free(to_delete);
#endif
}

void mc_pfwl_flow_table_delete_flow_later(pfwl_flow_table_t *db,
                                          uint16_t partition_id,
                                          pfwl_flow_t *to_delete) {
  db->partitions[partition_id].partition.informations.delayed_deletion_flow =
      to_delete;
}

void pfwl_flow_table_delete_flow_later(pfwl_flow_table_t *db,
                                       pfwl_flow_t *to_delete) {
  mc_pfwl_flow_table_delete_flow_later(db, 0, to_delete);
}

void pfwl_flow_table_delete_flow(pfwl_flow_table_t *db,
                                 pfwl_flow_t *to_delete) {
  mc_pfwl_flow_table_delete_flow(db, 0, to_delete);
}

#define MAX(x, y)                                                              \
  ({                                                                           \
    __typeof__(x) _x = (x);                                                    \
    __typeof__(y) _y = (y);                                                    \
    _x > _y ? _x : _y;                                                         \
  })

#ifndef PFWL_DEBUG
static
#endif
    void
    pfwl_flow_table_check_expiration(pfwl_flow_table_t *db,
                                     uint16_t partition_id,
                                     uint32_t current_time) {
  uint32_t i;
#if !PFWL_USE_MTF
  ipv4_flow_t *current;
#endif
  for (i = db->partitions[partition_id].partition.informations.lowest_index;
       i <= db->partitions[partition_id].partition.informations.highest_index;
       i++) {
    /**
     * Set the last timestamp for the sentinel node in such
     * a way that we simplify the loop over the list.
     **/
    db->table[i].info.timestamp_last[0] = current_time;
    db->table[i].info.timestamp_last[1] = 0;

#if PFWL_USE_MTF
    while (current_time - MAX(db->table[i].prev->info.timestamp_last[0],
                              db->table[i].prev->info.timestamp_last[1]) >
           PFWL_FLOW_TABLE_MAX_IDLE_TIME) {
      mc_pfwl_flow_table_delete_flow(db, partition_id, db->table[i].prev);
    }
#else
    current = db->table[i].prev;
    while (current != &(db->table[i])) {
      if (current_time - db->table[i].prev->info.last_timestamp >
          PFWL_FLOW_TABLE_MAX_IDLE_TIME) {
        mc_pfwl_flow_table_delete_flow(db, flow_cleaner_callback, partition_id,
                                       db->table[i].prev);
      }
      current = current->prev;
    }
#endif
  }
}

#if 0
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

void print_flow(ipv4_flow_t* iterator) {
	struct in_addr src, dst;
	src.s_addr = iterator->srcaddr;
	dst.s_addr = iterator->dstaddr;
	printf("%s -> ", inet_ntoa(src));
	printf("%s : ", inet_ntoa(dst));

  printf("%u -> ", ntohs(iterator->port_src));
  printf("%u : ", ntohs(iterator->port_dst));
	printf("%u\n", iterator->l4prot);
}
#endif

void pfwl_init_flow_info_internal(pfwl_flow_info_private_t *flow_info_private,
                                  char *protocols_to_inspect,
                                  uint8_t tcp_reordering_enabled) {
  bzero(flow_info_private, sizeof(pfwl_flow_info_private_t));
  pfwl_protocol_l7_t i;
  flow_info_private->possible_protocols = 0;
  for (i = 0; i < PFWL_PROTO_L7_NUM; i++) {
    uint8_t set = BITTEST(protocols_to_inspect, i);
    if(set){
      BITSET(flow_info_private->possible_matching_protocols, i);
      ++flow_info_private->possible_protocols;
    }
  }

  flow_info_private->l7_protocols_num = 0;
  flow_info_private->l7_protocols[0] = PFWL_PROTO_L7_NOT_DETERMINED;
  flow_info_private->identification_terminated = 0;
  flow_info_private->trials = 0;
  flow_info_private->tcp_reordering_enabled = tcp_reordering_enabled;
  flow_info_private->last_rebuilt_tcp_data = NULL;
  flow_info_private->last_rebuilt_ip_fragments = NULL;
  flow_info_private->udata_private = NULL;
}

static void pfwl_init_flow_info_public_internal(pfwl_flow_info_t *flow_info) {
  memset(flow_info, 0, sizeof(pfwl_flow_info_t));
}

pfwl_flow_t *mc_pfwl_flow_table_find_or_create_flow(
    pfwl_flow_table_t *db, uint16_t partition_id, uint32_t index,
    pfwl_dissection_info_t *pkt_info, char *protocols_to_inspect,
    uint8_t tcp_reordering_enabled, uint32_t timestamp, uint8_t syn) {
  debug_print("%s\n", "[flow_table.c]: "
                      "pfwl_flow_table_find_or_create_flow_v4 invoked.");

  // Do it before searching the current flow
  if (db->partitions[partition_id]
          .partition.informations.delayed_deletion_flow) {
    mc_pfwl_flow_table_delete_flow(
        db, partition_id, db->partitions[partition_id]
                              .partition.informations.delayed_deletion_flow);
    db->partitions[partition_id].partition.informations.delayed_deletion_flow =
        NULL;
  }

  /** Flow searching. **/
  pfwl_flow_t *head = &(db->table[index]);
  pfwl_flow_t *iterator = head->next;
  while (iterator != head && !flow_equals(iterator, pkt_info)) {
    iterator = iterator->next;
  }

  /**
   * Check for RST. We need to do this check here. Multiple RST may be received
   * in a row. If we close the connection when the first RST is received,
   * the next RSTs would create another flow (one for each of the following
   * RSTs). For this reason, we close the connection when a SYN (new connection)
   * is received on the same 5tuple (or when the flow expires).
   * Expiration check is done in another place, here we need to check if
   * a SYN has been received on a connection where some RSTs where received.
   **/
  if (iterator != head && pkt_info->l4.protocol == IPPROTO_TCP &&
      iterator->info_private.seen_rst && syn) {
    // Delete old flow.
    mc_pfwl_flow_table_delete_flow(db, partition_id, iterator);
    // Force the following code to create a new flow.
    iterator = head;
  }

  /**Flow not found, add it after the head.**/
  if (iterator == head) {
    if (unlikely(
            db->partitions[partition_id].partition.informations.active_flows ==
            db->partitions[partition_id]
                .partition.informations.max_active_flows))
      return NULL;
#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
    if (likely(db->partitions[partition_id].partition.pool_size != 0)) {
      debug_print("%s\n", "[flow_table.c]: New flow created, "
                          "extracting an empty flow from the pool.");
      /** Remove the flow from the pool. **/
      uint32_t p =
          db->partitions[partition_id]
              .partition
              .pool[--db->partitions[partition_id].partition.pool_size];
      iterator =
          &(db->partitions[partition_id].partition.memory_chunk_lower_bound[p]);
    } else {
      debug_print("%s\n", "[flow_table.c]: New flow created, "
                          " pool exhausted, allocating a new flow.");
      iterator = v4_flow_alloc();
    }
#else
    iterator = v4_flow_alloc();
#endif
    assert(iterator);

    /**Creates new flow and inserts it in the list.**/
    iterator->addr_src = pkt_info->l3.addr_src;
    iterator->addr_dst = pkt_info->l3.addr_dst;
    iterator->port_src = pkt_info->l4.port_src;
    iterator->port_dst = pkt_info->l4.port_dst;
    iterator->l4prot = pkt_info->l4.protocol;
    iterator->prev = head;
    iterator->next = head->next;
    iterator->prev->next = iterator;
    iterator->next->prev = iterator;
    pfwl_init_flow_info_public_internal(&iterator->info);
    pfwl_init_flow_info_internal(&(iterator->info_private),
                                 protocols_to_inspect, tcp_reordering_enabled);
    iterator->info_private.info_public = &iterator->info;
    iterator->info_private.flow = iterator;
    iterator->info.udata = &(iterator->info_private.udata_private);

    ++db->partitions[partition_id].partition.informations.active_flows;
  }
#if PFWL_USE_MTF
  else if (iterator->prev != head) {
    /**
     * Remove the flow from the current position. It will be inserted
     * in the first position (Move to front). In this way collisions
     * lists are sorted from the highest to the lowest 'last update'
     * timestamp.
     **/
    iterator->prev->next = iterator->next;
    iterator->next->prev = iterator->prev;
    iterator->prev = head;
    iterator->next = head->next;
    iterator->prev->next = iterator;
    iterator->next->prev = iterator;
  }
#endif

  if (!iterator->info.timestamp_first[pkt_info->l4.direction]) {
    iterator->info.timestamp_first[pkt_info->l4.direction] = timestamp;
  }
  iterator->info.timestamp_last[pkt_info->l4.direction] = timestamp;

  if (unlikely(
          timestamp -
              db->partitions[partition_id].partition.informations.last_walk >=
          PFWL_FLOW_TABLE_WALK_TIME)) {
    pfwl_flow_table_check_expiration(db, partition_id, timestamp);
    db->partitions[partition_id].partition.informations.last_walk = timestamp;
  }

  if (memcmp(&(iterator->addr_src), &(pkt_info->l3.addr_src),
             sizeof(pkt_info->l3.addr_src)) == 0 &&
      iterator->port_src == pkt_info->l4.port_src) {
    pkt_info->l4.direction = 0;
  } else {
    pkt_info->l4.direction = 1;
  }
  return iterator;
}

uint32_t
pfwl_compute_v4_hash_function(pfwl_flow_table_t *db,
                              const pfwl_dissection_info_t *const pkt_info) {
#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_FNV_HASH
  uint32_t row = v4_fnv_hash_function(pkt_info) % db->total_size;
#elif PFWL_FLOW_TABLE_HASH_VERSION == PFWL_MURMUR3_HASH
  uint32_t row = v4_hash_murmur3(pkt_info, db->seed) % db->total_size;
#elif PFWL_FLOW_TABLE_HASH_VERSION == PFWL_BKDR_HASH
  uint32_t row = v4_hash_function_bkdr(pkt_info) % db->total_size;
#else /** Default hash function is the simplest one. **/
  uint32_t row = v4_hash_function_simple(pkt_info) % db->total_size;
#endif
  return row;
}

pfwl_flow_t *pfwl_flow_table_find_or_create_flow(
    pfwl_flow_table_t *db, pfwl_dissection_info_t *pkt_info,
    char *protocols_to_inspect, uint8_t tcp_reordering_enabled,
    uint32_t timestamp, uint8_t syn) {
  return mc_pfwl_flow_table_find_or_create_flow(
      db, 0, pfwl_compute_v4_hash_function(db, pkt_info), pkt_info,
      protocols_to_inspect, tcp_reordering_enabled, timestamp, syn);
}

uint32_t
pfwl_compute_v6_hash_function(pfwl_flow_table_t *db,
                              const pfwl_dissection_info_t *const pkt_info) {
#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_FNV_HASH
  uint32_t row = v6_fnv_hash_function(pkt_info) % db->total_size;
#elif PFWL_FLOW_TABLE_HASH_VERSION == PFWL_MURMUR3_HASH
  uint32_t row = v6_hash_murmur3(pkt_info, db->seed) % db->total_size;
#elif PFWL_FLOW_TABLE_HASH_VERSION == PFWL_BKDR_HASH
  uint32_t row = v6_hash_function_bkdr(pkt_info) % db->total_size;
#else /** Default hash function is the simplest one. **/
  uint32_t row = v6_hash_function_simple(pkt_info) % db->total_size;
#endif
  return row;
}

pfwl_flow_t *pfwl_flow_table_find_flow(pfwl_flow_table_t *db, uint32_t index,
                                       pfwl_dissection_info_t *pkt_info) {
  pfwl_flow_t *head = &(db->table[index]);
  pfwl_flow_t *iterator = head->next;

  /** Flow searching. **/
  while (iterator != head && !flow_equals(iterator, pkt_info)) {
    iterator = iterator->next;
  }

  if (iterator == head)
    return NULL;
  else
    return iterator;
}

void pfwl_flow_table_delete(pfwl_flow_table_t *db) {
  if (db != NULL) {
    if (db->table != NULL) {
      for (uint16_t j = 0; j < db->num_partitions; ++j) {
        for (uint32_t i = db->partitions[j].partition.informations.lowest_index;
             i <= db->partitions[j].partition.informations.highest_index; ++i) {
          while (db->table[i].next != &(db->table[i])) {
            mc_pfwl_flow_table_delete_flow(db, j, db->table[i].next);
          }
        }
#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
#if PFWL_NUMA_AWARE
        numa_free(db->partitions[j].partition.memory_chunk_lower_bound,
                  sizeof(ipv6_flow_t) * db->individual_pool_size);
        numa_free(db->partitions[j].partition.pool,
                  sizeof(uint32_t) * db->individual_pool_size);
#else
        free(db->partitions[j].partition.memory_chunk_lower_bound);
        free(db->partitions[j].partition.pool);
#endif
#endif
      }
    }

#if PFWL_NUMA_AWARE
    numa_free(db->partitions,
              sizeof(pfwl_flow_DB_v4_partition_t) * db->num_partitions);
    numa_free(db->table, sizeof(ipv4_flow_t) * db->total_size);
#else
    free(db->partitions);
    free(db->table);
#endif
    free(db);
  }
}
