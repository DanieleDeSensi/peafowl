/*
 * flow_table.c
 *
 *  Created on: 22/10/2012
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

#include "flow_table.h"
#include "hash_functions.h"
#include "tcp_stream_management.h"
#include "config.h"
#include "utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <math.h>
#include <netinet/tcp.h>

#if DPI_NUMA_AWARE
#include <numa.h>
#endif

#define DPI_CACHE_LINES_PADDING_REQUIRED(size)          \
	(size%DPI_CACHE_LINE_SIZE==0?0:DPI_CACHE_LINE_SIZE- \
	(size%DPI_CACHE_LINE_SIZE))

#define DPI_DEBUG_FLOW_TABLE 0
#define debug_print(fmt, ...)              \
            do { if (DPI_DEBUG_FLOW_TABLE) \
            	fprintf(stdout, fmt, __VA_ARGS__); } while (0)


#define DPI_FLOW_TABLE_MAX_IDLE_TIME 30 /** In seconds. **/

#define DPI_FLOW_TABLE_WALK_TIME 1 /** In seconds. **/

static inline ipv4_flow_t* v4_flow_alloc(){
	void* r;
#if DPI_NUMA_AWARE
	r=numa_alloc_onnode(sizeof(ipv4_flow_t),
			            DPI_NUMA_AWARE_FLOW_TABLE_NODE);
	assert(r);
#else
	#if DPI_FLOW_TABLE_ALIGN_FLOWS
		assert(posix_memalign((void**) &r, DPI_CACHE_LINE_SIZE,
			   sizeof(ipv4_flow_t))==0);
	#else
		r=malloc(sizeof(ipv4_flow_t));
		assert(r);
	#endif
#endif
	return (ipv4_flow_t*) r;
}

static inline ipv6_flow_t* v6_flow_alloc(){
	void* r;
#if DPI_NUMA_AWARE
	r=numa_alloc_onnode(sizeof(ipv6_flow_t),
			            DPI_NUMA_AWARE_FLOW_TABLE_NODE);
	assert(r);
#else
	#if DPI_FLOW_TABLE_ALIGN_FLOWS
		assert(posix_memalign((void**) &r, DPI_CACHE_LINE_SIZE,
			   sizeof(ipv6_flow_t))==0);
	#else
		r=malloc(sizeof(ipv6_flow_t));
		assert(r);
	#endif
#endif
	return (ipv6_flow_t*) r;
}

static inline void v4_flow_free(ipv4_flow_t* flow){
#if DPI_NUMA_AWARE
	numa_free(flow, sizeof(ipv4_flow_t));
#else
	free(flow);
#endif
}

static inline void v6_flow_free(ipv6_flow_t* flow){
#if DPI_NUMA_AWARE
	numa_free(flow, sizeof(ipv6_flow_t));
#else
	free(flow);
#endif
}


typedef u_int32_t(dpi_fnv_hash_function)(dpi_pkt_infos_t* in,
		                                 u_int8_t log);


typedef struct dpi_flow_DB_partition_specific_informations{
	/** This table part is in the range [lowest_index, highest_index]. **/
	u_int32_t lowest_index;
	u_int32_t highest_index;
	u_int32_t last_walk;
	u_int32_t active_flows;
	u_int32_t max_active_flows;
}dpi_flow_DB_partition_specific_informations_t;


typedef struct dpi_flow_DB_v4_partition{
	struct dpi_flow_DB_v4_real_partition{
		dpi_flow_DB_partition_specific_informations_t informations;
	#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		/**
		 * If an integer x is contained in this array, then
		 * memory_chunk_lower_bound[i] can be used.
		 **/
		u_int32_t* pool;
		u_int32_t pool_size;
		ipv4_flow_t* memory_chunk_lower_bound;
		ipv4_flow_t* memory_chunk_upper_bound;
	#endif
	}partition;
	/**
	 * Using padding each partition will go in a separate cache line
	 * avoiding false sharing between threads working on different
	 * partitions.
	 **/
	char padding[DPI_CACHE_LINES_PADDING_REQUIRED
	             (sizeof(struct dpi_flow_DB_v4_real_partition))];
}dpi_flow_DB_v4_partition_t;

typedef struct dpi_flow_DB_v6_partition{
	struct dpi_flow_DB_v6_real_partition{
		dpi_flow_DB_partition_specific_informations_t informations;
	#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		/**
		 * If an integer x is contained in this array, then
		 * memory_chunk_lower_bound[i] can be used.
		 **/
		u_int32_t* pool;
		u_int32_t pool_size;
		ipv6_flow_t* memory_chunk_lower_bound;
		ipv6_flow_t* memory_chunk_upper_bound;
	#endif
	}partition;
	/**
	 * Using padding each partition will go in a separate cache line
	 * avoiding false sharing between threads working on different
	 * partitions.
	 **/
	char padding[DPI_CACHE_LINES_PADDING_REQUIRED
	            (sizeof(struct dpi_flow_DB_v6_real_partition))];
}dpi_flow_DB_v6_partition_t;

struct dpi_flow_DB_v4{
	/**
	 *  The flow table may be shared among multiple threads. In this
	 *  case each thread will access to a different part of 'table'.
	 *  We also have one dpi_flow_DB_v*_partition_t per thread containing
	 *  the thread's partition specific informations.
	 */
	ipv4_flow_t* table;
#if DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH
	u_int32_t seed;
#endif
	u_int32_t total_size;
	dpi_flow_DB_v4_partition_t* partitions;
	u_int16_t num_partitions;
	u_int32_t max_active_flows;
#if DPI_FLOW_TABLE_USE_MEMORY_POOL
	u_int32_t individual_pool_size;
	u_int32_t start_pool_size;
#endif
};

struct dpi_flow_DB_v6{
	/**
	 *  The flow table may be shared among multiple threads. In this
	 *  case each thread will access to a different part of 'table'.
	 *  We also have one dpi_flow_DB_v*_partition_t per thread containing
	 *  the thread's partition specific informations.
	 */
	ipv6_flow_t* table;
#if DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH
	u_int32_t seed;
#endif
	u_int32_t total_size;
	dpi_flow_DB_v6_partition_t* partitions;
	u_int16_t num_partitions;
	u_int32_t max_active_flows;
#if DPI_FLOW_TABLE_USE_MEMORY_POOL
	u_int32_t individual_pool_size;
	u_int32_t start_pool_size;
#endif
};


#ifndef DPI_DEBUG
static
#endif
u_int8_t v4_equals(ipv4_flow_t* flow, dpi_pkt_infos_t* pkt_infos){
	return ((flow->srcaddr==pkt_infos->src_addr_t.ipv4_srcaddr &&
			 flow->dstaddr==pkt_infos->dst_addr_t.ipv4_dstaddr &&
			 flow->srcport==pkt_infos->srcport &&
			 flow->dstport==pkt_infos->dstport) ||
			(flow->srcaddr==pkt_infos->dst_addr_t.ipv4_dstaddr &&
			 flow->dstaddr==pkt_infos->src_addr_t.ipv4_srcaddr &&
			 flow->srcport==pkt_infos->dstport &&
			 flow->dstport==pkt_infos->srcport)) &&
			 flow->l4prot==pkt_infos->l4prot;

}

#ifndef DPI_DEBUG
static
#endif
u_int8_t v6_equals(ipv6_flow_t* flow, dpi_pkt_infos_t* pkt_infos){
	u_int8_t i;

	/*1: src=src and dst=dst. 2: src=dst and dst=src. */
	u_int8_t direction=0;

	for(i=0; i<16; i++){
		if(direction!=2 &&
		   pkt_infos->src_addr_t.ipv6_srcaddr.s6_addr[i]==
	       flow->srcaddr.s6_addr[i] &&
	       pkt_infos->dst_addr_t.ipv6_dstaddr.s6_addr[i]==
	       flow->dstaddr.s6_addr[i]){
			direction=1;
		}else if(direction!=1 &&
				 pkt_infos->src_addr_t.ipv6_srcaddr.s6_addr[i]==
				 flow->dstaddr.s6_addr[i] &&
				 pkt_infos->dst_addr_t.ipv6_dstaddr.s6_addr[i]==
				 flow->srcaddr.s6_addr[i]){
			direction=2;
		}else
			return 0;
	}

	if(direction==1)
		return flow->srcport==pkt_infos->srcport &&
			   flow->dstport==pkt_infos->dstport &&
			   flow->l4prot==pkt_infos->l4prot;
	else if(direction==2)
		return flow->srcport==pkt_infos->dstport &&
			   flow->dstport==pkt_infos->srcport &&
			   flow->l4prot==pkt_infos->l4prot;
	else
		return 0;
}

#ifndef DPI_DEBUG
static
#endif
void dpi_flow_table_initialize_informations(
		dpi_flow_DB_partition_specific_informations_t* table_informations,
		u_int32_t lowest_index, u_int32_t highest_index,
		u_int32_t max_active_flows){
	table_informations->lowest_index=lowest_index;
	table_informations->highest_index=highest_index;
	table_informations->max_active_flows=max_active_flows;

	table_informations->last_walk=0;
	table_informations->active_flows=0;
}

static void dpi_flow_table_update_flow_count_v4(dpi_flow_DB_v4_t* db){
	u_int32_t i;
	u_int16_t j;
	ipv4_flow_t* cur;
	if(db!=NULL){
		if(db->table!=NULL){
			for(j=0; j<db->num_partitions; ++j){
				db->partitions[j].partition.informations.active_flows=0;
				for(i=db->partitions[j].partition.informations.
						  lowest_index;
					i<=db->partitions[j].partition.informations.
					      highest_index; ++i){
				  	cur=db->table[i].next;
					while(cur!=&(db->table[i])){
				       		cur=cur->next;
						++db->partitions[j].partition.informations.active_flows;
					}
				}
			}
		}
	}
}

static void dpi_flow_table_update_flow_count_v6(dpi_flow_DB_v6_t* db){
	u_int32_t i;
	u_int16_t j;
	ipv6_flow_t* cur;
	if(db!=NULL){
		if(db->table!=NULL){
			for(j=0; j<db->num_partitions; ++j){
				db->partitions[j].partition.informations.active_flows=0;
				for(i=db->partitions[j].partition.informations.
						  lowest_index;
					i<=db->partitions[j].partition.informations.
					      highest_index; ++i){
				  cur=db->table[i].next;
				 	while(cur!=&(db->table[i])){
				 		cur=cur->next;
						++db->partitions[j].partition.informations.active_flows;
					}
				}
			}
		}
	}
}

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
dpi_flow_DB_v4_t* dpi_flow_table_create_v4(
		u_int32_t size, u_int32_t max_active_v4_flows,
		u_int16_t num_partitions, u_int32_t start_pool_size){
#else
dpi_flow_DB_v4_t* dpi_flow_table_create_v4(
		u_int32_t size, u_int32_t max_active_v4_flows,
		u_int16_t num_partitions){
#endif
	u_int32_t i;
	dpi_flow_DB_v4_t* table;

	if(size!=0){
		assert((table=(dpi_flow_DB_v4_t*)
				  malloc(sizeof(dpi_flow_DB_v4_t)))!=NULL);
		table->table=(ipv4_flow_t*)
				  malloc(sizeof(ipv4_flow_t)*size);
		assert(table->table);
		table->total_size=size;
		table->num_partitions=num_partitions;
		table->max_active_flows=max_active_v4_flows;
#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		table->start_pool_size=start_pool_size;
#endif

		for(i=0; i<table->total_size; i++){
			/** Creation of sentinel node. **/
			table->table[i].next=&(table->table[i]);
			table->table[i].prev=&(table->table[i]);
		}
		

#if DPI_NUMA_AWARE
		table->partitions=numa_alloc_onnode(
				sizeof(dpi_flow_DB_v4_partition_t)*table->num_partitions,
				DPI_NUMA_AWARE_FLOW_TABLE_NODE);
		assert(table->partitions);
#else
		assert(posix_memalign(
				(void**) &(table->partitions), DPI_CACHE_LINE_SIZE,
				sizeof(dpi_flow_DB_v4_partition_t)*table->num_partitions)==0);
#endif

#if DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH
		srand((unsigned int) time(NULL));
		table->seed=rand();
#endif

		dpi_flow_table_setup_partitions_v4(table, table->num_partitions);
	}else
		table=NULL;
	return table;
}

void dpi_flow_table_setup_partitions_v4(dpi_flow_DB_v4_t* table, u_int16_t num_partitions){
	table->num_partitions=num_partitions;
	/** Partitions management. **/
	u_int32_t partition_size=ceil((float)table->total_size/(float)table->num_partitions);
	u_int32_t partition_max_active_v4_flows=
			     table->max_active_flows/table->num_partitions;
		
	u_int16_t j;
	u_int32_t lowest_index=0;
	u_int32_t highest_index=lowest_index+partition_size-1;
	for(j=0; j<table->num_partitions; ++j){
		debug_print("[flow_table.c]: Created partition "
				    "[%"PRIu32", %"PRIu32"]\n",
				    lowest_index, highest_index);
		dpi_flow_table_initialize_informations(
				&(table->partitions[j].partition.informations),
				lowest_index, highest_index,
				partition_max_active_v4_flows);
		lowest_index=highest_index+1;
		/**
		 * The last partition gets the entries up to the end of the
		 * table. Indeed, when the size is not a multiple of the
		 * number of partitions, the last partition may be smaller.
		 */
		if(j==table->num_partitions-2)
			highest_index=table->total_size-1;
		else
			highest_index+=partition_size;

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		ipv4_flow_t* flow_pool;
		u_int32_t i;
		table->individual_pool_size=table->start_pool_size/table->num_partitions;
#if DPI_NUMA_AWARE
		flow_pool=numa_alloc_onnode(
				sizeof(ipv4_flow_t)*table->individual_pool_size,
				DPI_NUMA_AWARE_FLOW_TABLE_NODE);
		assert(flow_pool);
		table->partitions[j].partition.pool=numa_alloc_onnode(
				sizeof(u_int32_t)*table->individual_pool_size,
				DPI_NUMA_AWARE_FLOW_TABLE_NODE);
		assert(table->partitions[j].partition.pool);
#else
		assert(posix_memalign(
			   (void**) &flow_pool, DPI_CACHE_LINE_SIZE,
			   (sizeof(ipv4_flow_t)*table->individual_pool_size)+
			   DPI_CACHE_LINE_SIZE)==0);
		assert(posix_memalign(
			   (void**) &(table->partitions[j].partition.pool),
			   DPI_CACHE_LINE_SIZE,
			   (sizeof(u_int32_t)*table->individual_pool_size)+
			   DPI_CACHE_LINE_SIZE)==0);
#endif
		for(i=0; i<table->individual_pool_size; i++){
			table->partitions[j].partition.pool[i]=i;
		}
		table->partitions[j].partition.pool_size=
				    table->individual_pool_size;
		table->partitions[j].partition.memory_chunk_lower_bound=
				    flow_pool;
		table->partitions[j].partition.memory_chunk_upper_bound=
				    flow_pool+table->individual_pool_size;
#endif
	}
	debug_print("%s\n", "[flow_table.c]: Computing active v4 flows.");
	dpi_flow_table_update_flow_count_v4(table);
	debug_print("%s\n", "[flow_table.c]: Active v4 flows computation finished.");
}


#if DPI_FLOW_TABLE_USE_MEMORY_POOL
dpi_flow_DB_v6_t* dpi_flow_table_create_v6(u_int32_t size,
		                                   u_int32_t max_active_v6_flows,
		                                   u_int16_t num_partitions,
		                                   u_int32_t start_pool_size){
#else
dpi_flow_DB_v6_t* dpi_flow_table_create_v6(u_int32_t size,
		                                   u_int32_t max_active_v6_flows,
		                                   u_int16_t num_partitions){
#endif
	u_int32_t i;
	dpi_flow_DB_v6_t* table;
	if(size!=0){
		assert((table=(dpi_flow_DB_v6_t*)
				       malloc(sizeof(dpi_flow_DB_v6_t)))!=NULL);
		table->table=(ipv6_flow_t*) malloc(sizeof(ipv6_flow_t)*size);
		assert(table->table);
		table->total_size=size;
		table->num_partitions=num_partitions;
		table->max_active_flows=max_active_v6_flows;
#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		table->start_pool_size=start_pool_size;
#endif
		
		for(i=0; i<table->total_size; i++){
			/** Creation of sentinel node. **/
			table->table[i].next=&(table->table[i]);
			table->table[i].prev=&(table->table[i]);
		}
		
#if DPI_NUMA_AWARE
		table->partitions=numa_alloc_onnode(
				sizeof(dpi_flow_DB_v6_partition_t)*table->num_partitions,
				DPI_NUMA_AWARE_FLOW_TABLE_NODE);
		assert(table->partitions);
#else
		assert(posix_memalign(
				(void**) &(table->partitions),
				DPI_CACHE_LINE_SIZE,
				sizeof(dpi_flow_DB_v6_partition_t)*table->num_partitions)==0);
#endif
		
#if DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH
		srand((unsigned int) time(NULL));
		table->seed=rand();
#endif
		dpi_flow_table_setup_partitions_v6(table, table->num_partitions);
	}else
		table=NULL;
	return table;
}

void dpi_flow_table_setup_partitions_v6(dpi_flow_DB_v6_t* table, u_int16_t num_partitions){
	/** Partitions management. **/
	u_int32_t partition_size=ceil((float)table->total_size/(float)table->num_partitions);
	u_int32_t partition_max_active_v6_flows=
			     table->max_active_flows/table->num_partitions;

	u_int16_t j;
	u_int32_t lowest_index=0;
	u_int32_t highest_index=lowest_index+partition_size-1;
	for(j=0; j<table->num_partitions; ++j){
		dpi_flow_table_initialize_informations(
				&(table->partitions[j].partition.informations),
				lowest_index, highest_index,
				partition_max_active_v6_flows);
		lowest_index=highest_index+1;

		/**
		 * The last partition gets the entries up to the end of the
		 * table. Indeed, when the size is not a multiple of the
		 * number of partitions, the last partition may be smaller.
		 */
		if(j==table->num_partitions-2)
			highest_index=table->total_size-1;
		else
			highest_index+=partition_size;

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		ipv6_flow_t* flow_pool;
		u_int32_t i=0;
		table->individual_pool_size=table->start_pool_size/table->num_partitions;
#if DPI_NUMA_AWARE
		flow_pool=numa_alloc_onnode(
				      sizeof(ipv6_flow_t)*table->individual_pool_size,
				      DPI_NUMA_AWARE_FLOW_TABLE_NODE);
		assert(flow_pool);
		table->partitions[j].partition.pool=numa_alloc_onnode(
				      sizeof(u_int32_t)*table->individual_pool_size,
				      DPI_NUMA_AWARE_FLOW_TABLE_NODE);
		assert(table->partitions[j].partition.pool);
#else
		assert(posix_memalign(
				     (void**) &flow_pool,
				     DPI_CACHE_LINE_SIZE,
				     (sizeof(ipv6_flow_t)*table->individual_pool_size)+
				     DPI_CACHE_LINE_SIZE)==0);
		assert(posix_memalign(
				     (void**) &(table->partitions[j].partition.pool),
				     DPI_CACHE_LINE_SIZE,
				     (sizeof(u_int32_t)*table->individual_pool_size)+
				     DPI_CACHE_LINE_SIZE)==0);
#endif
		for(i=0; i<table->individual_pool_size; i++){
			table->partitions[j].partition.pool[i]=i;
		}
		table->partitions[j].partition.pool_size=
				table->individual_pool_size;
		table->partitions[j].partition.memory_chunk_lower_bound=
				flow_pool;
		table->partitions[j].partition.memory_chunk_upper_bound=
				flow_pool+table->individual_pool_size;
#endif
	}
	debug_print("%s\n", "[flow_table.c]: Computing active v6 flows.");
	dpi_flow_table_update_flow_count_v6(table);
	debug_print("%s\n", "[flow_table.c]: Active v6 flows computation finished.");
}

void mc_dpi_flow_table_delete_flow_v4(
		dpi_flow_DB_v4_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		u_int16_t partition_id, ipv4_flow_t* to_delete){
	to_delete->prev->next=to_delete->next;
	to_delete->next->prev=to_delete->prev;

	if(flow_cleaner_callback)
		(*(flow_cleaner_callback))(
				to_delete->infos.tracking.flow_specific_user_data);
	--db->partitions[partition_id].partition.informations.active_flows;
	free(to_delete->infos.tracking.http_informations[0].temp_buffer);
	free(to_delete->infos.tracking.http_informations[1].temp_buffer);
	dpi_reordering_tcp_delete_all_fragments(&(to_delete->infos.tracking));

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
	if(likely(to_delete>=db->partitions[partition_id].partition.
			     memory_chunk_lower_bound &&
			  to_delete<db->partitions[partition_id].partition.
			  memory_chunk_upper_bound)){
		debug_print("%s\n", "[flow_table.c]: Reinserting the flow"
				    " in the pool.");
		db->partitions[partition_id].partition.pool
			[db->partitions[partition_id].partition.pool_size]=
			to_delete-db->partitions[partition_id].partition.
			memory_chunk_lower_bound;
		++db->partitions[partition_id].partition.pool_size;
	}else{
		debug_print("%s\n", "[flow_table.c]: Poolsize exceeded,"
				    " removing the flow.");
		v4_flow_free(to_delete);
	}
#else
	v4_flow_free(to_delete);
#endif
}

void mc_dpi_flow_table_delete_flow_v6(
		dpi_flow_DB_v6_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		u_int16_t partition_id,
		ipv6_flow_t* to_delete){
	to_delete->prev->next=to_delete->next;
	to_delete->next->prev=to_delete->prev;

	if(flow_cleaner_callback)
		(*(flow_cleaner_callback))(to_delete->infos.
				                   tracking.flow_specific_user_data);
	--db->partitions[partition_id].partition.informations.active_flows;
	free(to_delete->infos.tracking.http_informations[0].temp_buffer);
	free(to_delete->infos.tracking.http_informations[1].temp_buffer);
	dpi_reordering_tcp_delete_all_fragments(&(to_delete->infos.tracking));

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
	if(likely(to_delete>=db->partitions[partition_id].
			  partition.memory_chunk_lower_bound &&
			  to_delete<db->partitions[partition_id].
			  partition.memory_chunk_upper_bound)){
		debug_print("%s\n", "[flow_table.c]: Reinserting the"
				    " flow in the pool.");
		db->partitions[partition_id].partition.pool
		      [db->partitions[partition_id].partition.pool_size]=
		      to_delete-db->partitions[partition_id].partition.
		      memory_chunk_lower_bound;
		++db->partitions[partition_id].partition.pool_size;
	}else{
		debug_print("%s\n", "[flow_table.c]: Poolsize exceeded,"
				    " removing the flow.");
		v6_flow_free(to_delete);
	}
#else
	v6_flow_free(to_delete);
#endif
}

void dpi_flow_table_delete_flow_v4(
		dpi_flow_DB_v4_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		ipv4_flow_t* to_delete){
	mc_dpi_flow_table_delete_flow_v4(db, flow_cleaner_callback,
			                         0, to_delete);
}

void dpi_flow_table_delete_flow_v6(
		dpi_flow_DB_v6_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		ipv6_flow_t* to_delete){
	mc_dpi_flow_table_delete_flow_v6(db, flow_cleaner_callback,
			                         0, to_delete);
}



#ifndef DPI_DEBUG
static
#endif
void dpi_flow_table_check_expiration_v4(
		dpi_flow_DB_v4_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		u_int16_t partition_id,
		u_int32_t current_time){
	u_int32_t i;
#if !DPI_USE_MTF
	ipv4_flow_t* current;
#endif
	for(i=db->partitions[partition_id].partition.
			 informations.lowest_index;
	    i<=db->partitions[partition_id].partition.
			informations.highest_index; i++){
		/**
		 * Set the last timestamp for the sentinel node in such
		 * a way that we simplify the loop over the list.
		 **/
		db->table[i].last_timestamp=current_time;
#if DPI_USE_MTF
		while(current_time-db->table[i].prev->last_timestamp>
	            DPI_FLOW_TABLE_MAX_IDLE_TIME){
			mc_dpi_flow_table_delete_flow_v4(db,
					                         flow_cleaner_callback,
					                         partition_id,
					                         db->table[i].prev);
		}
#else
		current=db->table[i].prev;
		while(current!=&(db->table[i])){
			if(current_time-db->table[i].prev->last_timestamp>
	             DPI_FLOW_TABLE_MAX_IDLE_TIME){
				mc_dpi_flow_table_delete_flow_v4(db,
						                         flow_cleaner_callback,
						                         partition_id,
						                         db->table[i].prev);
			}
			current=current->prev;
		}
#endif
	}
}

#ifndef DPI_DEBUG
static
#endif
void dpi_flow_table_check_expiration_v6(
		dpi_flow_DB_v6_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		u_int16_t partition_id,
		u_int32_t current_time){


	u_int32_t i;
#if !DPI_USE_MTF
	ipv6_flow_t* current;
#endif
	for(i=db->partitions[partition_id].partition.
		  informations.lowest_index;
		i<=db->partitions[partition_id].partition.
		  informations.highest_index; i++){

		/**
		 *  Set the last timestamp for the sentinel node in such a way
		 *  that we simplify the loop over the list.
		 **/
		db->table[i].last_timestamp=current_time;
#if DPI_USE_MTF
		while(current_time-db->table[i].prev->last_timestamp>
					DPI_FLOW_TABLE_MAX_IDLE_TIME){
			mc_dpi_flow_table_delete_flow_v6(db,
					                         flow_cleaner_callback,
					                         partition_id,
					                         db->table[i].prev);
		}
#else
		current=db->table[i].prev;
		while(current!=&(db->table[i])){
			if(current_time-db->table[i].prev->last_timestamp>
				    DPI_FLOW_TABLE_MAX_IDLE_TIME){
				mc_dpi_flow_table_delete_flow_v6(db,
						                         flow_cleaner_callback,
						                         partition_id,
						                         db->table[i].prev);
			}
			current=current->prev;
		}
#endif
	}
}

#if 0
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void print_flow(ipv4_flow_t* iterator) {
	struct in_addr src, dst;
	src.s_addr = iterator->srcaddr;
	dst.s_addr = iterator->dstaddr;
	printf("%s -> ", inet_ntoa(src));
	printf("%s : ", inet_ntoa(dst));

	printf("%u -> ", ntohs(iterator->srcport));
	printf("%u : ", ntohs(iterator->dstport));
	printf("%u\n", iterator->l4prot);
}
#endif


ipv4_flow_t* mc_dpi_flow_table_find_or_create_flow_v4(
		dpi_library_state_t* state, u_int16_t partition_id,
		u_int32_t index, dpi_pkt_infos_t *pkt_infos){


	dpi_flow_DB_v4_t *db=(dpi_flow_DB_v4_t*) state->db4;

	ipv4_flow_t* head=&(db->table[index]);
	ipv4_flow_t* iterator=head->next;

	debug_print("%s\n", "[flow_table.c]: "
			    "dpi_flow_table_find_or_create_flow_v4 invoked.");

	/** Flow searching. **/
	while(iterator!=head && !v4_equals(iterator, pkt_infos)){
		iterator=iterator->next;
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
	if(iterator != head && pkt_infos->l4prot == IPPROTO_TCP && 
	   iterator->infos.tracking.seen_rst && 
	   ((struct tcphdr*) (pkt_infos->pkt + pkt_infos->l4offset))->syn){
		// Delete old flow.
		mc_dpi_flow_table_delete_flow_v4(db, state->flow_cleaner_callback,
					                     partition_id, iterator);
		// Force the following code to create a new flow.
		iterator = head;
	}

	/**Flow not found, add it after the head.**/
	if(iterator==head){
		if(unlikely(db->partitions[partition_id].partition.
				    informations.active_flows==
				    db->partitions[partition_id].partition.
				    informations.max_active_flows))
			return NULL;
#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		if(likely(db->partitions[partition_id].partition.pool_size!=0)){
			debug_print("%s\n", "[flow_table.c]: New flow created, "
					    "extracting an empty flow from the pool.");
			/** Remove the flow from the pool. **/
			u_int32_t p=db->partitions[partition_id].
					    partition.pool[--db->partitions[partition_id].
					    partition.pool_size];
			iterator=&(db->partitions[partition_id].partition.
					   memory_chunk_lower_bound[p]);
		}else{
			debug_print("%s\n", "[flow_table.c]: New flow created, "
					    " pool exhausted, allocating a new flow.");
			iterator=v4_flow_alloc();
		}
#else
		iterator=v4_flow_alloc();
#endif
		assert(iterator);

		/**Creates new flow and inserts it in the list.**/
		iterator->srcaddr=pkt_infos->src_addr_t.ipv4_srcaddr;
		iterator->dstaddr=pkt_infos->dst_addr_t.ipv4_dstaddr;
		iterator->srcport=pkt_infos->srcport;
		iterator->dstport=pkt_infos->dstport;
		iterator->l4prot=pkt_infos->l4prot;
		iterator->prev=head;
		iterator->next=head->next;
		iterator->prev->next=iterator;
		iterator->next->prev=iterator;
		dpi_init_flow_infos(state, &(iterator->infos), pkt_infos->l4prot);

		++db->partitions[partition_id].partition.informations.
		      active_flows;
	}
#if DPI_USE_MTF
	else if(iterator->prev!=head){
		/**
		 * Remove the flow from the current position. It will be inserted
		 * in the first position (Move to front). In this way collisions
		 * lists are sorted from the highest to the lowest 'last update'
		 * timestamp.
		 **/
		iterator->prev->next=iterator->next;
		iterator->next->prev=iterator->prev;
		iterator->prev=head;
		iterator->next=head->next;
		iterator->prev->next=iterator;
		iterator->next->prev=iterator;
	}
#endif

	iterator->last_timestamp=pkt_infos->processing_time;

	if(unlikely(pkt_infos->processing_time-db->partitions[partition_id].
			    partition.informations.last_walk>=
			    DPI_FLOW_TABLE_WALK_TIME)){
		dpi_flow_table_check_expiration_v4((dpi_flow_DB_v4_t*) state->db4,
				                           state->flow_cleaner_callback,
				                           partition_id,
				                           pkt_infos->processing_time);
		db->partitions[partition_id].partition.informations.last_walk=
				                           pkt_infos->processing_time;
	}

	if(iterator->srcaddr==pkt_infos->src_addr_t.ipv4_srcaddr &&
	   iterator->srcport==pkt_infos->srcport){
		pkt_infos->direction=0;
	}else{
		pkt_infos->direction=1;
	}

	return iterator;
}


u_int32_t dpi_compute_v4_hash_function(
		dpi_flow_DB_v4_t *db,
		const dpi_pkt_infos_t* const pkt_infos){
#if DPI_FLOW_TABLE_HASH_VERSION == DPI_FNV_HASH
	u_int32_t row=v4_fnv_hash_function(pkt_infos)%db->total_size;
#elif DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH
	u_int32_t row=v4_hash_murmur3(pkt_infos, db->seed)%db->total_size;
#elif DPI_FLOW_TABLE_HASH_VERSION == DPI_BKDR_HASH
	u_int32_t row=v4_hash_function_bkdr(pkt_infos)%db->total_size;
#else /** Default hash function is the simplest one. **/
	u_int32_t row=v4_hash_function_simple(pkt_infos)%db->total_size;
#endif
	return row;
}

ipv4_flow_t* dpi_flow_table_find_or_create_flow_v4(
		dpi_library_state_t* state,
		dpi_pkt_infos_t* pkt_infos){
	return mc_dpi_flow_table_find_or_create_flow_v4(
			state, 0,
			dpi_compute_v4_hash_function(
					(dpi_flow_DB_v4_t*) state->db4, pkt_infos),
					pkt_infos);
}

ipv6_flow_t* mc_dpi_flow_table_find_or_create_flow_v6(
		dpi_library_state_t* state,
		u_int16_t partition_id,
		u_int32_t index,
		dpi_pkt_infos_t* pkt_infos){
	dpi_flow_DB_v6_t *db=(dpi_flow_DB_v6_t*) state->db6;

	ipv6_flow_t* head=&(db->table[index]);
	ipv6_flow_t* iterator=head->next;

	debug_print("%s\n", "[flow_table.c]: "
			    "dpi_flow_table_find_or_create_flow_v6 invoked.");

	/** Flow searching. **/
	while(iterator!=head && !v6_equals(iterator, pkt_infos)){
		iterator=iterator->next;
	}

	/**Flow not found, add it after the head.**/
	if(iterator==head){
		if(unlikely(db->partitions[partition_id].partition.
				    informations.active_flows==
				    db->partitions[partition_id].partition.
				    informations.max_active_flows))
			return NULL;

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
		if(likely(db->partitions[partition_id].partition.pool_size!=0)){
			debug_print("%s\n", "[flow_table.c]: New flow created,"
					    " extracting an empty flow from the pool.");
			u_int32_t p=db->partitions[partition_id].partition.pool
					    [--db->partitions[partition_id].
					    partition.pool_size];
			iterator=&(db->partitions[partition_id].partition.
					   memory_chunk_lower_bound[p]);
		}else{
			debug_print("%s\n", "[flow_table.c]: New flow created, "
					    "pool exhausted, allocating a new flow.");
			iterator=v6_flow_alloc();
		}
#else
		iterator=v6_flow_alloc();
#endif
		assert(iterator);

		/**Creates new flow and inserts it in the list.**/
		iterator->srcaddr=pkt_infos->src_addr_t.ipv6_srcaddr;
		iterator->dstaddr=pkt_infos->dst_addr_t.ipv6_dstaddr;
		iterator->srcport=pkt_infos->srcport;
		iterator->dstport=pkt_infos->dstport;
		iterator->l4prot=pkt_infos->l4prot;
		iterator->prev=head;
		iterator->next=head->next;
		iterator->prev->next=iterator;
		iterator->next->prev=iterator;
		dpi_init_flow_infos(state, &(iterator->infos), pkt_infos->l4prot);

		++db->partitions[partition_id].partition.informations.
		                                         active_flows;
	}
#if DPI_USE_MTF
	else if(iterator->prev!=head){
		/**
		 * Remove the flow from the current position. It will be inserted
		 * in the first position (Move to front). In this way collisions
		 * lists are sorted from the highest to the lowest last update
		 * timestamp.
		 **/
		debug_print("%s\n", "[flow_table.c]: Flow already exists, "
				    "move to front.");
		iterator->prev->next=iterator->next;
		iterator->next->prev=iterator->prev;
		iterator->prev=head;
		iterator->next=head->next;
		iterator->prev->next=iterator;
		iterator->next->prev=iterator;
	}
#endif

	iterator->last_timestamp=pkt_infos->processing_time;

	if(unlikely(pkt_infos->processing_time-
			   db->partitions[partition_id].partition.
			   informations.last_walk>=DPI_FLOW_TABLE_WALK_TIME)){
		dpi_flow_table_check_expiration_v6(
				(dpi_flow_DB_v6_t*) state->db6,
				state->flow_cleaner_callback,
				partition_id,
				pkt_infos->processing_time);
		db->partitions[partition_id].partition.informations.last_walk=
				pkt_infos->processing_time;
	}

	if(dpi_v6_addresses_equal(iterator->srcaddr,
			                  pkt_infos->src_addr_t.ipv6_srcaddr) &&
			                  iterator->srcport==pkt_infos->srcport){
		pkt_infos->direction=0;
	}else
		pkt_infos->direction=1;

	return iterator;
}


u_int32_t dpi_compute_v6_hash_function(
		dpi_flow_DB_v6_t *db,
		const dpi_pkt_infos_t* const pkt_infos){
#if DPI_FLOW_TABLE_HASH_VERSION == DPI_FNV_HASH
	u_int32_t row=v6_fnv_hash_function(pkt_infos) % db->total_size;
#elif DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH
	u_int32_t row=v6_hash_murmur3(pkt_infos, db->seed)%db->total_size;
#elif DPI_FLOW_TABLE_HASH_VERSION == DPI_BKDR_HASH
	u_int32_t row=v6_hash_function_bkdr(pkt_infos)%db->total_size;
#else /** Default hash function is the simplest one. **/
	u_int32_t row=v6_hash_function_simple(pkt_infos)%db->total_size;
#endif
	return row;
}

ipv6_flow_t* dpi_flow_table_find_or_create_flow_v6(
		dpi_library_state_t* state,
		dpi_pkt_infos_t* pkt_infos){
	return mc_dpi_flow_table_find_or_create_flow_v6(
			state, 0,
			dpi_compute_v6_hash_function(
					(dpi_flow_DB_v6_t*) state->db6, pkt_infos),
					pkt_infos);
}



/**
 * Search for a flow in the table.
 * @param state A pointer to the state of the library.
 * @param index The hash index of the flow to search.
 * @param pkt_infos The L3 and L4 packet's parsed informations.
 * @return A pointer to the flow if it is present, NULL otherwise.
 */
ipv4_flow_t* dpi_flow_table_find_flow_v4(
		dpi_library_state_t* state,
		u_int32_t index,
		dpi_pkt_infos_t* pkt_infos){
	dpi_flow_DB_v4_t *db=(dpi_flow_DB_v4_t*) state->db4;

	ipv4_flow_t* head=&(db->table[index]);
	ipv4_flow_t* iterator=head->next;

	/** Flow searching. **/
	while(iterator!=head && !v4_equals(iterator, pkt_infos)){
		iterator=iterator->next;
	}

	if(iterator==head)
		return NULL;
	else
		return iterator;
}

/**
 * Search for a flow in the table.
 * @param state A pointer to the state of the library.
 * @param index The hash index of the flow to search.
 * @param pkt_infos The L3 and L4 packet's parsed informations.
 * @return A pointer to the flow if it is present, NULL otherwise.
 */
ipv6_flow_t* dpi_flow_table_find_flow_v6(
		dpi_library_state_t* state,
		u_int32_t index,
		dpi_pkt_infos_t* pkt_infos){
	dpi_flow_DB_v6_t *db=(dpi_flow_DB_v6_t*) state->db6;

	ipv6_flow_t* head=&(db->table[index]);
	ipv6_flow_t* iterator=head->next;

	/** Flow searching. **/
	while(iterator!=head && !v6_equals(iterator, pkt_infos)){
		iterator=iterator->next;
	}

	if(iterator==head)
		return NULL;
	else
		return iterator;
}

void dpi_flow_table_delete_v4(
		dpi_flow_DB_v4_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback){


	u_int32_t i;
	u_int16_t j;
	if(db!=NULL){
		if(db->table!=NULL){
			for(j=0; j<db->num_partitions; ++j){
				for(i=db->partitions[j].partition.informations.
						  lowest_index;
					i<=db->partitions[j].partition.informations.
					      highest_index; ++i){
					while(db->table[i].next!=&(db->table[i])){
						mc_dpi_flow_table_delete_flow_v4(
								db, flow_cleaner_callback,
								j, db->table[i].next);
					}
				}
#if DPI_FLOW_TABLE_USE_MEMORY_POOL
#if DPI_NUMA_AWARE
				numa_free(db->partitions[j].partition.
						        memory_chunk_lower_bound,
						  sizeof(ipv6_flow_t)*db->individual_pool_size);
				numa_free(db->partitions[j].partition.
						         pool,
						  sizeof(u_int32_t)*db->individual_pool_size);
#else
				free(db->partitions[j].partition.
						 memory_chunk_lower_bound);
				free(db->partitions[j].partition.pool);
#endif
#endif
			}
		}



#if DPI_NUMA_AWARE
		numa_free(db->partitions,
				  sizeof(dpi_flow_DB_v4_partition_t)*db->num_partitions);
		numa_free(db->table, sizeof(ipv4_flow_t)*db->total_size);
#else
		free(db->partitions);
		free(db->table);
#endif
		free(db);
	}
}

void dpi_flow_table_delete_v6(
		dpi_flow_DB_v6_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback){
	u_int32_t i;
	u_int16_t j;
	if(db!=NULL){
		if(db->table!=NULL){
			for(j=0; j<db->num_partitions; ++j){
				for(i=db->partitions[j].partition.
						  informations.lowest_index;
					i<=db->partitions[j].partition.
					       informations.highest_index; ++i){
					while(db->table[i].next!=&(db->table[i])){
						mc_dpi_flow_table_delete_flow_v6(
								db, flow_cleaner_callback,
								j, db->table[i].next);
					}
				}
#if DPI_FLOW_TABLE_USE_MEMORY_POOL
#if DPI_NUMA_AWARE
				numa_free(db->partitions[j].partition.
						      memory_chunk_lower_bound,
						  sizeof(ipv4_flow_t)*db->individual_pool_size);
				numa_free(db->partitions[j].partition.pool,
						  sizeof(u_int32_t)*db->individual_pool_size);
#else
				free(db->partitions[j].partition.
						 memory_chunk_lower_bound);
				free(db->partitions[j].partition.pool);
#endif
#endif
			}
		}

#if DPI_NUMA_AWARE
		numa_free(db->table, sizeof(ipv6_flow_t)*db->total_size);
		numa_free(db->partitions,
				  sizeof(dpi_flow_DB_v6_partition_t)*db->num_partitions);
#else
		free(db->partitions);
		free(db->table);
#endif
		free(db);
	}
}



