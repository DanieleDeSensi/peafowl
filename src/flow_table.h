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

#include "api.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ipv4_flow ipv4_flow_t;
typedef struct ipv6_flow ipv6_flow_t;

struct ipv4_flow{
	u_int16_t srcport;
	u_int16_t dstport;
	u_int32_t srcaddr;
	u_int32_t dstaddr;
	u_int8_t l4prot;

	ipv4_flow_t* prev;
	ipv4_flow_t* next;
	dpi_flow_infos_t infos;
	u_int32_t last_timestamp;
};

struct ipv6_flow{
	u_int16_t srcport;
	u_int16_t dstport;
	struct in6_addr srcaddr;
	struct in6_addr dstaddr;
	u_int8_t l4prot;

	ipv6_flow_t* prev;
	ipv6_flow_t* next;
	dpi_flow_infos_t infos;
	u_int32_t last_timestamp;
};


typedef struct dpi_flow_DB_v4 dpi_flow_DB_v4_t;
typedef struct dpi_flow_DB_v6 dpi_flow_DB_v6_t;

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
dpi_flow_DB_v4_t* dpi_flow_table_create_v4(u_int32_t size,
		                                   u_int32_t max_active_v4_flows,
		                                   u_int16_t num_partitions,
		                                   u_int32_t start_pool_size);
dpi_flow_DB_v6_t* dpi_flow_table_create_v6(u_int32_t size,
		                                   u_int32_t max_active_v6_flows,
		                                   u_int16_t num_partitions,
		                                   u_int32_t start_pool_size);

#else
dpi_flow_DB_v4_t* dpi_flow_table_create_v4(u_int32_t size,
		                                   u_int32_t max_active_v4_flows,
		                                   u_int16_t num_partitions);
dpi_flow_DB_v6_t* dpi_flow_table_create_v6(u_int32_t size,
		                                   u_int32_t max_active_v6_flows,
		                                   u_int16_t num_partitions);
#endif

void dpi_flow_table_delete_v4(
		dpi_flow_DB_v4_t* db,
        dpi_flow_cleaner_callback* flow_cleaner_callback);
void dpi_flow_table_delete_v6(
		dpi_flow_DB_v6_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback);


/**
 * Search for a flow in the table.
 * @param state A pointer to the state of the library.
 * @param index The hash index of the flow to search.
 * @param pkt_infos The L3 and L4 packet's parsed informations.
 * @return A pointer to the flow if it is present, NULL otherwise.
 */
ipv4_flow_t* dpi_flow_table_find_flow_v4(dpi_library_state_t* state,
		                                 u_int32_t index,
		                                 dpi_pkt_infos_t* pkt_infos);

/**
 * Search for a flow in the table.
 * @param state A pointer to the state of the library.
 * @param index The hash index of the flow to search.
 * @param pkt_infos The L3 and L4 packet's parsed informations.
 * @return A pointer to the flow if it is present, NULL otherwise.
 */
ipv6_flow_t* dpi_flow_table_find_flow_v6(dpi_library_state_t* state,
		                                 u_int32_t index,
		                                 dpi_pkt_infos_t* pkt_infos);


/**
 * Find the flow to which pkt_infos belongs or creates it if doesn't
 * exists. Updates pkt_infos->direction field according to the direction
 * of the stored flow.
 * @return The informations about the flow.
 */
ipv4_flow_t* dpi_flow_table_find_or_create_flow_v4(
		dpi_library_state_t* state,
		dpi_pkt_infos_t* pkt_infos);
ipv6_flow_t* dpi_flow_table_find_or_create_flow_v6(
		dpi_library_state_t* state,
		dpi_pkt_infos_t* pkt_infos);

void dpi_flow_table_delete_flow_v4(
		dpi_flow_DB_v4_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		ipv4_flow_t* to_delete);

void dpi_flow_table_delete_flow_v6(
		dpi_flow_DB_v6_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		ipv6_flow_t* to_delete);


/**
 * They are used directly only in mc_dpi. Should never be used directly
 * by the user.
 **/
u_int32_t dpi_compute_v4_hash_function(
		dpi_flow_DB_v4_t *db,
		const dpi_pkt_infos_t* const pkt_infos);

u_int32_t dpi_compute_v6_hash_function(
		dpi_flow_DB_v6_t *db,
		const dpi_pkt_infos_t* const pkt_infos);

ipv4_flow_t* mc_dpi_flow_table_find_or_create_flow_v4(
		dpi_library_state_t* state, u_int16_t partition_id,
		u_int32_t index, dpi_pkt_infos_t* pkt_infos);

ipv6_flow_t* mc_dpi_flow_table_find_or_create_flow_v6(
		dpi_library_state_t* state, u_int16_t partition_id,
		u_int32_t index, dpi_pkt_infos_t* pkt_infos);

void dpi_flow_table_setup_partitions_v4(dpi_flow_DB_v4_t* table, 
		u_int16_t num_partitions);

void dpi_flow_table_setup_partitions_v6(dpi_flow_DB_v6_t* table, 
		u_int16_t num_partitions);

void mc_dpi_flow_table_delete_flow_v4(
		dpi_flow_DB_v4_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		u_int16_t partition_id, ipv4_flow_t* to_delete);

void mc_dpi_flow_table_delete_flow_v6(
		dpi_flow_DB_v6_t* db,
		dpi_flow_cleaner_callback* flow_cleaner_callback,
		u_int16_t partition_id, ipv6_flow_t* to_delete);

#ifdef __cplusplus
}
#endif

#endif /* FLOW_TABLE_H_ */
