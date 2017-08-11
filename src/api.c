/*
 * api.c
 *
 * Created on: 19/09/2012
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

#include "api.h"
#include "flow_table.h"
#include "hash_functions.h"
#include "utils.h"
#include "./inspectors/inspectors.h"
#include "tcp_stream_management.h"
#include "ipv4_reassembly.h"
#include "ipv6_reassembly.h"
#include <time.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <assert.h>


#include <arpa/inet.h>


#define debug_print(fmt, ...) \
        do { if (DPI_DEBUG) fprintf(stderr, fmt, __VA_ARGS__); } while (0)

/**
 * Designated initializers has been introduced with C99.
 * gcc allows them also in c89.
 **/
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L || defined(__GNUC__))
static const dpi_l7_prot_id const
	dpi_well_known_ports_association_tcp[DPI_MAX_UINT_16+1]=
		{[0 ... DPI_MAX_UINT_16]=DPI_PROTOCOL_UNKNOWN
		,[port_http]=DPI_PROTOCOL_TCP_HTTP
		,[port_bgp]=DPI_PROTOCOL_TCP_BGP
		,[port_smtp_1]=DPI_PROTOCOL_TCP_SMTP
		,[port_smtp_2]=DPI_PROTOCOL_TCP_SMTP
		,[port_pop3]=DPI_PROTOCOL_TCP_POP3
		,[port_ssl]=DPI_PROTOCOL_TCP_SSL};

static const dpi_l7_prot_id const
	dpi_well_known_ports_association_udp[DPI_MAX_UINT_16+1]=
		{[0 ... DPI_MAX_UINT_16]=DPI_PROTOCOL_UNKNOWN
		,[port_dns]=DPI_PROTOCOL_UDP_DNS
		,[port_mdns]=DPI_PROTOCOL_UDP_MDNS
		,[port_dhcp_1]=DPI_PROTOCOL_UDP_DHCP
		,[port_dhcp_2]=DPI_PROTOCOL_UDP_DHCP
		,[port_dhcpv6_1]=DPI_PROTOCOL_UDP_DHCPv6
		,[port_dhcpv6_2]=DPI_PROTOCOL_UDP_DHCPv6
		,[port_sip]=DPI_PROTOCOL_UDP_SIP
		,[port_ntp]=DPI_PROTOCOL_UDP_NTP};


static const dpi_inspector_callback const
	udp_inspectors[DPI_NUM_UDP_PROTOCOLS]=
		{[DPI_PROTOCOL_UDP_DHCP]=check_dhcp
		,[DPI_PROTOCOL_UDP_DHCPv6]=check_dhcpv6
		,[DPI_PROTOCOL_UDP_DNS]=check_dns
		,[DPI_PROTOCOL_UDP_MDNS]=check_mdns
		,[DPI_PROTOCOL_UDP_SIP]=check_sip
		,[DPI_PROTOCOL_UDP_RTP]=check_rtp
		,[DPI_PROTOCOL_UDP_SKYPE]=check_skype
		,[DPI_PROTOCOL_UDP_NTP]=check_ntp};

static const dpi_inspector_callback const
	tcp_inspectors[DPI_NUM_TCP_PROTOCOLS]=
		{[DPI_PROTOCOL_TCP_BGP]=check_bgp
		,[DPI_PROTOCOL_TCP_HTTP]=check_http
		,[DPI_PROTOCOL_TCP_SMTP]=check_smtp
		,[DPI_PROTOCOL_TCP_POP3]=check_pop3
		,[DPI_PROTOCOL_TCP_SSL]=check_ssl};

static const dpi_inspector_callback const
	udp_callbacks_manager[DPI_NUM_UDP_PROTOCOLS];

static const dpi_inspector_callback const
	tcp_callbacks_manager[DPI_NUM_TCP_PROTOCOLS]=
		{[DPI_PROTOCOL_TCP_HTTP]=invoke_callbacks_http,
		[DPI_PROTOCOL_TCP_SSL]=invoke_callbacks_ssl
		};

#else
static dpi_l7_prot_id
       dpi_well_known_ports_association_tcp[DPI_MAX_UINT_16+1];
static dpi_l7_prot_id
       dpi_well_known_ports_association_udp[DPI_MAX_UINT_16+1];

static dpi_inspector_callback udp_inspectors[DPI_NUM_UDP_PROTOCOLS];
static dpi_inspector_callback tcp_inspectors[DPI_NUM_TCP_PROTOCOLS];

static dpi_inspector_callback
       udp_callbacks_manager[DPI_NUM_UDP_PROTOCOLS];

static dpi_inspector_callback
       tcp_callbacks_manager[DPI_NUM_TCP_PROTOCOLS];
#endif

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
dpi_library_state_t* dpi_init_stateful_num_partitions(
		       u_int32_t size_v4, u_int32_t size_v6,
		       u_int32_t max_active_v4_flows,
		       u_int32_t max_active_v6_flows,
		       u_int16_t num_table_partitions){

	dpi_library_state_t* state =
			 (dpi_library_state_t*) malloc(sizeof(dpi_library_state_t));

	assert(state);

	bzero(state, sizeof(dpi_library_state_t));

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
	state->db4=dpi_flow_table_create_v4(size_v4, max_active_v4_flows,
	                     num_table_partitions,
			             DPI_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4);
	state->db6=dpi_flow_table_create_v6(size_v6, max_active_v6_flows,
	                     num_table_partitions,
	                     DPI_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6);
#else
	state->db4=dpi_flow_table_create_v4(size_v4, max_active_v4_flows,
	                                    num_table_partitions);
	state->db6=dpi_flow_table_create_v6(size_v6, max_active_v6_flows,
	                                    num_table_partitions);
#endif
	dpi_set_max_trials(state, DPI_DEFAULT_MAX_TRIALS_PER_FLOW);
	dpi_inspect_all(state);

	dpi_ipv4_fragmentation_enable(state,
			                  DPI_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE);
	dpi_ipv6_fragmentation_enable(state,
			                  DPI_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE);

	dpi_tcp_reordering_enable(state);

#if !defined(__GNUC__) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
	memset(dpi_well_known_ports_association_tcp, DPI_PROTOCOL_UNKNOWN,
	       DPI_MAX_UINT_16+1);
	memset(dpi_well_known_ports_association_udp, DPI_PROTOCOL_UNKNOWN,
           DPI_MAX_UINT_16+1);
	dpi_well_known_ports_association_tcp[port_http]=
			DPI_PROTOCOL_TCP_HTTP;
	dpi_well_known_ports_association_tcp[port_bgp]=
			DPI_PROTOCOL_TCP_BGP;
	dpi_well_known_ports_association_tcp[port_smtp_1]=
			DPI_PROTOCOL_TCP_SMTP;
	dpi_well_known_ports_association_tcp[port_smtp_2]=
			DPI_PROTOCOL_TCP_SMTP;
	dpi_well_known_ports_association_tcp[port_pop3]=
			DPI_PROTOCOL_TCP_POP3;

	dpi_well_known_ports_association_udp[port_dns]=
			DPI_PROTOCOL_UDP_DNS;
	dpi_well_known_ports_association_udp[port_mdns]=D
			PI_PROTOCOL_UDP_MDNS;
	dpi_well_known_ports_association_udp[port_dhcp_1]=
			DPI_PROTOCOL_UDP_DHCP;
	dpi_well_known_ports_association_udp[port_dhcp_2]=
			DPI_PROTOCOL_UDP_DHCP;
	dpi_well_known_ports_association_udp[port_dhcpv6_1]=
			DPI_PROTOCOL_UDP_DHCPv6;
	dpi_well_known_ports_association_udp[port_dhcpv6_2]=
			DPI_PROTOCOL_UDP_DHCPv6;
	dpi_well_known_ports_association_udp[port_ntp]=
			DPI_PROTOCOL_UDP_NTP;
	dpi_well_known_ports_association_udp[port_sip]=
			DPI_PROTOCOL_UDP_SIP;


	udp_inspectors[DPI_PROTOCOL_UDP_DHCP]=check_dhcp;
	udp_inspectors[DPI_PROTOCOL_UDP_DHCPv6]=check_dhcpv;
	udp_inspectors[DPI_PROTOCOL_UDP_DNS]=check_dns;
	udp_inspectors[DPI_PROTOCOL_UDP_MDNS]=check_mdns;
	udp_inspectors[DPI_PROTOCOL_UDP_NTP]=check_ntp;
	udp_inspectors[DPI_PROTOCOL_UDP_SIP]=check_sip;
	udp_inspectors[DPI_PROTOCOL_UDP_RTP]=check_rtp;
	udp_inspectors[DPI_PROTOCOL_UDP_SKYPE]=check_skype;

	tcp_inspectors[DPI_PROTOCOL_TCP_BGP]=check_bgp;
	tcp_inspectors[DPI_PROTOCOL_TCP_HTTP]=check_http;
	tcp_inspectors[DPI_PROTOCOL_TCP_SMTP]=check_smtp;
	tcp_inspectors[DPI_PROTOCOL_TCP_POP3]=check_pop3;
	tcp_inspectors[DPI_PROTOCOL_TCP_POP3]=check_ssl;

	tcp_callbacks_manager[DPI_PROTOCOL_TCP_HTTP]=invoke_callbacks_http;
	tcp_callbacks_manager[DPI_PROTOCOL_TCP_HTTP]=invoke_callbacks_ssl;
#endif
	return state;
}

dpi_library_state_t* dpi_init_stateful(
		       u_int32_t size_v4, u_int32_t size_v6,
		       u_int32_t max_active_v4_flows,
		       u_int32_t max_active_v6_flows){

	return dpi_init_stateful_num_partitions(size_v4, size_v6,
	                                        max_active_v4_flows,
	                                        max_active_v6_flows, 1);
}



/**
 * Initializes the state of the library. If not specified otherwise after
 * the initialization, the library will consider all the protocols active.
 * @return A pointer to the state of the library otherwise.
 */
dpi_library_state_t* dpi_init_stateless(void){
	return dpi_init_stateful(0,0,0,0);
}

/**
 * Sets the maximum number of times that the library tries to guess the
 * protocol. During the flow protocol identification, after this number
 * of trials, in the case in which it cannot decide between two or more
 * protocols, one of them will be chosen, otherwise DPI_PROTOCOL_UNKNOWN
 * will be returned.
 * @param state A pointer to the state of the library.
 * @param max_trials Maximum number of trials. Zero will be consider as
 *                   infinity.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded, DPI_STATE_UPDATE_FAILURE
 *         otherwise.
 */
u_int8_t dpi_set_max_trials(dpi_library_state_t *state, u_int16_t max_trials){
	state->max_trials=max_trials;
	return DPI_STATE_UPDATE_SUCCESS;
}


/**
 * Enable IPv4 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv4
 *                     fragments informations.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded, DPI_STATE_UPDATE_FAILURE
 *         otherwise.
 */
u_int8_t dpi_ipv4_fragmentation_enable(dpi_library_state_t *state,
		                               u_int16_t table_size){
	if(likely(state)){
		state->ipv4_frag_state=dpi_reordering_enable_ipv4_fragmentation(table_size);
		if(state->ipv4_frag_state)
			return DPI_STATE_UPDATE_SUCCESS;
		else
			return DPI_STATE_UPDATE_FAILURE;
	}else
		return DPI_STATE_UPDATE_FAILURE;
}

/**
 * Enable IPv6 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv6
 *                     fragments informations.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded, DPI_STATE_UPDATE_FAILURE
 *         otherwise.
 */
u_int8_t dpi_ipv6_fragmentation_enable(dpi_library_state_t *state,
                                       u_int16_t table_size){
	if(likely(state)){
		state->ipv6_frag_state=dpi_reordering_enable_ipv6_fragmentation(
				                 table_size);
		if(state->ipv6_frag_state)
			return DPI_STATE_UPDATE_SUCCESS;
		else
			return DPI_STATE_UPDATE_FAILURE;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Sets the amount of memory that a single host can use for IPv4
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                any IPv4 host can use.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv4_fragmentation_set_per_host_memory_limit(
		        dpi_library_state_t *state,
		        u_int32_t per_host_memory_limit){
	if(likely(state && state->ipv4_frag_state)){
		dpi_reordering_ipv4_fragmentation_set_per_host_memory_limit(
				          state->ipv4_frag_state, per_host_memory_limit);
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Sets the amount of memory that a single host can use for IPv6
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                 any IPv6 host can use.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv6_fragmentation_set_per_host_memory_limit(
		         dpi_library_state_t *state,
		         u_int32_t per_host_memory_limit){
	if(likely(state && state->ipv6_frag_state)){
		dpi_reordering_ipv6_fragmentation_set_per_host_memory_limit(
				      state->ipv6_frag_state, per_host_memory_limit);
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

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
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv4_fragmentation_set_total_memory_limit(
		         dpi_library_state_t *state,
		         u_int32_t total_memory_limit){
	if(likely(state && state->ipv4_frag_state)){
		dpi_reordering_ipv4_fragmentation_set_total_memory_limit(
				      state->ipv4_frag_state, total_memory_limit);
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Sets the total amount of memory that can be used for IPv6
 * defragmentation. If fragmentation is disabled and then enabled, this
 * information must be passed again. Otherwise default value will be used.
 * @param state               A pointer to the state of the library
 * @param total_memory_limit  The maximum amount of memory that can be
 *                            used for IPv6 defragmentation.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv6_fragmentation_set_total_memory_limit(
		         dpi_library_state_t *state,
		         u_int32_t total_memory_limit){
	if(likely(state && state->ipv6_frag_state)){
		dpi_reordering_ipv6_fragmentation_set_total_memory_limit(
				      state->ipv6_frag_state, total_memory_limit);
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Sets the maximum time (in seconds) that can be spent to reassembly an
 * IPv4 fragmented datagram. Is the maximum time gap between the first and
 * last fragments of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv4_fragmentation_set_reassembly_timeout(
		         dpi_library_state_t *state,
		         u_int8_t timeout_seconds){
	if(likely(state && state->ipv4_frag_state)){
		dpi_reordering_ipv4_fragmentation_set_reassembly_timeout(
				      state->ipv4_frag_state, timeout_seconds);
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Sets the maximum time (in seconds) that can be spent to reassembly an
 * IPv6 fragmented datagram. Is the maximum time gap between the first and
 * last fragments of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv6_fragmentation_set_reassembly_timeout(
		         dpi_library_state_t *state,
		         u_int8_t timeout_seconds){
	if(likely(state && state->ipv6_frag_state)){
		dpi_reordering_ipv6_fragmentation_set_reassembly_timeout(
				      state->ipv6_frag_state, timeout_seconds);
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Disable IPv4 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv4_fragmentation_disable(dpi_library_state_t *state){
	if(likely(state && state->ipv4_frag_state)){
		dpi_reordering_disable_ipv4_fragmentation(state->ipv4_frag_state);
		state->ipv4_frag_state=NULL;
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Disable IPv6 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_ipv6_fragmentation_disable(dpi_library_state_t *state){
	if(likely(state && state->ipv6_frag_state)){
		dpi_reordering_disable_ipv6_fragmentation(state->ipv6_frag_state);
		state->ipv6_frag_state=NULL;
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}


/**
 * If enabled, the library will reorder out of order TCP packets
 * (enabled by default).
 * @param state  A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_tcp_reordering_enable(dpi_library_state_t* state){
	if(likely(state)){
		state->tcp_reordering_enabled=1;
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * If it is called, the library will not reorder out of order TCP packets.
 * Out-of-order segments will be delivered to the inspector as they
 * arrive. This means that the inspector may not be able to identify the
 * application protocol. Moreover, if there are callbacks saved for TCP
 * based protocols, if TCP reordering is disabled, the extracted
 * informations could be erroneous or incomplete.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_tcp_reordering_disable(dpi_library_state_t* state){
	if(likely(state)){
		state->tcp_reordering_enabled=0;
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Enable a protocol inspector.
 * @param state         A pointer to the state of the library.
 * @param protocol      The protocol to enable.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_set_protocol(dpi_library_state_t *state,
		                  dpi_protocol_t protocol){
	if(protocol.l4prot==IPPROTO_UDP){
		BITSET(state->udp_protocols_to_inspect, protocol.l7prot);
		++state->udp_active_protocols;
		return DPI_STATE_UPDATE_SUCCESS;
	}else if(protocol.l4prot==IPPROTO_TCP){
		BITSET(state->tcp_protocols_to_inspect, protocol.l7prot);
		++state->tcp_active_protocols;
		return DPI_STATE_UPDATE_SUCCESS;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}
}

/**
 * Disable a protocol inspector.
 * @param state       A pointer to the state of the library.
 * @param protocol    The protocol to disable.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_delete_protocol(dpi_library_state_t *state,
		                     dpi_protocol_t protocol){
	char *protocol_mask;
	char *inspector_mask;
	if(protocol.l4prot==IPPROTO_UDP){
		protocol_mask=state->udp_protocols_to_inspect;
		inspector_mask=state->udp_active_callbacks;
		--state->udp_active_protocols;
	}else if(protocol.l4prot==IPPROTO_TCP){
		protocol_mask=state->tcp_protocols_to_inspect;
		inspector_mask=state->tcp_active_callbacks;
		--state->tcp_active_protocols;
	}else{
		return DPI_STATE_UPDATE_FAILURE;
	}

	BITCLEAR(protocol_mask, protocol.l7prot);
	BITCLEAR(inspector_mask, protocol.l7prot);
	return DPI_STATE_UPDATE_SUCCESS;
}

/**
 * Enable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_inspect_all(dpi_library_state_t *state){
	unsigned char nonzero = ~0;
	memset(state->udp_protocols_to_inspect, nonzero,
	       BITNSLOTS(DPI_NUM_UDP_PROTOCOLS));
	memset(state->tcp_protocols_to_inspect, nonzero,
	       BITNSLOTS(DPI_NUM_TCP_PROTOCOLS));

	state->udp_active_protocols=DPI_NUM_UDP_PROTOCOLS;
	state->tcp_active_protocols=DPI_NUM_TCP_PROTOCOLS;
	return DPI_STATE_UPDATE_SUCCESS;
}


/**
 * Disable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_inspect_nothing(dpi_library_state_t *state){
	bzero(state->udp_protocols_to_inspect, BITNSLOTS(DPI_NUM_UDP_PROTOCOLS));
	bzero(state->tcp_protocols_to_inspect, BITNSLOTS(DPI_NUM_TCP_PROTOCOLS));

	state->udp_active_protocols=0;
	state->tcp_active_protocols=0;

	bzero(state->tcp_active_callbacks, DPI_NUM_TCP_PROTOCOLS);
	bzero(state->udp_active_callbacks, DPI_NUM_UDP_PROTOCOLS);
	return DPI_STATE_UPDATE_SUCCESS;
}

/**
 * Terminates the library.
 * @param state A pointer to the state of the library.
 */
void dpi_terminate(dpi_library_state_t *state){
	if(likely(state)){
		dpi_http_disable_callbacks(state);
		dpi_ipv4_fragmentation_disable(state);
		dpi_ipv6_fragmentation_disable(state);
		dpi_tcp_reordering_disable(state);

		dpi_flow_table_delete_v4(state->db4,
				                 state->flow_cleaner_callback);
		dpi_flow_table_delete_v6(state->db6,
				                 state->flow_cleaner_callback);

		free(state);
	}
}


/*
 * Try to detect the application protocol.
 * @param   state The state of the library.
 * @param   pkt The pointer to the beginning of IP header.
 * @param   data_length Length of the packet (from the beginning of the IP
 *          header, without L2 headers/trailers).
 * @param   current_time The current time in seconds.
 * @return  The status of the operation.  It gives additional informations
 *          about the processing of the request. If lesser than 0, an error
 *          occurred. dpi_get_error_msg() can be used to get a textual
 *          representation of the error. If greater or equal than 0 then
 *          it should not be interpreted as an error but simply gives
 *          additional informations (e.g. if the packet was IP fragmented,
 *          if it was out of order in the TCP stream, if is a segment of a
 *          larger application request, etc..). dpi_get_status_msg() can
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
dpi_identification_result_t dpi_stateful_identify_application_protocol(
		       dpi_library_state_t* state,
		       const unsigned char* pkt,
		       u_int32_t length,
		       u_int32_t current_time){

	dpi_identification_result_t r;
	r.status=DPI_STATUS_OK;
	dpi_pkt_infos_t infos;
	memset(&infos, 0, sizeof(infos));
	u_int8_t l3_status;

	r.status=dpi_parse_L3_L4_headers(state, pkt, length, &infos,
			                         current_time);

	if(unlikely(r.status==DPI_STATUS_IP_FRAGMENT || r.status<0)){
		return r;
	}

	if(infos.l4prot!=IPPROTO_TCP && infos.l4prot!=IPPROTO_UDP){
		r.status=DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
		return r;
	}

	l3_status=r.status;
	r.status=DPI_STATUS_OK;
	/**
	 * We return the status of dpi_stateful_get_app_protocol call,
	 * without giving informations on status returned
	 * by dpi_parse_L3_L4_headers. Basically we return the status which
	 * provides more informations.
	 */
	r=dpi_stateful_get_app_protocol(state, &infos);

	if(l3_status==DPI_STATUS_IP_LAST_FRAGMENT){
		free((unsigned char*) infos.pkt);
	}

	return r;
}


/*
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
 *          error occurred. dpi_get_error_msg() can be used to get a
 *          textual representation of the error. If greater or equal than
 *          0 then it should not be interpreted as an error but simply
 *          gives additional informations (e.g. if the packet was IP
 *          fragmented, if it was out of order in the TCP stream, if is a
 *          segment of a larger application request, etc..).
 *          dpi_get_status_msg() can be used to get a textual
 *          representation of the status. Status and error codes are
 *          defined above in this header file.
 *
 *          The status is DPI_STATUS_IP_FRAGMENT if the datagram is a
 *          fragment. In this case, if IP fragmentation support is
 *          enabled, the library copied the content of the datagram, so if
 *          the user wants, he can release the resources used to store the
 *          datagram.
 *
 *          The status is DPI_STATUS_IP_LAST_FRAGMENT if the received
 *          datagram allows the library to reconstruct a fragmented
 *          datagram. In this case, pkt_infos->pkt will contain a pointer
 *          to the recomposed datagram. This pointer will be different
 *          from p_pkt. The user should free() this pointer when it is no
 *          more needed (e.g. after calling
 *          dpi_state*_get_app_protocol(..)).
 */
int8_t mc_dpi_extract_packet_infos(
		       dpi_library_state_t *state, const unsigned char* p_pkt,
		       u_int32_t p_length, dpi_pkt_infos_t *pkt_infos,
		       u_int32_t current_time, int tid){
	if(unlikely(p_length==0)) return DPI_STATUS_OK;
	u_int8_t version;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	version=(p_pkt[0]>>4)&0x0F;
#elif __BYTE_ORDER == __BIG_ENDIAN
    version=(p_pkt[0]<<4)&0x0F;
#else
# error	"Please fix <bits/endian.h>"
#endif

    unsigned char* pkt=(unsigned char*) p_pkt;
    u_int32_t length=p_length;
	u_int16_t offset;
	u_int8_t more_fragments;

    pkt_infos->l4prot=0;
	pkt_infos->srcport=0;
	pkt_infos->dstport=0;

	/** Offset starting from the beginning of p_pkt. **/
    u_int32_t application_offset;
    /**
     * Offset starting from the last identified IPv4 or IPv6 header
     * (used to support tunneling).
     **/
    u_int32_t relative_offset;
    u_int32_t tmp;
	u_int8_t next_header,stop=0;

	int8_t to_return=DPI_STATUS_OK;

	struct ip6_hdr* ip6=NULL;
	struct iphdr* ip4=NULL;

	if(version==DPI_IP_VERSION_4){ 	/** IPv4 **/
		ip4=(struct iphdr*) (p_pkt);
		u_int16_t tot_len=ntohs(ip4->tot_len);

#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
		if(unlikely(length<(sizeof(struct iphdr)) || tot_len>length ||
				    tot_len<=((ip4->ihl)*4))){
			return DPI_ERROR_L3_TRUNCATED_PACKET;
		}
#endif
		/**
		 * At this point we are sure that tot_len<=length, so we set
		 * length=tot_len. In some cases indeed there may be an L2 padding
		 * at the end of the packet, so capture length (length) may be
		 * greater than the effective datagram length.
		 */
		length=tot_len;

		offset=ntohs(ip4->frag_off);
		if(unlikely((offset&DPI_IPv4_FRAGMENTATION_MF))){
			more_fragments=1;
		}else
			more_fragments=0;

		/*
		 * Offset is in 8-byte blocks. Multiplying by 8 correspond to a
		 * right shift by 3 position, but the offset was 13 bit, so it can
		 * still fit in a 16 bit integer.
		 */
		offset=(offset & DPI_IPv4_FRAGMENTATION_OFFSET_MASK)*8;

		if(likely((!more_fragments)&&(offset==0))){
			pkt=(unsigned char*) p_pkt;
		}else if(state->ipv4_frag_state!=NULL){
			pkt=dpi_reordering_manage_ipv4_fragment(
					state->ipv4_frag_state, p_pkt, current_time,
					offset, more_fragments, tid);
			if(pkt==NULL){
				return DPI_STATUS_IP_FRAGMENT;
			}
			to_return=DPI_STATUS_IP_LAST_FRAGMENT;
			ip4=(struct iphdr*) (pkt);
			length=ntohs(((struct iphdr*) (pkt))->tot_len);
		}else{
			return DPI_STATUS_IP_FRAGMENT;
		}

		pkt_infos->src_addr_t.ipv4_srcaddr=ip4->saddr;
		pkt_infos->dst_addr_t.ipv4_dstaddr=ip4->daddr;

		application_offset=(ip4->ihl)*4;
		relative_offset=application_offset;

		next_header=ip4->protocol;
	}else if(version==DPI_IP_VERSION_6){ /** IPv6 **/
		ip6=(struct ip6_hdr*) (pkt);
		u_int16_t tot_len=ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen)+
				          sizeof(struct ip6_hdr);
#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
		if(unlikely(tot_len>length)){
			return DPI_ERROR_L3_TRUNCATED_PACKET;
		}
#endif

		/**
		 * At this point we are sure that tot_len<=length, so we set
		 * length=tot_len. In some cases indeed there may be an L2 padding
		 * at the end of the packet, so capture length (length) may be
		 * greater than the effective datagram length.
		 */
		length=tot_len;

		pkt_infos->src_addr_t.ipv6_srcaddr=ip6->ip6_src;
		pkt_infos->dst_addr_t.ipv6_dstaddr=ip6->ip6_dst;

		application_offset=sizeof(struct ip6_hdr);
		relative_offset=application_offset;
		next_header=ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	}else{
		return DPI_ERROR_WRONG_IPVERSION;
	}

	while(!stop){
		switch (next_header) {
			case IPPROTO_TCP:{ /* TCP */
				struct tcphdr* tcp=(struct tcphdr*)
						           (pkt+application_offset);
#ifdef DPI_ENABLE_L4_TRUNCATION_PROTECTION
				if(unlikely(application_offset+
						    sizeof(struct tcphdr)>length ||
						    application_offset+tcp->doff*4>length)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L4_TRUNCATED_PACKET;
				}
#endif
				pkt_infos->srcport=tcp->source;
				pkt_infos->dstport=tcp->dest;
				pkt_infos->l4offset=application_offset;
				application_offset+=(tcp->doff*4);
				stop=1;
				}
				break;
			case IPPROTO_UDP:{ /* UDP */
				struct udphdr* udp=(struct udphdr*)
						           (pkt+application_offset);
#ifdef DPI_ENABLE_L4_TRUNCATION_PROTECTION
				if(unlikely(application_offset+
						    sizeof(struct udphdr)>length ||
						           application_offset+
						           ntohs(udp->len)>length)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L4_TRUNCATED_PACKET;
				}
#endif
				pkt_infos->srcport=udp->source;
				pkt_infos->dstport=udp->dest;
				pkt_infos->l4offset=application_offset;
				application_offset+=8;
				stop=1;
				}
				break;
			case IPPROTO_HOPOPTS:{ /* Hop by hop options */
#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
				if(unlikely(application_offset+
						    sizeof(struct ip6_hbh)>length)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L3_TRUNCATED_PACKET;
				}
#endif
				if(likely(version==6)){
					struct ip6_hbh* hbh_hdr=(struct ip6_hbh*)
							                (pkt+application_offset);
					tmp=(8+hbh_hdr->ip6h_len*8);
					application_offset+=tmp;
					relative_offset+=tmp;
					next_header=hbh_hdr->ip6h_nxt;
				}else{
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
				}
				}
				break;
			case IPPROTO_DSTOPTS:{ /* Destination options */
#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
				if(unlikely(application_offset+
						    sizeof(struct ip6_dest)>length)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L3_TRUNCATED_PACKET;
				}
#endif
				if(likely(version==6)){
					struct ip6_dest* dst_hdr=(struct ip6_dest*)
							                 (pkt+application_offset);
					tmp=(8+dst_hdr->ip6d_len*8);
					application_offset+=tmp;
					relative_offset+=tmp;
					next_header=dst_hdr->ip6d_nxt;
				}else{
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
				}
				}
				break;
			case IPPROTO_ROUTING:{ /* Routing header */
#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
				if(unlikely(application_offset+sizeof(struct ip6_rthdr)>length)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L3_TRUNCATED_PACKET;
				}
#endif
				if(likely(version==6)){
					struct ip6_rthdr* rt_hdr=(struct ip6_rthdr*)
							                 (pkt+application_offset);
					tmp=(8+rt_hdr->ip6r_len*8);
					application_offset+=tmp;
					relative_offset+=tmp;
					next_header=rt_hdr->ip6r_nxt;
				}else{
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
				}
				}
				break;
			case IPPROTO_FRAGMENT:{ /* Fragment header */
#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
				if(unlikely(application_offset+
						    sizeof(struct ip6_frag)>length)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L3_TRUNCATED_PACKET;
				}
#endif
				if(likely(version==6)){
					if(state->ipv6_frag_state){
						struct ip6_frag* frg_hdr=(struct ip6_frag*)
								                 (pkt+application_offset);
						u_int16_t offset=((frg_hdr->ip6f_offlg &
								           IP6F_OFF_MASK)>>3)*8;
						u_int8_t more_fragments=((frg_hdr->ip6f_offlg &
								                  IP6F_MORE_FRAG))?1:0;
						offset=ntohs(offset);
						u_int32_t fragment_size=ntohs(
								ip6->ip6_ctlun.ip6_un1.ip6_un1_plen)+
								sizeof(struct ip6_hdr)-relative_offset-
								sizeof(struct ip6_frag);

						/**
						 * If this fragment has been obtained from a
						 * defragmentation (e.g. tunneling), then delete
						 * it after that the defragmentation support has
						 * copied it.
						 */
						unsigned char* to_delete=NULL;
						if(pkt!=p_pkt){
							to_delete=pkt;
						}

						/*
						 * For our purposes, from the unfragmentable part
						 * we need only the IPv6 header, any other
						 * optional header can be discarded, for this
						 * reason we copy only the IPv6 header bytes.
						 */
						pkt=dpi_reordering_manage_ipv6_fragment(
								state->ipv6_frag_state,
								(unsigned char*) ip6,
								sizeof(struct ip6_hdr),
								((unsigned char*) ip6)+
								    relative_offset+
								    sizeof(struct ip6_frag),
								fragment_size, offset, more_fragments,
								frg_hdr->ip6f_ident, frg_hdr->ip6f_nxt,
								current_time, tid);

						if(to_delete) free(to_delete);

						if(pkt==NULL){
							return DPI_STATUS_IP_FRAGMENT;
						}

						to_return=DPI_STATUS_IP_LAST_FRAGMENT;
						next_header=IPPROTO_IPV6;
						length=((struct ip6_hdr*) (pkt))->
								ip6_ctlun.ip6_un1.ip6_un1_plen+
								sizeof(struct ip6_hdr);
						/**
						 * Force the next iteration to analyze the
						 * reassembled IPv6 packet.
						 **/
						application_offset=relative_offset=0;
					}else{
						return DPI_STATUS_IP_FRAGMENT;
					}
				}else{
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
				}
				}
				break;
			case IPPROTO_IPV6: /** 6in4 and 6in6 tunneling **/
				/** The real packet is now ipv6. **/
				version=6;
				ip6=(struct ip6_hdr*) (pkt+application_offset);
#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
				if(unlikely(ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen)+
						    sizeof(struct ip6_hdr)>length-
						    application_offset)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L3_TRUNCATED_PACKET;
				}
#endif

				pkt_infos->src_addr_t.ipv6_srcaddr=ip6->ip6_src;
				pkt_infos->dst_addr_t.ipv6_dstaddr=ip6->ip6_dst;

				application_offset+=sizeof(struct ip6_hdr);
				relative_offset=sizeof(struct ip6_hdr);
				next_header=ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
				break;
			case 4: /* 4in4 and 4in6 tunneling */
				/** The real packet is now ipv4. **/
				version=4;
				ip4=(struct iphdr*) (pkt+application_offset);
#ifdef DPI_ENABLE_L3_TRUNCATION_PROTECTION
				if(unlikely(application_offset+
						    sizeof(struct iphdr)>length ||
						    application_offset+((ip4->ihl)*4)>length ||
						    application_offset+
						    ntohs(ip4->tot_len)>length)){
					if(unlikely(pkt!=p_pkt)) free(pkt);
					return DPI_ERROR_L3_TRUNCATED_PACKET;
				}
#endif
				pkt_infos->src_addr_t.ipv4_srcaddr=ip4->saddr;
				pkt_infos->dst_addr_t.ipv4_dstaddr=ip4->daddr;
				next_header=ip4->protocol;
				tmp=(ip4->ihl)*4;
				application_offset+=tmp;
				relative_offset=tmp;
				break;
			default:
				stop=1;
				pkt_infos->l4offset=application_offset;
				break;

			}
	}

    pkt_infos->l4prot=next_header;
#ifdef DPI_ENABLE_L4_TRUNCATION_PROTECTION
	if(unlikely(application_offset>length)){
		if(unlikely(pkt!=p_pkt)) free(pkt);
		return DPI_ERROR_L4_TRUNCATED_PACKET;
	}
#endif
	pkt_infos->processing_time=current_time;
	pkt_infos->pkt=pkt;
	pkt_infos->l7offset=application_offset;
	pkt_infos->data_length= length-application_offset;
	pkt_infos->ip_version=version;
	return to_return;
}

int8_t dpi_parse_L3_L4_headers(dpi_library_state_t *state,
		                       const unsigned char* p_pkt,
		                       u_int32_t p_length,
		                       dpi_pkt_infos_t *pkt_infos,
		                       u_int32_t current_time){
	/**
	 * We can pass any thread id, indeed in this case we don't
	 * need lock synchronization.
	 **/
	return mc_dpi_extract_packet_infos(state, p_pkt, p_length, pkt_infos,
			                           current_time, 0);
}


/*
 * Try to detect the application protocol. Before calling it, a check on
 * L4 protocol should be done and the function should be called only if
 * the packet is TCP or UDP.
 * @param   state The pointer to the library state.
 * @param   pkt_infos The pointer to the packet infos.
 * @return  The status of the operation. It gives additional informations
 *          about the processing of the request. If lesser than 0, an
 *          error occurred. dpi_get_error_msg() can be used to get a
 *          textual representation of the error. If greater or equal
 *          than 0 then it should not be interpreted as an error but
 *          simply gives additional informations (e.g. if the packet was
 *          IP fragmented, if it was out of order in the TCP stream, if is
 *          a segment of a larger application request, etc..).
 *          dpi_get_status_msg() can be used to get a textual
 *          representation of the status. Status and error codes are
 *          defined above in this header file.
 *
 *          The status is DPI_STATUS_IP_FRAGMENT if the datagram is a
 *          fragment. In this case, if IP fragmentation support is
 *          enabled, the library copied the content of the datagram, so if
 *          the user wants, he can release the resources used to store the
 *          datagram.
 *
 *          The status is DPI_STATUS_IP_LAST_FRAGMENT if the received
 *          datagram allows the library to reconstruct a fragmented
 *          datagram. In this case, pkt_infos->pkt will contain a pointer
 *          to the recomposed datagram. This pointer will be different
 *          from p_pkt. The user should free() this pointer when it is no
 *          more needed (e.g. after calling
 *          dpi_state*_get_app_protocol(..)).
 */
dpi_identification_result_t dpi_stateful_get_app_protocol(
		         dpi_library_state_t *state, dpi_pkt_infos_t* pkt_infos){
	dpi_identification_result_t r;
	r.status=DPI_STATUS_OK;

	dpi_flow_infos_t* flow_infos=NULL;
	ipv4_flow_t* ipv4_flow=NULL;
	ipv6_flow_t* ipv6_flow=NULL;

	if(pkt_infos->ip_version==DPI_IP_VERSION_4){
		ipv4_flow=dpi_flow_table_find_or_create_flow_v4(state, pkt_infos);
		if(ipv4_flow)
			flow_infos=&(ipv4_flow->infos);
	}else{
		ipv6_flow=dpi_flow_table_find_or_create_flow_v6(state, pkt_infos);
		if(ipv6_flow)
			flow_infos=&(ipv6_flow->infos);
	}

	if(unlikely(flow_infos==NULL)){
		r.status=DPI_ERROR_MAX_FLOWS;
		return r;
	}

	r=dpi_stateless_get_app_protocol(state, flow_infos, pkt_infos);

	if(r.status==DPI_STATUS_TCP_CONNECTION_TERMINATED){
		if(ipv4_flow!=NULL){
			dpi_flow_table_delete_flow_v4(state->db4,
					                      state->flow_cleaner_callback,
					                      ipv4_flow);
		}else{
			dpi_flow_table_delete_flow_v6(state->db6,
					                      state->flow_cleaner_callback,
					                      ipv6_flow);
		}
	}
	return r;
}



/**
 * Initialize the flow informations passed as argument.
 * @param state       A pointer to the state of the library.
 * @param flow_infos  The informations that will be initialized by
 *                    the library.
 * @param l4prot      The transport protocol identifier.
 */
void dpi_init_flow_infos(
		       dpi_library_state_t* state,
		       dpi_flow_infos_t *flow_infos,
		       u_int8_t l4prot){
	dpi_l7_prot_id i;
	if(l4prot==IPPROTO_TCP){
		for(i=0; i<BITNSLOTS(DPI_NUM_TCP_PROTOCOLS); i++){
			flow_infos->possible_matching_protocols_t.tcp[i]=
					      state->tcp_protocols_to_inspect[i];
		}
		flow_infos->possible_protocols=state->tcp_active_protocols;
	}else{
		for(i=0; i<BITNSLOTS(DPI_NUM_UDP_PROTOCOLS); i++){
			flow_infos->possible_matching_protocols_t.udp[i]=
					      state->udp_protocols_to_inspect[i];
		}
		flow_infos->possible_protocols=state->udp_active_protocols;
	}
	flow_infos->l7prot=DPI_PROTOCOL_NOT_DETERMINED;
	flow_infos->trials=0;
	flow_infos->tcp_reordering_enabled=state->tcp_reordering_enabled;
	bzero(&(flow_infos->tracking), sizeof(dpi_tracking_informations_t));
}


/*
 * Try to detect the application protocol. Before calling it, a check on
 * L4 protocol should be done and the function should be called only if
 * the packet is TCP or UDP. It should be used if the application already
 * has the concept of 'flow'. In this case the first time that the flow is
 * passed to the call, it must be initialized with
 * dpi_init_flow_infos(...).
 * @param   state The pointer to the library state.
 * @param   flow The informations about the flow. They must be kept by the
 *               user.
 * @param   pkt_infos The pointer to the packet infos.
 * @return  The status of the operation. It gives additional informations
 *          about the processing of the request. If lesser than 0, an error
 *          occurred. dpi_get_error_msg() can be used to get a textual
 *          representation of the error. If greater or equal than 0 then
 *          it should not be interpreted as an error but simply gives
 *          additional informations (e.g. if the packet was IP fragmented,
 *          if it was out of order in the TCP stream, if is a segment of
 *          a larger application request, etc..). dpi_get_status_msg()
 *          can be used to get a textual representation of the status.
 *          Status and error codes are defined above in this header file.
 *
 *          The status is DPI_STATUS_IP_FRAGMENT if the datagram is a
 *          fragment. In this case, if IP fragmentation support is
 *          enabled, the library copied the content of the datagram, so if
 *          the user wants, he can release the resources used to store the
 *          datagram.
 *
 *          The status is DPI_STATUS_IP_LAST_FRAGMENT if the received
 *          datagram allows the library to reconstruct a fragmented
 *          datagram. In this case, pkt_infos->pkt will contain a pointer
 *          to the recomposed datagram. This pointer will be different
 *          from p_pkt. The user should free() this pointer when it is no
 *          more needed (e.g. after calling
 *          dpi_state*_get_app_protocol(..)).
 */
dpi_identification_result_t dpi_stateless_get_app_protocol(
		       dpi_library_state_t *state,
		       dpi_flow_infos_t *flow,
		       dpi_pkt_infos_t *pkt_infos){
	dpi_identification_result_t r;
	r.status=DPI_STATUS_OK;
	r.protocol.l4prot=pkt_infos->l4prot;
	r.user_flow_data=(flow->tracking.flow_specific_user_data);
	dpi_l7_prot_id i;

	u_int8_t check_result=DPI_PROTOCOL_NO_MATCHES;
	dpi_l7_prot_id num_protocols;
	const dpi_l7_prot_id* well_known_ports;
	char *active_protocols_mask;
	const unsigned char* app_data=pkt_infos->pkt+pkt_infos->l7offset;
	u_int32_t data_length=pkt_infos->data_length;
	dpi_inspector_callback const *inspectors;
	dpi_tcp_reordering_reordered_segment_t seg;
	seg.status=DPI_TCP_REORDERING_STATUS_IN_ORDER;
	seg.data=NULL;
	seg.connection_terminated=0;

	if(flow->l7prot<DPI_PROTOCOL_NOT_DETERMINED){
		r.protocol.l7prot=flow->l7prot;
		if(pkt_infos->l4prot==IPPROTO_TCP){

			if(flow->tcp_reordering_enabled){
				seg=dpi_reordering_tcp_track_connection(
						    pkt_infos, &(flow->tracking));

				if(seg.status==
						 DPI_TCP_REORDERING_STATUS_OUT_OF_ORDER){
					r.status=DPI_STATUS_TCP_OUT_OF_ORDER;
					return r;
				}else if(seg.status==
						 DPI_TCP_REORDERING_STATUS_REBUILT){
					app_data=seg.data;
					data_length=seg.data_length;
				}
			}else{
				seg.connection_terminated=
						dpi_reordering_tcp_track_connection_light(
								     pkt_infos, &(flow->tracking));
			}

			if(BITTEST(state->tcp_active_callbacks, flow->l7prot) &&
					   data_length!=0){
				(*(tcp_callbacks_manager[flow->l7prot]))(
						 state, pkt_infos, app_data,
						 data_length, &(flow->tracking));
			}

			if(seg.status==DPI_TCP_REORDERING_STATUS_REBUILT){
				free(seg.data);
			}

		}else if(pkt_infos->l4prot==IPPROTO_UDP &&
				BITTEST(state->udp_active_callbacks, flow->l7prot)){
			(*(udp_callbacks_manager[flow->l7prot]))(
					     state, pkt_infos, app_data,
					     data_length, &(flow->tracking));
		}

		if(seg.connection_terminated){
			r.status=DPI_STATUS_TCP_CONNECTION_TERMINATED;
		}
		return r;
	}else if(flow->l7prot==DPI_PROTOCOL_NOT_DETERMINED){
		if(pkt_infos->l4prot==IPPROTO_TCP &&
		   state->tcp_active_protocols>0){
			active_protocols_mask=flow->possible_matching_protocols_t.tcp;
			inspectors=tcp_inspectors;
			num_protocols=DPI_NUM_TCP_PROTOCOLS;
			well_known_ports=dpi_well_known_ports_association_tcp;
			if(flow->tcp_reordering_enabled){
				seg=dpi_reordering_tcp_track_connection(
						  pkt_infos, &(flow->tracking));

				if(seg.status==DPI_TCP_REORDERING_STATUS_OUT_OF_ORDER){
					r.status=DPI_STATUS_TCP_OUT_OF_ORDER;
					r.protocol.l7prot=DPI_PROTOCOL_UNKNOWN;
					return r;
				}else if(seg.status==DPI_TCP_REORDERING_STATUS_REBUILT){
					app_data=seg.data;
					data_length=seg.data_length;
				}
			}else{
				if(dpi_reordering_tcp_track_connection_light(
						  pkt_infos, &(flow->tracking)))
					r.status=DPI_STATUS_TCP_CONNECTION_TERMINATED;
			}
		}else if(pkt_infos->l4prot==IPPROTO_UDP &&
				 state->udp_active_protocols>0){
			active_protocols_mask=flow->possible_matching_protocols_t.udp;
			inspectors=udp_inspectors;
			num_protocols=DPI_NUM_UDP_PROTOCOLS;
			well_known_ports=dpi_well_known_ports_association_udp;
		}else{
			return r;
		}

		/**
		 * If we have no payload we don't do anything. We already
		 * invoked the TCP reordering to update the connection state.
		 */
		if(data_length==0){
			r.protocol.l7prot=flow->l7prot;
			return r;
		}

		dpi_l7_prot_id first_protocol_to_check;
		dpi_l7_prot_id checked_protocols=0;

		if((first_protocol_to_check=well_known_ports[pkt_infos->srcport])
			==DPI_PROTOCOL_UNKNOWN &&
			(first_protocol_to_check=well_known_ports[pkt_infos->dstport])
			==DPI_PROTOCOL_UNKNOWN){
			first_protocol_to_check=0;
		}

		for(i=first_protocol_to_check; checked_protocols<num_protocols;
		    i=(i+1)%num_protocols, ++checked_protocols){
			if(BITTEST(active_protocols_mask, i)){
				check_result=(*(inspectors[i]))(state, pkt_infos,
						                        app_data, data_length,
						                        &(flow->tracking));
				if(check_result==DPI_PROTOCOL_MATCHES){
					flow->l7prot=i;
					r.protocol.l7prot=flow->l7prot;

					if(seg.status==DPI_TCP_REORDERING_STATUS_REBUILT){
						free(seg.data);
					}

					if(seg.connection_terminated){
						r.status=DPI_STATUS_TCP_CONNECTION_TERMINATED;
					}

					return r;
				}else if(check_result==DPI_PROTOCOL_NO_MATCHES){
					BITCLEAR(active_protocols_mask, i);
					--(flow->possible_protocols);
				}
			}
		}

		/**
		 * If all the protocols don't match or if we still have
		 * ambiguity after the maximum number of trials, then the
		 * library was unable to identify the protocol.
		 **/
		if(flow->possible_protocols==0 ||
		   (state->max_trials!=0 &&
		    unlikely(++flow->trials==state->max_trials))){
			flow->l7prot=DPI_PROTOCOL_UNKNOWN;
		}

	}

	r.protocol.l7prot=flow->l7prot;

	if(seg.status==DPI_TCP_REORDERING_STATUS_REBUILT){
		free(seg.data);
	}

	if(seg.connection_terminated){
		r.status=DPI_STATUS_TCP_CONNECTION_TERMINATED;
	}
	return r;
}

/**
 * Try to guess the protocol looking only at source/destination ports.
 * This could be erroneous because sometimes protocols
 * run over ports which are not their well-known ports.
 * @param    pkt_infos The pointer to the packet infos.
 * @return   Returns the possible matching protocol.
 */
dpi_protocol_t dpi_guess_protocol(dpi_pkt_infos_t* pkt_infos){
	dpi_protocol_t r;
	r.l4prot=pkt_infos->l4prot;
	if(pkt_infos->l4prot==IPPROTO_TCP){
		r.l7prot=dpi_well_known_ports_association_tcp[pkt_infos->srcport];
		if(r.l7prot==DPI_PROTOCOL_UNKNOWN)
			r.l7prot=dpi_well_known_ports_association_tcp[pkt_infos->dstport];
	}else if(pkt_infos->l4prot==IPPROTO_UDP){
		r.l7prot=dpi_well_known_ports_association_udp[pkt_infos->srcport];
		if(r.l7prot==DPI_PROTOCOL_UNKNOWN)
			r.l7prot=dpi_well_known_ports_association_udp[pkt_infos->dstport];
	}else{
		r.l7prot=DPI_PROTOCOL_UNKNOWN;
	}
	return r;
}


/**
 * Get the string representing the error message associated to the
 * specified error_code.
 * @param   error_code The error code.
 * @return  The error message.
 */
const char* const dpi_get_error_msg(int8_t error_code){
	switch(error_code){
		case DPI_ERROR_WRONG_IPVERSION:
			return "ERROR: The packet is neither IPv4 nor IPv6.";
		case DPI_ERROR_IPSEC_NOTSUPPORTED:
			return "ERROR: The packet is encrypted using IPSEC. "
				   "IPSEC is not supported.";
		case DPI_ERROR_L3_TRUNCATED_PACKET:
			return "ERROR: The L3 packet is truncated or corrupted.";
		case DPI_ERROR_L4_TRUNCATED_PACKET:
			return "ERROR: The L4 packet is truncated or corrupted.";
		case DPI_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED:
			return "ERROR: The transport protocol is not supported.";
		case DPI_ERROR_MAX_FLOWS:
			return "ERROR: The maximum number of active flows has been"
				   " reached.";
		default:
			return "ERROR: Not existing error code.";
	}
}

/**
 * Get the string representing the status message associated to the
 * specified status_code.
 * @param   status_code The status code.
 * @return  The status message.
 */
const char* const dpi_get_status_msg(int8_t status_code){
	switch(status_code){
		case DPI_STATUS_OK:
			return "STATUS: Everything is ok.";
		case DPI_STATUS_IP_FRAGMENT:
			return "STATUS: The received IP datagram is a fragment of a "
				   " bigger datagram.";
		case DPI_STATUS_IP_LAST_FRAGMENT:
			return "STATUS: The received IP datagram is the last fragment"
				   " of a bigger datagram. The original datagram has been"
				   " recomposed.";
		case DPI_STATUS_TCP_OUT_OF_ORDER:
			return "STATUS: The received TCP segment is out of order in "
				   " its stream. It will be buffered waiting for in order"
				   " segments.";
		case DPI_STATUS_TCP_CONNECTION_TERMINATED:
			return "STATUS: The TCP connection is terminated.";
		default:
			return "STATUS: Not existing status code.";
	}
}

/**
 * Returns a string corresponding to the given protocol.
 * @param   protocol The protocol identifier.
 * @return  A string representation of the given protocol.
 */
const char* const dpi_get_protocol_name(dpi_protocol_t protocol){
	if(protocol.l4prot==IPPROTO_TCP){
		switch(protocol.l7prot){
			case DPI_PROTOCOL_TCP_BGP:
				return "BGP";
			case DPI_PROTOCOL_TCP_HTTP:
				return "HTTP";
			case DPI_PROTOCOL_TCP_SMTP:
				return "SMTP";
			case DPI_PROTOCOL_TCP_POP3:
				return "POP3";
			case DPI_PROTOCOL_TCP_SSL:
				return "SSL";
			default:
				return "Unknown";
		}
	}else if(protocol.l4prot==IPPROTO_UDP){
		switch(protocol.l7prot){
			case DPI_PROTOCOL_UDP_DHCP:
				return "DHCP";
			case DPI_PROTOCOL_UDP_DHCPv6:
				return "DHCPv6";
			case DPI_PROTOCOL_UDP_DNS:
				return "DNS";
			case DPI_PROTOCOL_UDP_MDNS:
				return "MDNS";
			case DPI_PROTOCOL_UDP_NTP:
				return "NTP";
			case DPI_PROTOCOL_UDP_SIP:
				return "SIP";
			case DPI_PROTOCOL_UDP_RTP:
				return "RTP";
			case DPI_PROTOCOL_UDP_SKYPE:
				return "SKYPE";
			default:
				return "Unknown";
		}
	}else
		return "Unknown";
}

/**
 * Sets the callback that will be called when a flow expires.
 * (Valid only if stateful API is used).
 * @param state     A pointer to the state of the library.
 * @param cleaner   The callback used to clear the user state.
 *
 * @return DPI_STATE_UPDATE_SUCCESS if succeeded,
 *         DPI_STATE_UPDATE_FAILURE otherwise.
 */
u_int8_t dpi_set_flow_cleaner_callback(
		     dpi_library_state_t* state,
		     dpi_flow_cleaner_callback* cleaner){
	state->flow_cleaner_callback=cleaner;
	return DPI_STATE_UPDATE_SUCCESS;
}
