/*
 * mc_dpi_api.h
 *
 * Created on: 12/11/2012
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
 * ====================================================================
 */

#ifndef MP_DPI_API_H_
#define MP_DPI_API_H_

#include "api.h"

#ifdef ENABLE_RECONFIGURATION
#include <src/manager.hpp>
#endif

typedef struct mc_dpi_library_state mc_dpi_library_state_t;

typedef struct mc_dpi_processing_result{
	void* user_pointer;
	dpi_identification_result_t result;
}mc_dpi_processing_result_t;

typedef struct mc_dpi_packet_reading_result{
	const unsigned char* pkt;
	u_int32_t length;
	u_int32_t current_time;
	void* user_pointer;
}mc_dpi_packet_reading_result_t;

typedef enum analysis_results{
     MC_DPI_PARALLELISM_FORM_ONE_FARM=0
    ,MC_DPI_PARALLELISM_FORM_DOUBLE_FARM
    ,MC_DPI_PARALLELISM_FORM_POSSIBLE_L3_L4_BOTTLENECK
}analysis_results;

/**
 * @struct mc_dpi_parallelism_details_t
 * @brief Represents some details that can be specified by the user
 * during initializations.
 *
 * @var available processors The maximum number of coress that can be
 *                           used by the framework.
 * @var mapping An array of cores identifiers on which the framework
 *              can be mapped. If NULL, a linear mapping will be
 *              applied (i.e. [0,1,2,...]).
 * @var parallelism_form MC_DPI_PARELLELISM_FORM_DOUBLE_FARM or
 *                       MC_DPI_PARALLELISM_FORM_ONE_FARM. By default it
 *                       is equal to MC_DPI_PARALLELISM_FORM_ONE_FARM.
 * @var double_farm_num_L3_workers   If parallelism_form==
 *                                   MC_DPI_PARELLELISM_FORM_DOUBLE_FARM,
 *                                   it represents the number of workers
 *                                   to activate for the first farm. It
 *                                   must be different from 0.
 * @var double_farm_num_L7_workers   If parallelism_form==
 *                                   MC_DPI_PARELLELISM_FORM_DOUBLE_FARM,
 *                                   it represents the number of workers
 *                                   to activate for the second farm. It
 *                                   must be different from 0.
 */
typedef struct mc_dpi_parallelism_details{
	/** Mapping informations. **/
	u_int16_t available_processors;
	u_int16_t* mapping;
	/** User manual specification of parallelism form. **/
	analysis_results parallelism_form;
	u_int16_t double_farm_num_L3_workers;
	u_int16_t double_farm_num_L7_workers;
}mc_dpi_parallelism_details_t;

/**
 * This function will be called by the library (active mode only) to read
 * a packet from the network.
 * @param callback_data   A pointer to user specified data (e.g.
 *                        network socket).
 * @return                The packet read. If the pkt field is NULL, then
 *                        there are no more data to read and the library
 *                        will terminate. The user must never try to
 *                        modify the state after that he returned
 *                        pkt=NULL, otherwise the behaviour is not
 *                        defined.
 */
typedef mc_dpi_packet_reading_result_t(mc_dpi_packet_reading_callback)
			(void* callback_data);

/**
 * This function will be called by the library (active mode only) to
 * process the result of the protocol identification.
 * @param processing_result   A pointer to the result of the library
 *                            processing.
 * @param callback_data       A pointer to user specified data (e.g.
 *                            network socket).
 */
typedef void(mc_dpi_processing_result_callback)
			(mc_dpi_processing_result_t* processing_result,
			 void* callback_data);

/**
 * Initializes the library and sets the parallelism degree according to
 * the cost model obtained from the parameters that the user specifies.
 * If not specified otherwise after the initialization, the library will
 * consider all the protocols active.
 *
 * @param size_v4 Size of the array of pointers used to build the database
 *                for v4 flows.
 * @param size_v6 Size of the array of pointers used to build the database
 *                for v6 flows.
 * @param max_active_v4_flows The maximum number of IPv4 flows which can
 *                            be active at any time. After reaching this
 *                            threshold, new flows will not be created.
 * @param max_active_v6_flows The maximum number of IPv6 flows which can
 *                            be active at any time. After reaching this
 *                            threshold, new flows will not be created.
 * @param parallelism_details Details about the parallelism form. Must be
 *                            zeroed and then filled by the user.
 * @return A pointer to the state of the library.
 */
mc_dpi_library_state_t* mc_dpi_init_stateful(
		u_int32_t size_v4, u_int32_t size_v6,
		u_int32_t max_active_v4_flows,
		u_int32_t max_active_v6_flows,
		mc_dpi_parallelism_details_t parallelism_details);



/**
 * Sets the reading and processing callbacks. It can be done only after
 * that the state has been initialized and before calling run().
 *
 * @param state                 A pointer to the state of the library.
 * @param reading_callback      A pointer to the reading callback. It must
 *                              be different from NULL.
 * @param processing_callback   A pointer to the processing callback. It
 *                              must be different from NULL.
 * @param user_data             A pointer to the user data to be passed to
 *                              the callbacks.
 */
void mc_dpi_set_read_and_process_callbacks(
		mc_dpi_library_state_t* state,
		mc_dpi_packet_reading_callback* reading_callback,
		mc_dpi_processing_result_callback* processing_callback,
                void* user_data);

#ifdef ENABLE_RECONFIGURATION
/**
 * Sets the reconfiguration parameters.
 * @param state A pointer to the state of the library.
 * @param p The reconfiguration parameters.
 */
void mc_dpi_set_reconf_parameters(mc_dpi_library_state_t* state, nornir::Parameters* p);
#endif

/**
 * Starts the library.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_run(mc_dpi_library_state_t* state);

/**
 * Wait the end of the data processing.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_wait_end(mc_dpi_library_state_t* state);

/**
 * Prints execution's statistics.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_print_stats(mc_dpi_library_state_t* state);

/**
 * Terminates the library.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_terminate(mc_dpi_library_state_t *state);


/*************************************************/
/*          Status change API calls              */
/*************************************************/

/**
 * Sets the maximum number of times that the library tries to guess the
 * protocol. During the flow protocol identification, after this number
 * of trials, in the case in which it cannot decide between two or more
 * protocols, one of them will be chosen, otherwise DPI_PROTOCOL_UNKNOWN
 * will be returned.
 * @param state       A pointer to the state of the library.
 * @param max_trials  The maximum number of trials.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_set_max_trials(mc_dpi_library_state_t *state,
		                       u_int16_t max_trials);


/**
 * Enable IPv4 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv4
 *                     fragments informations.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *          updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv4_fragmentation_enable(mc_dpi_library_state_t *state,
		                                  u_int16_t table_size);

/**
 * Enable IPv6 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv6
 *                     fragments informations.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv6_fragmentation_enable(mc_dpi_library_state_t *state,
		                                  u_int16_t table_size);

/**
 * Sets the amount of memory that a single host can use for IPv4
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                 any IPv4 host can use.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv4_fragmentation_set_per_host_memory_limit(
		mc_dpi_library_state_t *state,
		u_int32_t per_host_memory_limit);

/**
 * Sets the amount of memory that a single host can use for IPv6
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                any IPv6 host can use.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv6_fragmentation_set_per_host_memory_limit(
		mc_dpi_library_state_t *state,
		u_int32_t per_host_memory_limit);

/**
 * Sets the total amount of memory that can be used for IPv4
 * defragmentation.
 * If fragmentation is disabled and then enabled, this information
 * must be passed again.
 * Otherwise default value will be used.
 * @param state               A pointer to the state of the library
 * @param totel_memory_limit  The maximum amount of memory that can
 *                             be used for IPv4 defragmentation.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv4_fragmentation_set_total_memory_limit(
		mc_dpi_library_state_t *state,
		u_int32_t total_memory_limit);

/**
 * Sets the total amount of memory that can be used for
 * IPv6 defragmentation.
 * If fragmentation is disabled and then enabled, this information
 * must be passed again.
 * Otherwise default value will be used.
 * @param state               A pointer to the state of the library
 * @param totel_memory_limit  The maximum amount of memory that can
 *                            be used for IPv6 defragmentation.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv6_fragmentation_set_total_memory_limit(
		mc_dpi_library_state_t *state,
		u_int32_t total_memory_limit);

/**
 * Sets the maximum time (in seconds) that can be spent to
 * reassembly an IPv4 fragmented datagram.
 * Is the maximum time gap between the first and last fragments
 * of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been
 *         successfully updated. DPI_STATE_UPDATE_FAILURE if the
 *         state has not been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv4_fragmentation_set_reassembly_timeout(
		mc_dpi_library_state_t *state,
		u_int8_t timeout_seconds);

/**
 * Sets the maximum time (in seconds) that can be spent to reassembly
 * an IPv6 fragmented datagram.
 * Is the maximum time gap between the first and last fragments of
 * the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv6_fragmentation_set_reassembly_timeout(
		mc_dpi_library_state_t *state,
		u_int8_t timeout_seconds);

/**
 * Disable IPv4 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been
 *         successfully updated. DPI_STATE_UPDATE_FAILURE if the
 *         state has not been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv4_fragmentation_disable(mc_dpi_library_state_t *state);

/**
 * Disable IPv6 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv6_fragmentation_disable(mc_dpi_library_state_t *state);



/**
 * If enabled, the library will reorder out of order TCP packets
 * (enabled by default).
 * @param state  A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been
 *         successfully updated. DPI_STATE_UPDATE_FAILURE if the state
 *         has not been changed because a problem happened.
 */
u_int8_t mc_dpi_tcp_reordering_enable(mc_dpi_library_state_t* state);

/**
 * If it is called, the library will not reorder out of order TCP packets.
 * Out-of-order segments will be delivered to the inspector as they
 * arrive. This means that the inspector may not be able to identify
 * the application protocol. Moreover, if there are callbacks saved
 * for TCP based protocols, if TCP reordering is disabled, the
 * extracted informations could be erroneous or incomplete.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_tcp_reordering_disable(mc_dpi_library_state_t* state);


/**
 * Enable a protocol inspector.
 * @param state         A pointer to the state of the library.
 * @param protocol      The protocol to enable.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_set_protocol(mc_dpi_library_state_t *state,
		                     dpi_protocol_t protocol);

/**
 * Disable a protocol inspector.
 * @param state       A pointer to the state of the library.
 * @param protocol    The protocol to disable.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_delete_protocol(mc_dpi_library_state_t *state,
		                        dpi_protocol_t protocol);

/**
 * Enable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_inspect_all(mc_dpi_library_state_t *state);

/**
 * Disable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_inspect_nothing(mc_dpi_library_state_t *state);


/**
 * Sets the callback that will be called when a flow expires.
 * (Valid only if stateful API is used).
 * @param state     A pointer to the state of the library.
 * @param cleaner   The callback used to clear the user state.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been
 *         successfully updated. DPI_STATE_UPDATE_FAILURE if
 *         the state has not been changed because a problem
 *         happened.
 */
u_int8_t mc_dpi_set_flow_cleaner_callback(
		mc_dpi_library_state_t* state,
		dpi_flow_cleaner_callback* cleaner);

/**
 * Sets callbacks informations. When a protocol is identified the
 * default behavior is to not inspect the packets belonging to that
 * flow anymore and keep simply returning the same protocol identifier.
 *
 * If a callback is enabled for a certain protocol, then we keep
 * inspecting all the new flows with that protocol in order to
 * invoke the callbacks specified by the user on the various parts
 * of the message. Moreover, if the application protocol uses TCP,
 * then we have the additional cost of TCP reordering for all the
 * segments. Is highly recommended to enable TCP reordering if it is
 * not already enabled (remember that is enabled by default).
 * Otherwise the informations extracted could be erroneous/incomplete.
 *
 * The pointers to the data passed to the callbacks are valid only for
 * the duration of the callback.
 *
 * @param state       A pointer to the state of the library.
 * @param callbacks   A pointer to HTTP callbacks.
 * @param user_data   A pointer to global user HTTP data. This pointer
 *                    will be passed to any HTTP callback when it is
 *                    invoked.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 *
 **/
u_int8_t mc_dpi_http_activate_callbacks(
		mc_dpi_library_state_t* state,
		dpi_http_callbacks_t* callbacks,
		void* user_data);

/**
 * Remove the internal structure used to store callbacks informations.
 * user_data is not freed/modified.
 * @param state       A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_http_disable_callbacks(mc_dpi_library_state_t* state);


#endif /* MP_DPI_API_H_ */
