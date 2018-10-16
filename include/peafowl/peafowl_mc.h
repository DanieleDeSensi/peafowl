/*
 * peafowl_mc.h
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

#ifndef MP_PFWL_API_H_
#define MP_PFWL_API_H_

#include <peafowl/peafowl.h>

#ifdef ENABLE_RECONFIGURATION
#include <src/manager.hpp>
#endif

typedef struct mc_pfwl_state mc_pfwl_state_t;

typedef struct mc_pfwl_processing_result {
  void *user_pointer;
  pfwl_dissection_info_t result;
} mc_pfwl_processing_result_t;

typedef struct mc_pfwl_packet_reading_result {
  const unsigned char *pkt;
  uint32_t length;
  uint32_t current_time;
  void *user_pointer;
} mc_pfwl_packet_reading_result_t;

typedef enum analysis_results {
  MC_PFWL_PARALLELISM_FORM_ONE_FARM = 0,
  MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM,
  MC_PFWL_PARALLELISM_FORM_POSSIBLE_L3_L4_BOTTLENECK
} analysis_results;

/**
 * @struct mc_pfwl_parallelism_details_t
 * @brief Represents some details that can be specified by the user
 * during initializations.
 *
 * @var available processors The maximum number of coress that can be
 *                           used by the framework.
 * @var mapping An array of cores identifiers on which the framework
 *              can be mapped. If NULL, a linear mapping will be
 *              applied (i.e. [0,1,2,...]).
 * @var parallelism_form MC_PFWL_PARELLELISM_FORM_DOUBLE_FARM or
 *                       MC_PFWL_PARALLELISM_FORM_ONE_FARM. By default it
 *                       is equal to MC_PFWL_PARALLELISM_FORM_ONE_FARM.
 * @var double_farm_num_L3_workers   If parallelism_form==
 *                                   MC_PFWL_PARELLELISM_FORM_DOUBLE_FARM,
 *                                   it represents the number of workers
 *                                   to activate for the first farm. It
 *                                   must be different from 0.
 * @var double_farm_num_L7_workers   If parallelism_form==
 *                                   MC_PFWL_PARELLELISM_FORM_DOUBLE_FARM,
 *                                   it represents the number of workers
 *                                   to activate for the second farm. It
 *                                   must be different from 0.
 */
typedef struct mc_pfwl_parallelism_details {
  /** Mapping informations. **/
  uint16_t available_processors;
  uint16_t *mapping;
  /** User manual specification of parallelism form. **/
  analysis_results parallelism_form;
  uint16_t double_farm_num_L3_workers;
  uint16_t double_farm_num_L7_workers;
} mc_pfwl_parallelism_details_t;

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
typedef mc_pfwl_packet_reading_result_t(mc_pfwl_packet_reading_callback)(
    void *callback_data);

/**
 * This function will be called by the library (active mode only) to
 * process the result of the protocol identification.
 * @param processing_result   A pointer to the result of the library
 *                            processing.
 * @param callback_data       A pointer to user specified data (e.g.
 *                            network socket).
 */
typedef void(mc_pfwl_processing_result_callback)(
    mc_pfwl_processing_result_t *processing_result, void *callback_data);

/**
 * Initializes the library and sets the parallelism degree according to
 * the cost model obtained from the parameters that the user specifies.
 * If not specified otherwise after the initialization, the library will
 * consider all the protocols to be active.
 *
 * @param parallelism_details Details about the parallelism form. Must be
 *                            zeroed and then filled by the user.
 * @return A pointer to the state of the library.
 */
mc_pfwl_state_t *
mc_pfwl_init(mc_pfwl_parallelism_details_t parallelism_details);

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
void mc_pfwl_set_core_callbacks(
    mc_pfwl_state_t *state, mc_pfwl_packet_reading_callback *reading_callback,
    mc_pfwl_processing_result_callback *processing_callback, void *user_data);

#ifdef ENABLE_RECONFIGURATION
/**
 * Sets the reconfiguration parameters.
 * @param state A pointer to the state of the library.
 * @param p The reconfiguration parameters.
 */
void mc_pfwl_set_reconf_parameters(mc_pfwl_library_state_t *state,
                                   nornir::Parameters *p);
#endif

/**
 * Starts the library.
 * @param state A pointer to the state of the library.
 */
void mc_pfwl_run(mc_pfwl_state_t *state);

/**
 * Wait the end of the data processing.
 * @param state A pointer to the state of the library.
 */
void mc_pfwl_wait_end(mc_pfwl_state_t *state);

/**
 * Prints execution's statistics.
 * @param state A pointer to the state of the library.
 */
void mc_pfwl_print_stats(mc_pfwl_state_t *state);

/**
 * Terminates the library.
 * @param state A pointer to the state of the library.
 */
void mc_pfwl_terminate(mc_pfwl_state_t *state);

/*************************************************/
/*          Status change API calls              */
/*************************************************/
/**
 * @brief Sets the number of simultaneously active flows to be expected.
 * @param state A pointer to the state of the library.
 * @param flows_v4 The number of simultaneously active IPv4 flows.
 * @param flows_v6 The number of simultaneously active IPv6 flows.
 * @param strict If 1, when that number of active flows is reached,
 * an error will be returned (PFWL_ERROR_MAX_FLOWS) and new flows
 * will not be created. If 0, there will not be any limit to the number
 * of simultaneously active flows.
 * @return 0 if succeeded, 1 otherwise.
 */
uint8_t mc_pfwl_set_expected_flows(mc_pfwl_state_t *state, uint32_t flows_v4,
                                   uint32_t flows_v6, uint8_t strict);

/**
 * Sets the maximum number of times that the library tries to guess the
 * protocol. During the flow protocol identification, after this number
 * of trials, in the case in which it cannot decide between two or more
 * protocols, one of them will be chosen, otherwise PFWL_PROTOCOL_UNKNOWN
 * will be returned.
 * @param state       A pointer to the state of the library.
 * @param max_trials  The maximum number of trials.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_set_max_trials(mc_pfwl_state_t *state, uint16_t max_trials);

/**
 * Enable IPv4 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv4
 *                     fragments informations.
 *
 * @return 1 If the state has been successfully
 *          updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_ipv4_fragmentation_enable(mc_pfwl_state_t *state,
                                          uint16_t table_size);

/**
 * Enable IPv6 defragmentation.
 * @param state        A pointer to the library state.
 * @param table_size   The size of the table to be used to store IPv6
 *                     fragments informations.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_ipv6_fragmentation_enable(mc_pfwl_state_t *state,
                                          uint16_t table_size);

/**
 * Sets the amount of memory that a single host can use for IPv4
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                 any IPv4 host can use.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_ipv4_fragmentation_set_per_host_memory_limit(
    mc_pfwl_state_t *state, uint32_t per_host_memory_limit);

/**
 * Sets the amount of memory that a single host can use for IPv6
 * defragmentation.
 * @param state                   A pointer to the library state.
 * @param per_host_memory_limit   The maximum amount of memory that
 *                                any IPv6 host can use.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_ipv6_fragmentation_set_per_host_memory_limit(
    mc_pfwl_state_t *state, uint32_t per_host_memory_limit);

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
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t
mc_pfwl_ipv4_fragmentation_set_total_memory_limit(mc_pfwl_state_t *state,
                                                  uint32_t total_memory_limit);

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
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t
mc_pfwl_ipv6_fragmentation_set_total_memory_limit(mc_pfwl_state_t *state,
                                                  uint32_t total_memory_limit);

/**
 * Sets the maximum time (in seconds) that can be spent to
 * reassembly an IPv4 fragmented datagram.
 * Is the maximum time gap between the first and last fragments
 * of the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return 1 If the state has been
 *         successfully updated. 0 if the
 *         state has not been changed because a problem happened.
 */
uint8_t
mc_pfwl_ipv4_fragmentation_set_reassembly_timeout(mc_pfwl_state_t *state,
                                                  uint8_t timeout_seconds);

/**
 * Sets the maximum time (in seconds) that can be spent to reassembly
 * an IPv6 fragmented datagram.
 * Is the maximum time gap between the first and last fragments of
 * the datagram.
 * @param state            A pointer to the state of the library.
 * @param timeout_seconds  The reassembly timeout.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t
mc_pfwl_ipv6_fragmentation_set_reassembly_timeout(mc_pfwl_state_t *state,
                                                  uint8_t timeout_seconds);

/**
 * Disable IPv4 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return 1 If the state has been
 *         successfully updated. 0 if the
 *         state has not been changed because a problem happened.
 */
uint8_t mc_pfwl_ipv4_fragmentation_disable(mc_pfwl_state_t *state);

/**
 * Disable IPv6 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_ipv6_fragmentation_disable(mc_pfwl_state_t *state);

/**
 * If enabled, the library will reorder out of order TCP packets
 * (enabled by default).
 * @param state  A pointer to the state of the library.
 *
 * @return 1 If the state has been
 *         successfully updated. 0 if the state
 *         has not been changed because a problem happened.
 */
uint8_t mc_pfwl_tcp_reordering_enable(mc_pfwl_state_t *state);

/**
 * If it is called, the library will not reorder out of order TCP packets.
 * Out-of-order segments will be delivered to the inspector as they
 * arrive. This means that the inspector may not be able to identify
 * the application protocol. Moreover, if there are callbacks saved
 * for TCP based protocols, if TCP reordering is disabled, the
 * extracted informations could be erroneous or incomplete.
 * @param state A pointer to the state of the library.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_tcp_reordering_disable(mc_pfwl_state_t *state);

/**
 * Enable a protocol inspector.
 * @param state         A pointer to the state of the library.
 * @param protocol      The protocol to enable.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_enable_protocol(mc_pfwl_state_t *state,
                                pfwl_protocol_l7_t protocol);

/**
 * Disable a protocol inspector.
 * @param state       A pointer to the state of the library.
 * @param protocol    The protocol to disable.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_disable_protocol(mc_pfwl_state_t *state,
                                 pfwl_protocol_l7_t protocol);

/**
 * Enable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_inspect_all(mc_pfwl_state_t *state);

/**
 * Disable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_inspect_nothing(mc_pfwl_state_t *state);

/**
 * Returns the string represetations of the protocols.
 * @param   protocol The protocol identifier.
 * @return  An array A of string, such that A[i] is the
 * string representation of the protocol with id 'i'.
 */
const char **const mc_pfwl_get_protocol_strings();

/**
 * Returns the string represetation of a protocol.
 * @param   protocol The protocol identifier.
 * @return  The string representation of the protocol with id 'protocol'.
 */
const char *const mc_pfwl_get_protocol_string(pfwl_protocol_l7_t protocol);

/**
 * Returns the protocol id corresponding to a protocol string.
 * @param string The protocols tring.
 * @return The protocol id corresponding to a protocol string.
 */
pfwl_protocol_l7_t mc_pfwl_get_protocol_id(const char *const string);

/**
 * Sets the callback that will be called when a flow expires.
 * (Valid only if stateful API is used).
 * @param state     A pointer to the state of the library.
 * @param cleaner   The callback used to clear the user state.
 *
 * @return 1 If the state has been
 *         successfully updated. 0 if
 *         the state has not been changed because a problem
 *         happened.
 */
uint8_t
mc_pfwl_set_flow_cleaner_callback(mc_pfwl_state_t *state,
                                  pfwl_flow_cleaner_callback_t *cleaner);

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
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 *
 **/
uint8_t mc_pfwl_http_activate_callbacks(mc_pfwl_state_t *state,
                                        pfwl_http_callbacks_t *callbacks,
                                        void *user_data);

/**
 * Remove the internal structure used to store callbacks informations.
 * user_data is not freed/modified.
 * @param state       A pointer to the state of the library.
 *
 * @return 1 If the state has been successfully
 *         updated. 0 if the state has not
 *         been changed because a problem happened.
 */
uint8_t mc_pfwl_http_disable_callbacks(mc_pfwl_state_t *state);

#endif /* MP_PFWL_API_H_ */
