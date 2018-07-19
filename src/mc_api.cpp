/*
 * mc_api.cpp
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


#include "mc_api.h"
#include "flow_table.h"
#include "worker.hpp"
#include <float.h>
#include <iostream>
#include <stddef.h>
#include <vector>
#include <cmath>

#include <ff/farm.hpp>
#include <ff/mapping_utils.hpp>
#include <ff/pipeline.hpp>
#include <ff/buffer.hpp>

#define DPI_DEBUG_MC_API 1
#define debug_print(fmt, ...)          \
            do { if (DPI_DEBUG_MC_API) \
            fprintf(stdout, fmt, __VA_ARGS__); } while (0)

#define DPI_MULTICORE_STATUS_UPDATER_TID 1

typedef struct mc_dpi_library_state{
	dpi_library_state_t* sequential_state;
	ff::SWSR_Ptr_Buffer* tasks_pool;

	u_int8_t parallel_module_type;
	/******************************************************/
	/*                     Callbacks                      */
	/******************************************************/
	mc_dpi_packet_reading_callback* reading_callback;
	mc_dpi_processing_result_callback* processing_callback;
	void* read_process_callbacks_user_data;

	u_int8_t terminating;
	u_int8_t is_running;

	u_int16_t available_processors;
	unsigned int* mapping;
	/******************************************************/
	/*                 Nodes for single farm.             */
	/******************************************************/
	ff::ff_farm<dpi::dpi_L7_scheduler>* single_farm;
	std::vector<ff::ff_node*>* single_farm_workers;
	dpi::dpi_collapsed_emitter* single_farm_emitter;
	dpi::dpi_L7_collector* single_farm_collector;
  	u_int16_t collector_proc_id;

	u_int16_t single_farm_active_workers;
#ifdef ENABLE_RECONFIGURATION
        nornir::ManagerFarm<dpi::dpi_L7_scheduler>* mf;
	nornir::Parameters* adp_params;
#endif

	/******************************************************/
	/*                 Nodes for double farm.             */
	/******************************************************/
	dpi::dpi_L3_L4_emitter* L3_L4_emitter;
#if DPI_MULTICORE_L3_L4_FARM_TYPE == \
	DPI_MULTICORE_L3_L4_ORDERED_FARM
	ff::ff_ofarm* L3_L4_farm;
#else
	ff::ff_farm<>* L3_L4_farm;
#endif
	std::vector<ff::ff_node*>* L3_L4_workers;
	dpi::dpi_L3_L4_collector* L3_L4_collector;

	dpi::dpi_L7_emitter* L7_emitter;
	ff::ff_farm<dpi::dpi_L7_scheduler>* L7_farm;
	std::vector<ff::ff_node*>* L7_workers;
	dpi::dpi_L7_collector* L7_collector;
	ff::ff_pipeline* pipeline;
	u_int16_t double_farm_L3_L4_active_workers;
	u_int16_t double_farm_L7_active_workers;
	/******************************************************/
	/*                 Statistics.                        */
	/******************************************************/
	struct timeval start_time;
	struct timeval stop_time;
}mc_dpi_library_state_t;


#ifndef DPI_DEBUG
static inline
#endif
void mc_dpi_create_double_farm(mc_dpi_library_state_t* state,
		                       u_int32_t size_v4,
		                       u_int32_t size_v6){
	u_int16_t last_mapped=0;
	/******************************************/
	/*         Create the first farm.         */
	/******************************************/
	void* tmp;
#if DPI_MULTICORE_L3_L4_FARM_TYPE == \
	DPI_MULTICORE_L3_L4_ORDERED_FARM
	tmp=malloc(sizeof(ff::ff_ofarm));
	assert(tmp);
	state->L3_L4_farm=new (tmp) ff::ff_ofarm(
			false,
			DPI_MULTICORE_L3_L4_FARM_INPUT_BUFFER_SIZE,
			DPI_MULTICORE_L3_L4_FARM_OUTPUT_BUFFER_SIZE,
			false, state->available_processors, true);
	tmp=malloc(sizeof(dpi::dpi_L3_L4_emitter));
	assert(tmp);
	state->L3_L4_emitter=new (tmp) dpi::dpi_L3_L4_emitter(
       	                state->sequential_state,
			&(state->reading_callback),
			&(state->read_process_callbacks_user_data),
			&(state->terminating),
			state->mapping[last_mapped], state->tasks_pool);
	last_mapped=(last_mapped+1)%state->available_processors;
	state->L3_L4_farm->setEmitterF(state->L3_L4_emitter);
#else
	tmp=malloc(sizeof(ff::ff_farm<>));
	assert(tmp);
	state->L3_L4_farm=new (tmp) ff::ff_farm<>(
			false,
			DPI_MULTICORE_L3_L4_FARM_INPUT_BUFFER_SIZE,
			DPI_MULTICORE_L3_L4_FARM_OUTPUT_BUFFER_SIZE,
			false, state->available_processors, true);
	tmp=malloc(sizeof(dpi::dpi_L3_L4_emitter));
	assert(tmp);
	state->L3_L4_emitter=new (tmp) dpi::dpi_L3_L4_emitter(
                        state->sequential_state,
			&(state->reading_callback),
			&(state->read_process_callbacks_user_data),
			&(state->terminating),
			state->mapping[last_mapped], state->tasks_pool);
	last_mapped=(last_mapped+1)%state->available_processors;
	state->L3_L4_farm->add_emitter(state->L3_L4_emitter);
#if DPI_MULTICORE_L3_L4_FARM_TYPE == \
	DPI_MULTICORE_L3_L4_ON_DEMAND
	state->L3_L4_farm->set_scheduling_ondemand(1024);
#endif
#endif

	state->L3_L4_workers=new std::vector<ff::ff_node*>;
	dpi::dpi_L3_L4_worker* w1;
	for(uint i=0; i<state->double_farm_L3_L4_active_workers; i++){
		tmp=malloc(sizeof(dpi::dpi_L3_L4_worker));
		assert(tmp);
		w1=new (tmp) dpi::dpi_L3_L4_worker(state->sequential_state, i,
		   (state->double_farm_L7_active_workers),
		   state->mapping[last_mapped],
		   size_v4,
		   size_v6);
		state->L3_L4_workers->push_back(w1);
		last_mapped=(last_mapped+1)%state->available_processors;
	}
	assert(state->L3_L4_farm->add_workers(*(state->L3_L4_workers))==0);

	tmp=malloc(sizeof(dpi::dpi_L3_L4_collector));
	assert(tmp);
	state->L3_L4_collector=new (tmp)
			               dpi::dpi_L3_L4_collector(state->mapping[last_mapped]);
	assert(state->L3_L4_collector);
	last_mapped=(last_mapped+1)%state->available_processors;
#if DPI_MULTICORE_L3_L4_FARM_TYPE == \
	DPI_MULTICORE_L3_L4_ORDERED_FARM
	state->L3_L4_farm->setCollectorF(state->L3_L4_collector);
#else
	assert(state->L3_L4_farm->add_collector(state->L3_L4_collector)>=0);
#endif

	/**************************************/
	/*      Create the second farm.       */
	/**************************************/
	tmp=malloc(sizeof(ff::ff_farm<dpi::dpi_L7_scheduler>));
	assert(tmp);
	state->L7_farm=new (tmp) ff::ff_farm<dpi::dpi_L7_scheduler>(
			false, DPI_MULTICORE_L7_FARM_INPUT_BUFFER_SIZE,
			DPI_MULTICORE_L7_FARM_OUTPUT_BUFFER_SIZE, false,
			state->available_processors, true);

	tmp=malloc(sizeof(dpi::dpi_L7_emitter));
	assert(tmp);
	state->L7_emitter=new (tmp) dpi::dpi_L7_emitter(
			state->L7_farm->getlb(),
			state->double_farm_L7_active_workers,
			state->mapping[last_mapped]);
	last_mapped=(last_mapped+1)%state->available_processors;
	state->L7_farm->add_emitter(state->L7_emitter);

	state->L7_workers=new std::vector<ff::ff_node*>;
	dpi::dpi_L7_worker* w2;
	for(uint i=0; i<state->double_farm_L7_active_workers; i++){
		tmp=malloc(sizeof(dpi::dpi_L7_worker));
		assert(tmp);
		w2=new (tmp) dpi::dpi_L7_worker(state->sequential_state, i,
				                        state->mapping[last_mapped]);
		state->L7_workers->push_back(w2);
		last_mapped=(last_mapped+1)%state->available_processors;
	}
	assert(state->L7_farm->add_workers(*(state->L7_workers))==0);

	tmp=malloc(sizeof(dpi::dpi_L7_collector));
	assert(tmp);
        state->collector_proc_id=state->mapping[last_mapped];

	state->L7_collector=new (tmp) dpi::dpi_L7_collector(
			&(state->processing_callback),
			&(state->read_process_callbacks_user_data),
			&(state->collector_proc_id), state->tasks_pool);
	last_mapped=(last_mapped+1)%state->available_processors;
	assert(state->L7_farm->add_collector(state->L7_collector)>=0);

	/********************************/
	/*     Create the pipeline.     */
	/********************************/
	tmp=malloc(sizeof(ff::ff_pipeline));
	assert(tmp);
	state->pipeline=new (tmp) ff::ff_pipeline(
			false,
			DPI_MULTICORE_PIPELINE_INPUT_BUFFER_SIZE,
			DPI_MULTICORE_PIPELINE_OUTPUT_BUFFER_SIZE,
			true);

	state->pipeline->add_stage(state->L3_L4_farm);
	state->pipeline->add_stage(state->L7_farm);
	state->parallel_module_type=MC_DPI_PARALLELISM_FORM_DOUBLE_FARM;
}

#ifndef DPI_DEBUG
static inline
#endif
void mc_dpi_create_single_farm(mc_dpi_library_state_t* state,
		                       u_int32_t size_v4, u_int32_t size_v6){
	u_int16_t last_mapped=0;
	state->single_farm=new ff::ff_farm<dpi::dpi_L7_scheduler>(
			false,
			DPI_MULTICORE_L7_FARM_INPUT_BUFFER_SIZE,
			DPI_MULTICORE_L7_FARM_OUTPUT_BUFFER_SIZE,
			false, state->available_processors, true);
	assert(state->single_farm);

	state->single_farm_emitter=new dpi::dpi_collapsed_emitter(
			&(state->reading_callback),
			&(state->read_process_callbacks_user_data),
			&(state->terminating),
			state->tasks_pool, state->sequential_state,
			(state->single_farm_active_workers),
			size_v4,
			size_v6,
			state->single_farm->getlb(),
			state->mapping[last_mapped]);
	assert(state->single_farm_emitter);
	last_mapped=(last_mapped+1)%state->available_processors;
	state->single_farm->add_emitter(state->single_farm_emitter);

	state->single_farm_workers=new std::vector<ff::ff_node*>;
	dpi::dpi_L7_worker* w;
	for(u_int16_t i=0; i<state->single_farm_active_workers; i++){
		w=new dpi::dpi_L7_worker(state->sequential_state, i,
				                 state->mapping[last_mapped]);
		assert(w);
		state->single_farm_workers->push_back(w);
		last_mapped=(last_mapped+1)%state->available_processors;
	}

	assert(state->single_farm->add_workers(
				*(state->single_farm_workers))==0);
	state->collector_proc_id=state->mapping[last_mapped];
	state->single_farm_collector=new dpi::dpi_L7_collector(
			&(state->processing_callback),
			&(state->read_process_callbacks_user_data),
			&(state->collector_proc_id), state->tasks_pool);
	assert(state->single_farm_collector);
	last_mapped=(last_mapped+1)%state->available_processors;
	assert(state->single_farm->add_collector(
			state->single_farm_collector)>=0);
	state->parallel_module_type=MC_DPI_PARALLELISM_FORM_ONE_FARM;
}


static inline ssize_t get_num_cores() {
    ssize_t  n=-1;
#if defined(_WIN32)
    n = 2; // Not yet implemented
#else
#if defined(__linux__)
    char inspect[]="cat /proc/cpuinfo|egrep 'core id|physical id'|tr -d '\n'|sed 's/physical/\\nphysical/g'|grep -v ^$|sort|uniq|wc -l";
#elif defined (__APPLE__)
    char inspect[]="sysctl hw.physicalcpu | awk '{print $2}'";
#else
    char inspect[]="";
    n=1;
#pragma message ("ff_realNumCores not supported on this platform")
#endif
    FILE       *f;
    f = popen(inspect, "r");
    if (f) {
        if (fscanf(f, "%ld", &n) == EOF) {
            perror("fscanf");
        }
        pclose(f);
    } else perror("popen");
#endif // _WIN32
    return n;
}

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
		mc_dpi_parallelism_details_t parallelism_details){
	mc_dpi_library_state_t* state;
	assert(posix_memalign((void**) &state, DPI_CACHE_LINE_SIZE,
		   sizeof(mc_dpi_library_state_t)+DPI_CACHE_LINE_SIZE)==0);
	bzero(state, sizeof(mc_dpi_library_state_t));

	u_int8_t parallelism_form=parallelism_details.parallelism_form;

	if(parallelism_details.available_processors){
		state->available_processors = parallelism_details.available_processors;
	}else{
	    state->available_processors = get_num_cores();
	}

	if(parallelism_form==MC_DPI_PARALLELISM_FORM_DOUBLE_FARM){
		assert(state->available_processors >= 4+2);
	}else{
		assert(state->available_processors >= 2+1);
	}
	
	state->mapping = new unsigned int[state->available_processors];


    uint k;
    for(k=0; k<state->available_processors; k++){
        if(parallelism_details.mapping==NULL){
            state->mapping[k] = k;
        }else{
            state->mapping[k] = parallelism_details.mapping[k];
        }
    }

	state->terminating=0;

	u_int16_t hash_table_partitions;

	state->double_farm_L3_L4_active_workers = parallelism_details.double_farm_num_L3_workers;
	state->double_farm_L7_active_workers = parallelism_details.double_farm_num_L7_workers;
	state->single_farm_active_workers = state->available_processors-2;
	if(parallelism_form==MC_DPI_PARALLELISM_FORM_DOUBLE_FARM){
		assert(state->double_farm_L3_L4_active_workers>0 &&
			   state->double_farm_L7_active_workers>0);
		debug_print("%s\n","[mc_dpi_api.cpp]: A pipeline of two "
				"farms will be activated.");
		hash_table_partitions=state->double_farm_L7_active_workers;
	}else{
		assert(state->single_farm_active_workers>0);
		debug_print("%s\n","[mc_dpi_api.cpp]: Only one farm will "
				"be activated.");
		hash_table_partitions=state->single_farm_active_workers;
	}

	state->sequential_state=dpi_init_stateful_num_partitions(
			size_v4,
			size_v6,
			max_active_v4_flows,
			max_active_v6_flows,
			hash_table_partitions);

	/******************************/
	/*   Create the tasks pool.   */
	/******************************/
#if DPI_MULTICORE_USE_TASKS_POOL
	void* tmp;
	assert(posix_memalign((void**) &tmp, DPI_CACHE_LINE_SIZE,
		   sizeof(ff::SWSR_Ptr_Buffer)+DPI_CACHE_LINE_SIZE)==0);
	state->tasks_pool=new (tmp) ff::SWSR_Ptr_Buffer(
			DPI_MULTICORE_TASKS_POOL_SIZE);
	state->tasks_pool->init();
#endif

	if(parallelism_form==MC_DPI_PARALLELISM_FORM_DOUBLE_FARM){
		mc_dpi_create_double_farm(state, size_v4, size_v6);
	}else{
		mc_dpi_create_single_farm(state, size_v4, size_v6);
	}

	state->is_running=0;
	state->stop_time.tv_sec=0;
	state->stop_time.tv_usec=0;
	return state;
}

/**
 * Prints execution's statistics.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_print_stats(mc_dpi_library_state_t* state){
	if(state){
		if(state->parallel_module_type==
				MC_DPI_PARALLELISM_FORM_DOUBLE_FARM){
			state->pipeline->ffStats(std::cout);
		}else{
			state->single_farm->ffStats(std::cout);
		}
		if(state->stop_time.tv_sec != 0){
			std::cout << "Completion time: " << ff::diffmsec(state->stop_time, state->start_time) << std::endl;
		}
	}
}


/**
 * Terminates the library.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_terminate(mc_dpi_library_state_t *state){
	if(likely(state)){
		if(state->parallel_module_type==
				MC_DPI_PARALLELISM_FORM_DOUBLE_FARM){
			state->L3_L4_emitter->~dpi_L3_L4_emitter();
			free(state->L3_L4_emitter);
#if DPI_MULTICORE_L3_L4_FARM_TYPE ==\
	DPI_MULTICORE_L3_L4_ORDERED_FARM
			state->L3_L4_farm->~ff_ofarm();
#else
			state->L3_L4_farm->~ff_farm();
#endif
			free(state->L3_L4_farm);
			free(state->L3_L4_collector);

			while(!state->L3_L4_workers->empty()){
				((dpi::dpi_L3_L4_worker*) state->
						L3_L4_workers->back())->~dpi_L3_L4_worker();
				free((dpi::dpi_L3_L4_worker*) state->
						L3_L4_workers->back());
				state->L3_L4_workers->pop_back();
			}
			delete state->L3_L4_workers;

			state->L7_emitter->~dpi_L7_emitter();
			free(state->L7_emitter);
			state->L7_farm->~ff_farm();
			free(state->L7_farm);
			free(state->L7_collector);

			while(!state->L7_workers->empty()){
				((dpi::dpi_L7_worker*) state->
						L7_workers->back())->~dpi_L7_worker();
				free((dpi::dpi_L7_worker*) state->L7_workers->back());
				state->L7_workers->pop_back();
			}
			delete state->L7_workers;

			state->pipeline->~ff_pipeline();
			free(state->pipeline);
		}else{
			delete state->single_farm_emitter;
			delete state->single_farm;
			delete state->single_farm_collector;
			while(!state->single_farm_workers->empty()){
				delete (dpi::dpi_L7_worker*) state->
						single_farm_workers->back();
				state->single_farm_workers->pop_back();
			}
			delete state->single_farm_workers;
		}
		dpi_terminate(state->sequential_state);

#if DPI_MULTICORE_USE_TASKS_POOL
		state->tasks_pool->~SWSR_Ptr_Buffer();
		free(state->tasks_pool);
#endif
		delete[] state->mapping;
		free(state);
	}

}

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
		void* user_data){
	state->reading_callback=reading_callback;
	state->processing_callback=processing_callback;
	state->read_process_callbacks_user_data=user_data;
}


/***************************************/
/*          Other API calls            */
/***************************************/

#ifdef ENABLE_RECONFIGURATION
void mc_dpi_set_reconf_parameters(mc_dpi_library_state_t* state, nornir::Parameters* p){
    state->adp_params = p;
}
#endif

/**
 * Starts the library.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_run(mc_dpi_library_state_t* state){
	// Real start
	debug_print("%s\n","[mc_dpi_api.cpp]: Run preparation...");
	state->is_running=1;
    if(state->parallel_module_type == MC_DPI_PARALLELISM_FORM_DOUBLE_FARM){
        // Warm-up
        assert(state->pipeline->run_then_freeze()>=0);
    }else{
        // Warm-up
#ifdef ENABLE_RECONFIGURATION
        try{
            state->mf = new nornir::ManagerFarm<dpi::dpi_L7_scheduler>(state->single_farm, *(state->adp_params));
            state->mf->start();
        }catch(std::exception& e){
            assert("Exception thrown by ManagerFarm" == NULL);
        }
#else
        assert(state->single_farm->run_then_freeze()>=0);
#endif
    }
	gettimeofday(&state->start_time,NULL);
	debug_print("%s\n","[mc_dpi_api.cpp]: Running...");
}

/**
 * Wait the end of the data processing.
 * @param state A pointer to the state of the library.
 */
void mc_dpi_wait_end(mc_dpi_library_state_t* state){
	  if(state->parallel_module_type == MC_DPI_PARALLELISM_FORM_DOUBLE_FARM){
        state->pipeline->wait();
    }else{
#ifdef ENABLE_RECONFIGURATION
		state->mf->join();
#else
       state->single_farm->wait();
#endif
    }
#if 0
	while(!state->terminating){
		sleep(1);
	}
#endif
    gettimeofday(&state->stop_time,NULL);
	state->is_running=0;
}


/****************************************/
/*        Status change API calls       */
/****************************************/

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
		                       u_int16_t max_trials){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_set_max_trials(state->sequential_state, max_trials);
	return r;
}



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
		                                  u_int16_t table_size){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv4_fragmentation_enable(state->sequential_state,
		                        table_size);
	return r;
}

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
		                                  u_int16_t table_size){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv6_fragmentation_enable(state->sequential_state,
		                        table_size);
	return r;
}

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
		u_int32_t per_host_memory_limit){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv4_fragmentation_set_per_host_memory_limit(
			state->sequential_state,
			per_host_memory_limit);
	return r;
}

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
		u_int32_t per_host_memory_limit){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv6_fragmentation_set_per_host_memory_limit(
			state->sequential_state,
			per_host_memory_limit);
	return r;
}

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
		u_int32_t total_memory_limit){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv4_fragmentation_set_total_memory_limit(
			state->sequential_state, total_memory_limit);
	return r;
}

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
		u_int32_t total_memory_limit){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv6_fragmentation_set_total_memory_limit(
			state->sequential_state, total_memory_limit);
	return r;
}

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
		u_int8_t timeout_seconds){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv4_fragmentation_set_reassembly_timeout(
			state->sequential_state, timeout_seconds);
	return r;

}

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
		u_int8_t timeout_seconds){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv6_fragmentation_set_reassembly_timeout(
			state->sequential_state, timeout_seconds);
	return r;
}

/**
 * Disable IPv4 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been
 *         successfully updated. DPI_STATE_UPDATE_FAILURE if the
 *         state has not been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv4_fragmentation_disable(mc_dpi_library_state_t *state){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv4_fragmentation_disable(state->sequential_state);
	return r;
}

/**
 * Disable IPv6 defragmentation.
 * @param state A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_ipv6_fragmentation_disable(mc_dpi_library_state_t *state){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_ipv6_fragmentation_disable(state->sequential_state);
	return r;
}



/**
 * If enabled, the library will reorder out of order TCP packets
 * (enabled by default).
 * @param state  A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been
 *         successfully updated. DPI_STATE_UPDATE_FAILURE if the state
 *         has not been changed because a problem happened.
 */
u_int8_t mc_dpi_tcp_reordering_enable(mc_dpi_library_state_t* state){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_tcp_reordering_enable(state->sequential_state);
	return r;
}

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
u_int8_t mc_dpi_tcp_reordering_disable(mc_dpi_library_state_t* state){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_tcp_reordering_disable(state->sequential_state);
	return r;
}

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
		                     dpi_protocol_t protocol){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_set_protocol(state->sequential_state, protocol);
	return r;
}

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
		                        dpi_protocol_t protocol){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_delete_protocol(state->sequential_state, protocol);
	return r;
}

/**
 * Enable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_inspect_all(mc_dpi_library_state_t *state){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_inspect_all(state->sequential_state);
	return r;
}

/**
 * Disable all the protocol inspector.
 * @param state      A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_inspect_nothing(mc_dpi_library_state_t *state){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_inspect_nothing(state->sequential_state);
	return r;
}


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
		dpi_flow_cleaner_callback* cleaner){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_set_flow_cleaner_callback(state->sequential_state, cleaner);
	return r;
}

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
		void* user_data){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_http_activate_callbacks(state->sequential_state,
		                      callbacks,
		                      user_data);
	return r;
}

/**
 * Remove the internal structure used to store callbacks informations.
 * user_data is not freed/modified.
 * @param state       A pointer to the state of the library.
 *
 * @return DPI_STATE_UPDATE_SUCCESS If the state has been successfully
 *         updated. DPI_STATE_UPDATE_FAILURE if the state has not
 *         been changed because a problem happened.
 */
u_int8_t mc_dpi_http_disable_callbacks(mc_dpi_library_state_t* state){
    if(state->is_running){
        return DPI_STATE_UPDATE_FAILURE;
    }
	u_int8_t r;
	r=dpi_http_disable_callbacks(state->sequential_state);
	return r;
}

