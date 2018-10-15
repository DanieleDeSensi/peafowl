/*
 * peafowl_mc.cpp
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

#include <peafowl/flow_table.h>
#include <peafowl/peafowl_mc.h>
#include <peafowl/worker.hpp>

#include <ff/buffer.hpp>
#include <ff/farm.hpp>
#include <ff/mapping_utils.hpp>
#include <ff/pipeline.hpp>

#include <cmath>
#include <float.h>
#include <iostream>
#include <stddef.h>
#include <vector>

#define PFWL_DEBUG_MC_API 1
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_MC_API)                                                     \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

#define PFWL_MULTICORE_STATUS_UPDATER_TID 1

typedef struct mc_pfwl_library_state {
  pfwl_state_t *sequential_state;
  ff::SWSR_Ptr_Buffer *tasks_pool;

  uint8_t parallel_module_type;
  /******************************************************/
  /*                     Callbacks                      */
  /******************************************************/
  mc_pfwl_packet_reading_callback *reading_callback;
  mc_pfwl_processing_result_callback *processing_callback;
  void *read_process_callbacks_user_data;

  uint8_t terminating;
  uint8_t is_running;

  uint16_t available_processors;
  unsigned int *mapping;
  /******************************************************/
  /*                 Nodes for single farm.             */
  /******************************************************/
  ff::ff_farm<dpi::pfwl_L7_scheduler> *single_farm;
  std::vector<ff::ff_node *> *single_farm_workers;
  dpi::pfwl_collapsed_emitter *single_farm_emitter;
  dpi::pfwl_L7_collector *single_farm_collector;
  uint16_t collector_proc_id;

  uint16_t single_farm_active_workers;
#ifdef ENABLE_RECONFIGURATION
  nornir::ManagerFarm<dpi::pfwl_L7_scheduler> *mf;
  nornir::Parameters *adp_params;
#endif

  /******************************************************/
  /*                 Nodes for double farm.             */
  /******************************************************/
  dpi::pfwl_L3_L4_emitter *L3_L4_emitter;
#if PFWL_MULTICORE_L3_L4_FARM_TYPE == PFWL_MULTICORE_L3_L4_ORDERED_FARM
  ff::ff_ofarm *L3_L4_farm;
#else
  ff::ff_farm<> *L3_L4_farm;
#endif
  std::vector<ff::ff_node *> *L3_L4_workers;
  dpi::pfwl_L3_L4_collector *L3_L4_collector;

  dpi::pfwl_L7_emitter *L7_emitter;
  ff::ff_farm<dpi::pfwl_L7_scheduler> *L7_farm;
  std::vector<ff::ff_node *> *L7_workers;
  dpi::pfwl_L7_collector *L7_collector;
  ff::ff_pipeline *pipeline;
  uint16_t double_farm_L3_L4_active_workers;
  uint16_t double_farm_L7_active_workers;
  /******************************************************/
  /*                 Statistics.                        */
  /******************************************************/
  struct timeval start_time;
  struct timeval stop_time;
} mc_pfwl_state_t;

#ifndef PFWL_DEBUG
static inline
#endif
    void
    mc_pfwl_create_double_farm(mc_pfwl_state_t *state, uint32_t size_v4,
                               uint32_t size_v6) {
  uint16_t last_mapped = 0;
  /******************************************/
  /*         Create the first farm.         */
  /******************************************/
  void *tmp;
#if PFWL_MULTICORE_L3_L4_FARM_TYPE == PFWL_MULTICORE_L3_L4_ORDERED_FARM
  tmp = malloc(sizeof(ff::ff_ofarm));
  assert(tmp);
  state->L3_L4_farm =
      new (tmp) ff::ff_ofarm(false, PFWL_MULTICORE_L3_L4_FARM_INPUT_BUFFER_SIZE,
                             PFWL_MULTICORE_L3_L4_FARM_OUTPUT_BUFFER_SIZE,
                             false, state->available_processors, true);
  tmp = malloc(sizeof(dpi::pfwl_L3_L4_emitter));
  assert(tmp);
  state->L3_L4_emitter = new (tmp) dpi::pfwl_L3_L4_emitter(
      state->sequential_state, &(state->reading_callback),
      &(state->read_process_callbacks_user_data), &(state->terminating),
      state->mapping[last_mapped], state->tasks_pool);
  last_mapped = (last_mapped + 1) % state->available_processors;
  state->L3_L4_farm->setEmitterF(state->L3_L4_emitter);
#else
  tmp = malloc(sizeof(ff::ff_farm<>));
  assert(tmp);
  state->L3_L4_farm = new (tmp)
      ff::ff_farm<>(false, PFWL_MULTICORE_L3_L4_FARM_INPUT_BUFFER_SIZE,
                    PFWL_MULTICORE_L3_L4_FARM_OUTPUT_BUFFER_SIZE, false,
                    state->available_processors, true);
  tmp = malloc(sizeof(dpi::pfwl_L3_L4_emitter));
  assert(tmp);
  state->L3_L4_emitter = new (tmp) dpi::pfwl_L3_L4_emitter(
      state->sequential_state, &(state->reading_callback),
      &(state->read_process_callbacks_user_data), &(state->terminating),
      state->mapping[last_mapped], state->tasks_pool);
  last_mapped = (last_mapped + 1) % state->available_processors;
  state->L3_L4_farm->add_emitter(state->L3_L4_emitter);
#if PFWL_MULTICORE_L3_L4_FARM_TYPE == PFWL_MULTICORE_L3_L4_ON_DEMAND
  state->L3_L4_farm->set_scheduling_ondemand(1024);
#endif
#endif

  state->L3_L4_workers = new std::vector<ff::ff_node *>;
  for (uint i = 0; i < state->double_farm_L3_L4_active_workers; i++) {
    tmp = malloc(sizeof(dpi::pfwl_L3_L4_worker));
    assert(tmp);
    dpi::pfwl_L3_L4_worker *w1 = new (tmp) dpi::pfwl_L3_L4_worker(
        state->sequential_state, i, (state->double_farm_L7_active_workers),
        state->mapping[last_mapped], size_v4, size_v6);
    state->L3_L4_workers->push_back(w1);
    last_mapped = (last_mapped + 1) % state->available_processors;
  }
  state->L3_L4_farm->add_workers(*(state->L3_L4_workers));

  tmp = malloc(sizeof(dpi::pfwl_L3_L4_collector));
  assert(tmp);
  state->L3_L4_collector =
      new (tmp) dpi::pfwl_L3_L4_collector(state->mapping[last_mapped]);
  assert(state->L3_L4_collector);
  last_mapped = (last_mapped + 1) % state->available_processors;
#if PFWL_MULTICORE_L3_L4_FARM_TYPE == PFWL_MULTICORE_L3_L4_ORDERED_FARM
  state->L3_L4_farm->setCollectorF(state->L3_L4_collector);
#else
  state->L3_L4_farm->add_collector(state->L3_L4_collector);
#endif

  /**************************************/
  /*      Create the second farm.       */
  /**************************************/
  tmp = malloc(sizeof(ff::ff_farm<dpi::pfwl_L7_scheduler>));
  assert(tmp);
  state->L7_farm = new (tmp) ff::ff_farm<dpi::pfwl_L7_scheduler>(
      false, PFWL_MULTICORE_L7_FARM_INPUT_BUFFER_SIZE,
      PFWL_MULTICORE_L7_FARM_OUTPUT_BUFFER_SIZE, false,
      state->available_processors, true);

  tmp = malloc(sizeof(dpi::pfwl_L7_emitter));
  assert(tmp);
  state->L7_emitter = new (tmp) dpi::pfwl_L7_emitter(
      state->L7_farm->getlb(), state->double_farm_L7_active_workers,
      state->mapping[last_mapped]);
  last_mapped = (last_mapped + 1) % state->available_processors;
  state->L7_farm->add_emitter(state->L7_emitter);

  state->L7_workers = new std::vector<ff::ff_node *>;
  for (uint i = 0; i < state->double_farm_L7_active_workers; i++) {
    tmp = malloc(sizeof(dpi::pfwl_L7_worker));
    assert(tmp);
    dpi::pfwl_L7_worker *w2 = new (tmp) dpi::pfwl_L7_worker(
        state->sequential_state, i, state->mapping[last_mapped]);
    state->L7_workers->push_back(w2);
    last_mapped = (last_mapped + 1) % state->available_processors;
  }
  state->L7_farm->add_workers(*(state->L7_workers));

  tmp = malloc(sizeof(dpi::pfwl_L7_collector));
  assert(tmp);
  state->collector_proc_id = state->mapping[last_mapped];

  state->L7_collector = new (tmp) dpi::pfwl_L7_collector(
      &(state->processing_callback), &(state->read_process_callbacks_user_data),
      &(state->collector_proc_id), state->tasks_pool);
  state->L7_farm->add_collector(state->L7_collector);

  /********************************/
  /*     Create the pipeline.     */
  /********************************/
  tmp = malloc(sizeof(ff::ff_pipeline));
  assert(tmp);
  state->pipeline = new (tmp)
      ff::ff_pipeline(false, PFWL_MULTICORE_PIPELINE_INPUT_BUFFER_SIZE,
                      PFWL_MULTICORE_PIPELINE_OUTPUT_BUFFER_SIZE, true);

  state->pipeline->add_stage(state->L3_L4_farm);
  state->pipeline->add_stage(state->L7_farm);
  state->parallel_module_type = MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM;
}

#ifndef PFWL_DEBUG
static inline
#endif
    void
    mc_pfwl_create_single_farm(mc_pfwl_state_t *state, uint32_t size_v4,
                               uint32_t size_v6) {
  uint16_t last_mapped = 0;
  state->single_farm = new ff::ff_farm<dpi::pfwl_L7_scheduler>(
      false, PFWL_MULTICORE_L7_FARM_INPUT_BUFFER_SIZE,
      PFWL_MULTICORE_L7_FARM_OUTPUT_BUFFER_SIZE, false,
      state->available_processors, true);
  assert(state->single_farm);

  state->single_farm_emitter = new dpi::pfwl_collapsed_emitter(
      &(state->reading_callback), &(state->read_process_callbacks_user_data),
      &(state->terminating), state->tasks_pool, state->sequential_state,
      (state->single_farm_active_workers), size_v4, size_v6,
      state->single_farm->getlb(), state->mapping[last_mapped]);
  assert(state->single_farm_emitter);
  last_mapped = (last_mapped + 1) % state->available_processors;
  state->single_farm->add_emitter(state->single_farm_emitter);

  state->single_farm_workers = new std::vector<ff::ff_node *>;
  for (uint16_t i = 0; i < state->single_farm_active_workers; i++) {
    dpi::pfwl_L7_worker *w = new dpi::pfwl_L7_worker(
        state->sequential_state, i, state->mapping[last_mapped]);
    assert(w);
    state->single_farm_workers->push_back(w);
    last_mapped = (last_mapped + 1) % state->available_processors;
  }

  state->single_farm->add_workers(*(state->single_farm_workers));
  state->collector_proc_id = state->mapping[last_mapped];
  state->single_farm_collector = new dpi::pfwl_L7_collector(
      &(state->processing_callback), &(state->read_process_callbacks_user_data),
      &(state->collector_proc_id), state->tasks_pool);
  assert(state->single_farm_collector);
  state->single_farm->add_collector(state->single_farm_collector);
  state->parallel_module_type = MC_PFWL_PARALLELISM_FORM_ONE_FARM;
}

static inline ssize_t get_num_cores() {
  ssize_t n;
#if defined(_WIN32)
  n = 2; // Not yet implemented
#else
  n = 0;
#if defined(__linux__)
  char inspect[] =
      "cat /proc/cpuinfo|egrep 'core id|physical id'|tr -d '\n'|sed "
      "'s/physical/\\nphysical/g'|grep -v ^$|sort|uniq|wc -l";
#elif defined(__APPLE__)
  char inspect[] = "sysctl hw.physicalcpu | awk '{print $2}'";
#else
  char inspect[] = "";
#pragma message("ff_realNumCores not supported on this platform")
  return 1;
#endif
  FILE *f;
  f = popen(inspect, "r");
  if (f) {
    if (fscanf(f, "%ld", &n) == EOF) {
      perror("fscanf");
    }
    pclose(f);
  } else
    perror("popen");
#endif // _WIN32
  return n;
}

mc_pfwl_state_t *
mc_pfwl_init_stateful(uint32_t size_v4, uint32_t size_v6,
                      uint32_t max_active_v4_flows,
                      uint32_t max_active_v6_flows,
                      mc_pfwl_parallelism_details_t parallelism_details) {
  mc_pfwl_state_t *state = NULL;
  if (posix_memalign((void **) &state, PFWL_CACHE_LINE_SIZE,
                     sizeof(mc_pfwl_state_t) + PFWL_CACHE_LINE_SIZE)) {
    throw std::runtime_error("posix_memalign failed.");
  }
  bzero(state, sizeof(mc_pfwl_state_t));

  uint8_t parallelism_form = parallelism_details.parallelism_form;

  if (parallelism_details.available_processors) {
    state->available_processors = parallelism_details.available_processors;
  } else {
    state->available_processors = get_num_cores();
  }

  if (parallelism_form == MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM) {
    assert(state->available_processors >= 4 + 2);
  } else {
    assert(state->available_processors >= 2 + 1);
  }

  state->mapping = new unsigned int[state->available_processors];

  uint k;
  for (k = 0; k < state->available_processors; k++) {
    if (parallelism_details.mapping == NULL) {
      state->mapping[k] = k;
    } else {
      state->mapping[k] = parallelism_details.mapping[k];
    }
  }

  state->terminating = 0;

  uint16_t hash_table_partitions;

  state->double_farm_L3_L4_active_workers =
      parallelism_details.double_farm_num_L3_workers;
  state->double_farm_L7_active_workers =
      parallelism_details.double_farm_num_L7_workers;
  state->single_farm_active_workers = state->available_processors - 2;
  if (parallelism_form == MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM) {
    assert(state->double_farm_L3_L4_active_workers > 0 &&
           state->double_farm_L7_active_workers > 0);
    debug_print("%s\n", "[mc_pfwl_peafowl.cpp]: A pipeline of two "
                        "farms will be activated.");
    hash_table_partitions = state->double_farm_L7_active_workers;
  } else {
    assert(state->single_farm_active_workers > 0);
    debug_print("%s\n", "[mc_pfwl_peafowl.cpp]: Only one farm will "
                        "be activated.");
    hash_table_partitions = state->single_farm_active_workers;
  }

  state->sequential_state = pfwl_init_stateful_num_partitions(
      size_v4, size_v6, max_active_v4_flows, max_active_v6_flows,
      hash_table_partitions);

/******************************/
/*   Create the tasks pool.   */
/******************************/
#if PFWL_MULTICORE_USE_TASKS_POOL
  void *tmp = NULL;
  if (posix_memalign((void **) &tmp, PFWL_CACHE_LINE_SIZE,
                     sizeof(ff::SWSR_Ptr_Buffer) + PFWL_CACHE_LINE_SIZE)) {
    throw std::runtime_error("posix_memalign failed.");
  }
  state->tasks_pool =
      new (tmp) ff::SWSR_Ptr_Buffer(PFWL_MULTICORE_TASKS_POOL_SIZE);
  state->tasks_pool->init();
#endif

  if (parallelism_form == MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM) {
    mc_pfwl_create_double_farm(state, size_v4, size_v6);
  } else {
    mc_pfwl_create_single_farm(state, size_v4, size_v6);
  }

  state->is_running = 0;
  state->stop_time.tv_sec = 0;
  state->stop_time.tv_usec = 0;
  return state;
}

void mc_pfwl_print_stats(mc_pfwl_state_t *state) {
  if (state) {
    if (state->parallel_module_type == MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM) {
      state->pipeline->ffStats(std::cout);
    } else {
      state->single_farm->ffStats(std::cout);
    }
    if (state->stop_time.tv_sec != 0) {
      std::cout << "Completion time: "
                << ff::diffmsec(state->stop_time, state->start_time)
                << std::endl;
    }
  }
}

void mc_pfwl_terminate(mc_pfwl_state_t *state) {
  if (likely(state)) {
    if (state->parallel_module_type == MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM) {
      state->L3_L4_emitter->~pfwl_L3_L4_emitter();
      free(state->L3_L4_emitter);
#if PFWL_MULTICORE_L3_L4_FARM_TYPE == PFWL_MULTICORE_L3_L4_ORDERED_FARM
      state->L3_L4_farm->~ff_ofarm();
#else
      state->L3_L4_farm->~ff_farm();
#endif
      free(state->L3_L4_farm);
      free(state->L3_L4_collector);

      while (!state->L3_L4_workers->empty()) {
        ((dpi::pfwl_L3_L4_worker *) state->L3_L4_workers->back())
            ->~pfwl_L3_L4_worker();
        free((dpi::pfwl_L3_L4_worker *) state->L3_L4_workers->back());
        state->L3_L4_workers->pop_back();
      }
      delete state->L3_L4_workers;

      state->L7_emitter->~pfwl_L7_emitter();
      free(state->L7_emitter);
      state->L7_farm->~ff_farm();
      free(state->L7_farm);
      free(state->L7_collector);

      while (!state->L7_workers->empty()) {
        ((dpi::pfwl_L7_worker *) state->L7_workers->back())->~pfwl_L7_worker();
        free((dpi::pfwl_L7_worker *) state->L7_workers->back());
        state->L7_workers->pop_back();
      }
      delete state->L7_workers;

      state->pipeline->~ff_pipeline();
      free(state->pipeline);
    } else {
      delete state->single_farm_emitter;
      delete state->single_farm;
      delete state->single_farm_collector;
      while (!state->single_farm_workers->empty()) {
        delete (dpi::pfwl_L7_worker *) state->single_farm_workers->back();
        state->single_farm_workers->pop_back();
      }
      delete state->single_farm_workers;
    }
    pfwl_terminate(state->sequential_state);

#if PFWL_MULTICORE_USE_TASKS_POOL
    state->tasks_pool->~SWSR_Ptr_Buffer();
    free(state->tasks_pool);
#endif
    delete[] state->mapping;
    free(state);
  }
}

void mc_pfwl_set_core_callbacks(
    mc_pfwl_state_t *state, mc_pfwl_packet_reading_callback *reading_callback,
    mc_pfwl_processing_result_callback *processing_callback, void *user_data) {
  state->reading_callback = reading_callback;
  state->processing_callback = processing_callback;
  state->read_process_callbacks_user_data = user_data;
}

#ifdef ENABLE_RECONFIGURATION
void mc_pfwl_set_reconf_parameters(mc_pfwl_library_state_t *state,
                                   nornir::Parameters *p) {
  state->adp_params = p;
}
#endif

void mc_pfwl_run(mc_pfwl_state_t *state) {
  // Real start
  debug_print("%s\n", "[mc_pfwl_peafowl.cpp]: Run preparation...");
  state->is_running = 1;
  if (state->parallel_module_type == MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM) {
    // Warm-up
    state->pipeline->run_then_freeze();
  } else {
// Warm-up
#ifdef ENABLE_RECONFIGURATION
    try {
      state->mf = new nornir::ManagerFarm<dpi::pfwl_L7_scheduler>(
          state->single_farm, *(state->adp_params));
      state->mf->start();
    } catch (std::exception &e) {
      assert("Exception thrown by ManagerFarm" == NULL);
    }
#else
    state->single_farm->run_then_freeze();
#endif
  }
  gettimeofday(&state->start_time, NULL);
  debug_print("%s\n", "[mc_pfwl_peafowl.cpp]: Running...");
}

/**
 * Wait the end of the data processing.
 * @param state A pointer to the state of the library.
 */
void mc_pfwl_wait_end(mc_pfwl_state_t *state) {
  if (state->parallel_module_type == MC_PFWL_PARALLELISM_FORM_DOUBLE_FARM) {
    state->pipeline->wait();
  } else {
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
  gettimeofday(&state->stop_time, NULL);
  state->is_running = 0;
}

uint8_t mc_pfwl_set_expected_flows(mc_pfwl_state_t *state, uint32_t flows_v4,
                                   uint32_t flows_v6, uint8_t strict) {
  if (state->is_running) {
    return 0;
  }
  return pfwl_set_expected_flows(state->sequential_state, flows_v4, flows_v6,
                                 strict);
}

uint8_t mc_pfwl_set_max_trials(mc_pfwl_state_t *state, uint16_t max_trials) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_set_max_trials(state->sequential_state, max_trials);
  return r;
}

uint8_t mc_pfwl_ipv4_fragmentation_enable(mc_pfwl_state_t *state,
                                          uint16_t table_size) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_enable_ipv4(state->sequential_state, table_size);
  return r;
}

uint8_t mc_pfwl_ipv6_fragmentation_enable(mc_pfwl_state_t *state,
                                          uint16_t table_size) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_enable_ipv6(state->sequential_state, table_size);
  return r;
}

uint8_t mc_pfwl_ipv4_fragmentation_set_per_host_memory_limit(
    mc_pfwl_state_t *state, uint32_t per_host_memory_limit) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_set_per_host_memory_limit_ipv4(
      state->sequential_state, per_host_memory_limit);
  return r;
}

uint8_t mc_pfwl_ipv6_fragmentation_set_per_host_memory_limit(
    mc_pfwl_state_t *state, uint32_t per_host_memory_limit) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_set_per_host_memory_limit_ipv6(
      state->sequential_state, per_host_memory_limit);
  return r;
}

uint8_t
mc_pfwl_ipv4_fragmentation_set_total_memory_limit(mc_pfwl_state_t *state,
                                                  uint32_t total_memory_limit) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_set_total_memory_limit_ipv4(state->sequential_state,
                                                       total_memory_limit);
  return r;
}

uint8_t
mc_pfwl_ipv6_fragmentation_set_total_memory_limit(mc_pfwl_state_t *state,
                                                  uint32_t total_memory_limit) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_set_total_memory_limit_ipv6(state->sequential_state,
                                                       total_memory_limit);
  return r;
}

uint8_t
mc_pfwl_ipv4_fragmentation_set_reassembly_timeout(mc_pfwl_state_t *state,
                                                  uint8_t timeout_seconds) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_set_reassembly_timeout_ipv4(state->sequential_state,
                                                       timeout_seconds);
  return r;
}

uint8_t
mc_pfwl_ipv6_fragmentation_set_reassembly_timeout(mc_pfwl_state_t *state,
                                                  uint8_t timeout_seconds) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_set_reassembly_timeout_ipv6(state->sequential_state,
                                                       timeout_seconds);
  return r;
}

uint8_t mc_pfwl_ipv4_fragmentation_disable(mc_pfwl_state_t *state) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_disable_ipv4(state->sequential_state);
  return r;
}

uint8_t mc_pfwl_ipv6_fragmentation_disable(mc_pfwl_state_t *state) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_defragmentation_disable_ipv6(state->sequential_state);
  return r;
}

uint8_t mc_pfwl_tcp_reordering_enable(mc_pfwl_state_t *state) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_tcp_reordering_enable(state->sequential_state);
  return r;
}

uint8_t mc_pfwl_tcp_reordering_disable(mc_pfwl_state_t *state) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_tcp_reordering_disable(state->sequential_state);
  return r;
}

uint8_t mc_pfwl_enable_protocol(mc_pfwl_state_t *state,
                                pfwl_protocol_l7_t protocol) {
  if (state->is_running) {
    return 0;
  }
  return pfwl_protocol_l7_enable(state->sequential_state, protocol);
}

uint8_t mc_pfwl_disable_protocol(mc_pfwl_state_t *state,
                                 pfwl_protocol_l7_t protocol) {
  if (state->is_running) {
    return 0;
  }
  return pfwl_protocol_l7_disable(state->sequential_state, protocol);
}

uint8_t mc_pfwl_inspect_all(mc_pfwl_state_t *state) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_protocol_l7_enable_all(state->sequential_state);
  return r;
}

uint8_t mc_pfwl_inspect_nothing(mc_pfwl_state_t *state) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_protocol_l7_disable_all(state->sequential_state);
  return r;
}

uint8_t
mc_pfwl_set_flow_cleaner_callback(mc_pfwl_state_t *state,
                                  pfwl_flow_cleaner_callback_t *cleaner) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_set_flow_cleaner_callback(state->sequential_state, cleaner);
  return r;
}

uint8_t mc_pfwl_http_activate_callbacks(mc_pfwl_state_t *state,
                                        pfwl_http_callbacks_t *callbacks,
                                        void *user_data) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_http_activate_callbacks(state->sequential_state, callbacks,
                                   user_data);
  return r;
}

uint8_t mc_pfwl_http_disable_callbacks(mc_pfwl_state_t *state) {
  if (state->is_running) {
    return 0;
  }
  uint8_t r;
  r = pfwl_http_disable_callbacks(state->sequential_state);
  return r;
}

const char **const mc_pfwl_get_protocol_strings() {
  return pfwl_get_L7_protocols_names();
}

const char *const mc_pfwl_get_protocol_string(pfwl_protocol_l7_t protocol) {
  return pfwl_get_L7_protocol_name(protocol);
}

pfwl_protocol_l7_t mc_pfwl_get_protocol_id(const char *const string) {
  return pfwl_get_L7_protocol_id(string);
}
