/*
 * worker.cpp
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

#include <ff/mapping_utils.hpp>
#include <peafowl/flow_table.h>
#include <peafowl/worker.hpp>

#include <math.h>
#include <pthread.h>
#include <stdexcept>
#include <stdlib.h>

#if PFWL_NUMA_AWARE
#include <numa.h>
#endif

namespace dpi {

#ifndef PFWL_DEBUG
static inline
#endif
    mc_pfwl_task_t *
    pfwl_allocate_task() {
  mc_pfwl_task_t *r;
#if PFWL_NUMA_AWARE
  r = (mc_pfwl_task_t *) numa_alloc_onnode(sizeof(mc_pfwl_task_t),
                                           PFWL_NUMA_AWARE_TASKS_NODE);
#else
#if PFWL_MULTICORE_ALIGN_TASKS
  if (posix_memalign((void **) &r, PFWL_CACHE_LINE_SIZE,
                     sizeof(mc_pfwl_task_t))) {
    throw std::runtime_error("posix_memalign failed.");
  }
#else
  r = new mc_pfwl_task_t;
#endif
#endif
  return r;
}

#ifndef PFWL_DEBUG
static inline
#endif
    void
    pfwl_free_task(mc_pfwl_task_t *task) {
#if PFWL_NUMA_AWARE
  numa_free(task, sizeof(mc_pfwl_task_t));
#else
#if PFWL_MULTICORE_ALIGN_TASKS
  free(task);
#else
  delete task;
#endif
#endif
}

/*****************************************************/
/*                      L3_L4 nodes.                 */
/*****************************************************/
pfwl_L3_L4_emitter::pfwl_L3_L4_emitter(pfwl_state_t *state,
                                       mc_pfwl_packet_reading_callback **cb,
                                       void **user_data, uint8_t *terminating,
                                       uint16_t proc_id,
                                       ff::SWSR_Ptr_Buffer *tasks_pool)
    : state(state), cb(cb), user_data(user_data), terminating(terminating),
      proc_id(proc_id), tasks_pool(tasks_pool), initialized(0) {
  ;
}

int pfwl_L3_L4_emitter::svc_init() {
  worker_debug_print("[worker.cpp]: L3_L4 emitter mapped on "
                     "processor: %d\n",
                     proc_id);
  ff_mapThreadToCpu(proc_id, -20);
  if (!initialized) {
/** Fill the task pool. **/
#if PFWL_MULTICORE_USE_TASKS_POOL
    for (uint i = 0; i < PFWL_MULTICORE_TASKS_POOL_SIZE; i++) {
      tasks_pool->push(pfwl_allocate_task());
    }
#endif
    initialized = 1;
  }
  return 0;
}

void *pfwl_L3_L4_emitter::svc(void *task) {
  mc_pfwl_packet_reading_result_t packet;
  mc_pfwl_task_t *r = NULL;

#if PFWL_MULTICORE_USE_TASKS_POOL
  if (!tasks_pool->empty()) {
    tasks_pool->pop((void **) &r);
  } else {
    r = pfwl_allocate_task();
  }
#else
  r = pfwl_allocate_task();
#endif

  for (uint i = 0; i < PFWL_MULTICORE_DEFAULT_GRAIN_SIZE; i++) {
    packet = (*(*cb))(*user_data);
    if (unlikely(packet.pkt == NULL)) {
      worker_debug_print("%s\n", "[worker.cpp]: No more task to "
                                 "process, terminating.");
      *terminating = 1;
      pfwl_free_task(r);
      return (void *) ff::FF_EOS;
    }

    r->input_output_task_t.L3_L4_input_task_t[i].user_pointer =
        packet.user_pointer;
    r->input_output_task_t.L3_L4_input_task_t[i].current_time =
        packet.current_time;
    r->input_output_task_t.L3_L4_input_task_t[i].length = packet.length;
    r->input_output_task_t.L3_L4_input_task_t[i].pkt = packet.pkt;
#if PFWL_MULTICORE_PREFETCH
    __builtin_prefetch(&(r->input_output_task_t.L3_L4_input_task_t[i + 5]), 1,
                       0);
#endif
  }
  return (void *) r;
}

pfwl_L3_L4_emitter::~pfwl_L3_L4_emitter() {
  ;
}

#ifdef ENABLE_RECONFIGURATION
void pfwl_L3_L4_emitter::notifyRethreading(size_t oldNumWorkers,
                                           size_t newNumWorkers) {
  worker_debug_print("%s\n", "[mc_pfwl_api.cpp]: Changing v4 table partitions");
  pfwl_flow_table_setup_partitions_v4((pfwl_flow_DB_v4_t *) state->db4,
                                      newNumWorkers);
  worker_debug_print("%s\n", "[mc_pfwl_api.cpp]: Changing v6 table partitions");
  pfwl_flow_table_setup_partitions_v6((pfwl_flow_DB_v6_t *) state->db6,
                                      newNumWorkers);
}
#endif

pfwl_L3_L4_worker::pfwl_L3_L4_worker(pfwl_state_t *state, uint16_t worker_id,
                                     uint16_t num_L7_workers, uint16_t proc_id,
                                     uint32_t v4_table_size,
                                     uint32_t v6_table_size)
    : state(state), v4_table_size(v4_table_size), v6_table_size(v6_table_size),
      worker_id(worker_id), proc_id(proc_id) {
  if (posix_memalign((void **) &in, PFWL_CACHE_LINE_SIZE,
                     sizeof(L3_L4_input_task_struct) *
                         PFWL_MULTICORE_DEFAULT_GRAIN_SIZE)) {
    throw std::runtime_error("posix_memalign failed.");
  }
  v4_worker_table_size = ceil((float) v4_table_size / (float) (num_L7_workers));
  v6_worker_table_size = ceil((float) v6_table_size / (float) (num_L7_workers));
}

pfwl_L3_L4_worker::~pfwl_L3_L4_worker() {
  free(in);
}

#ifdef ENABLE_RECONFIGURATION
void pfwl_L3_L4_worker::notifyRethreading(size_t oldNumWorkers,
                                          size_t newNumWorkers) {
  v4_worker_table_size = ceil((float) v4_table_size / (float) (newNumWorkers));
  v6_worker_table_size = ceil((float) v6_table_size / (float) (newNumWorkers));
  worker_debug_print("[worker.cpp]: L3_L4 worker. v4_worker_table_size: %d "
                     "v6_worker_table_size: %d\n",
                     v4_worker_table_size, v6_worker_table_size);
}
#endif

int pfwl_L3_L4_worker::svc_init() {
  worker_debug_print("[worker.cpp]: L3_L4 worker %d mapped "
                     "on processor: %d\n",
                     worker_id, proc_id);
  ff_mapThreadToCpu(proc_id, -20);
  return 0;
}

void *pfwl_L3_L4_worker::svc(void *task) {
  mc_pfwl_task_t *real_task = (mc_pfwl_task_t *) task;
  /**
   * Here we need a copy. Indeed, the task is a union and, if
   * we do not make the copy, we overwrite the input tasks with
   * the generated output tasks.
   **/
  memcpy(in, real_task->input_output_task_t.L3_L4_input_task_t,
         PFWL_MULTICORE_DEFAULT_GRAIN_SIZE * sizeof(L3_L4_input_task_struct));

  pfwl_pkt_info_t pkt_infos;
  for (uint i = 0; i < PFWL_MULTICORE_DEFAULT_GRAIN_SIZE; i++) {
#if PFWL_MULTICORE_PREFETCH
    __builtin_prefetch(&(in[i + 2]), 0, 0);
    __builtin_prefetch((in[i + 2]).pkt, 0, 0);
#endif

    real_task->input_output_task_t.L3_L4_output_task_t[i].status =
        mc_pfwl_parse_L3_header(this->state, in[i].pkt, in[i].length,
                                &pkt_infos, in[i].current_time, worker_id);

    /* To have always a consistent value temp L7 worker selection. */
    real_task->input_output_task_t.L3_L4_output_task_t[i].hash_result = 0;
    real_task->input_output_task_t.L3_L4_output_task_t[i].destination_worker =
        0;
    real_task->input_output_task_t.L3_L4_output_task_t[i].user_pointer =
        in[i].user_pointer;

    if (likely(real_task->input_output_task_t.L3_L4_output_task_t[i].status >=
               0)) {
      if (pkt_infos.protocol_l4 != IPPROTO_TCP &&
          pkt_infos.protocol_l4 != IPPROTO_UDP) {
        continue;
      }

      if (likely(real_task->input_output_task_t.L3_L4_output_task_t[i].status !=
                 PFWL_STATUS_IP_FRAGMENT)) {
        real_task->input_output_task_t.L3_L4_output_task_t[i].pkt_infos =
            pkt_infos;
        if (pkt_infos.ip_version == PFWL_PROTO_L3_IPV4) {
          real_task->input_output_task_t.L3_L4_output_task_t[i].hash_result =
              pfwl_compute_v4_hash_function(
                  (pfwl_flow_DB_v4 *) this->state->flow_table, &pkt_infos);
          real_task->input_output_task_t.L3_L4_output_task_t[i]
              .destination_worker =
              real_task->input_output_task_t.L3_L4_output_task_t[i]
                  .hash_result /
              v4_worker_table_size;
        } else {
          real_task->input_output_task_t.L3_L4_output_task_t[i].hash_result =
              pfwl_compute_v6_hash_function(
                  (pfwl_flow_DB_v6 *) this->state->db6, &pkt_infos);
          real_task->input_output_task_t.L3_L4_output_task_t[i]
              .destination_worker =
              real_task->input_output_task_t.L3_L4_output_task_t[i]
                  .hash_result /
              v6_worker_table_size;
        }
      }
    }
  }
  return real_task;
}

pfwl_L3_L4_collector::pfwl_L3_L4_collector(uint16_t proc_id)
    : proc_id(proc_id) {
  ;
}

int pfwl_L3_L4_collector::svc_init() {
  worker_debug_print("[worker.cpp]: L3_L4 collector mapped "
                     "on processor: %u\n",
                     proc_id);
  ff_mapThreadToCpu(proc_id, -20);
  return 0;
}

void *pfwl_L3_L4_collector::svc(void *task) {
  return task;
}

/*******************************************************************/
/*                          L7 nodes.                              */
/*******************************************************************/

pfwl_L7_emitter::pfwl_L7_emitter(pfwl_L7_scheduler *lb, uint16_t num_L7_workers,
                                 uint16_t proc_id)
    : proc_id(proc_id), lb(lb) {
  if (posix_memalign((void **) &partially_filled_sizes, PFWL_CACHE_LINE_SIZE,
                     (sizeof(uint) * num_L7_workers) + PFWL_CACHE_LINE_SIZE)) {
    throw std::runtime_error("posix_memalign failed.");
  }
  bzero(partially_filled_sizes, sizeof(uint) * num_L7_workers);

  if (posix_memalign((void **) &partially_filled, PFWL_CACHE_LINE_SIZE,
                     (sizeof(mc_pfwl_task_t) * num_L7_workers) +
                         PFWL_CACHE_LINE_SIZE)) {
    throw std::runtime_error("posix_memalign failed.");
  }
  bzero(partially_filled, sizeof(mc_pfwl_task_t) * num_L7_workers);

  if (posix_memalign((void **) &waiting_tasks, PFWL_CACHE_LINE_SIZE,
                     (sizeof(mc_pfwl_task_t *) * num_L7_workers * 2) +
                         PFWL_CACHE_LINE_SIZE)) {
    throw std::runtime_error("posix_memalign failed.");
  }

  waiting_tasks_size = 0;
  for (uint i = 0; i < num_L7_workers; i++) {
    waiting_tasks[i] = pfwl_allocate_task();
    ++waiting_tasks_size;
  }
}

pfwl_L7_emitter::~pfwl_L7_emitter() {
  free(partially_filled_sizes);
  free(partially_filled);
}

int pfwl_L7_emitter::svc_init() {
  worker_debug_print("[worker.cpp]: L7 emitter mapped "
                     "on processor: %d\n",
                     proc_id);
  ff_mapThreadToCpu(proc_id, -20);
  return 0;
}

void *pfwl_L7_emitter::svc(void *task) {
  mc_pfwl_task_t *real_task = (mc_pfwl_task_t *) task;
  mc_pfwl_task_t *out;
  uint pfs;

  for (uint i = 0; i < PFWL_MULTICORE_DEFAULT_GRAIN_SIZE; i++) {
#if PFWL_MULTICORE_PREFETCH
    __builtin_prefetch(
        &(real_task->input_output_task_t.L3_L4_output_task_t[i + 4]), 0, 0);
#endif
    uint16_t destination_worker =
        real_task->input_output_task_t.L3_L4_output_task_t[i]
            .destination_worker;
    worker_debug_print("[worker.cpp]: L7 emitter: Inserted"
                       " a task into the queue of worker: "
                       "%d\n",
                       destination_worker);
    pfs = partially_filled_sizes[destination_worker];
#if PFWL_MULTICORE_PREFETCH
    __builtin_prefetch(&(partially_filled[destination_worker]
                             .input_output_task_t.L3_L4_output_task_t[pfs]),
                       1, 0);
#endif

    if (pfs + 1 == PFWL_MULTICORE_DEFAULT_GRAIN_SIZE) {
      assert(waiting_tasks_size != 0);
      out = waiting_tasks[--waiting_tasks_size];
      memcpy(out->input_output_task_t.L3_L4_output_task_t,
             partially_filled[destination_worker]
                 .input_output_task_t.L3_L4_output_task_t,
             sizeof(L3_L4_output_task_struct) *
                 (PFWL_MULTICORE_DEFAULT_GRAIN_SIZE - 1));
      out->input_output_task_t
          .L3_L4_output_task_t[PFWL_MULTICORE_DEFAULT_GRAIN_SIZE - 1] =
          real_task->input_output_task_t.L3_L4_output_task_t[i];
      lb->set_victim(destination_worker);
      while (ff_send_out((void *) out, -1, SPINTICKS) == false)
        ;
      partially_filled_sizes[destination_worker] = 0;
    } else {
      partially_filled[destination_worker]
          .input_output_task_t.L3_L4_output_task_t[pfs] =
          real_task->input_output_task_t.L3_L4_output_task_t[i];
      ++partially_filled_sizes[destination_worker];
    }
  }
  waiting_tasks[waiting_tasks_size] = real_task;
  ++waiting_tasks_size;
  return (void *) ff::FF_GO_ON;
}

pfwl_L7_worker::pfwl_L7_worker(pfwl_state_t *state, uint16_t worker_id,
                               uint16_t proc_id)
    : state(state), worker_id(worker_id), proc_id(proc_id) {
  if (posix_memalign((void **) &this->temp, PFWL_CACHE_LINE_SIZE,
                     (sizeof(L3_L4_output_task_struct) *
                      PFWL_MULTICORE_DEFAULT_GRAIN_SIZE) +
                         PFWL_CACHE_LINE_SIZE)) {
    throw std::runtime_error("posix_memalign failed.");
  }
}

pfwl_L7_worker::~pfwl_L7_worker() {
  free(temp);
}

int pfwl_L7_worker::svc_init() {
  worker_debug_print("[worker.cpp]: L7 worker %u mapped on"
                     " processor: %u. Tid: %lu\n",
                     worker_id, proc_id, pthread_self());
  ff_mapThreadToCpu(proc_id, -20);
  return 0;
}

void *pfwl_L7_worker::svc(void *task) {
  mc_pfwl_task_t *real_task = (mc_pfwl_task_t *) task;
  pfwl_pkt_info_t infos;
  pfwl_flow_info_t *flow_infos = NULL;

#if MC_PFWL_TICKS_WAIT == 1
  ticks svcstart = getticks();
#endif
  memcpy(temp, real_task->input_output_task_t.L3_L4_output_task_t,
         PFWL_MULTICORE_DEFAULT_GRAIN_SIZE * sizeof(L3_L4_output_task_struct));
  worker_debug_print("[worker.cpp]: L7 worker %d received task\n", worker_id);

  for (uint i = 0; i < PFWL_MULTICORE_DEFAULT_GRAIN_SIZE; i++) {
    real_task->input_output_task_t.L7_output_task_t[i].user_pointer =
        temp[i].user_pointer;
    pfwl_flow_t *ipv4_flow = NULL;
    pfwl_flow_t *ipv6_flow = NULL;

    int8_t l3_status = temp[i].status;
    if (unlikely(l3_status < 0 || l3_status == PFWL_STATUS_IP_FRAGMENT)) {
      real_task->input_output_task_t.L7_output_task_t[i].result.status =
          l3_status;
      continue;
    }
    infos = temp[i].pkt_infos;
#if PFWL_MULTICORE_PREFETCH
    __builtin_prefetch(
        temp[i + 1].pkt_infos.pkt + temp[i + 1].pkt_infos.l7offset, 0, 0);
#endif

    if (infos.ip_version == PFWL_PROTO_L3_IPV4) {
      ipv4_flow = mc_pfwl_flow_table_find_or_create_flow(
          state, this->worker_id, temp[i].hash_result, &(infos));
      if (ipv4_flow)
        flow_infos = &(ipv4_flow->infos);
    } else {
      ipv6_flow = mc_pfwl_flow_table_find_or_create_flow(
          state, this->worker_id, temp[i].hash_result, &(infos));
      if (ipv6_flow)
        flow_infos = &(ipv6_flow->infos);
    }

    real_task->input_output_task_t.L7_output_task_t[i].result.status =
        PFWL_STATUS_OK;
    if (unlikely(flow_infos == NULL)) {
      real_task->input_output_task_t.L7_output_task_t[i].result.status =
          PFWL_ERROR_MAX_FLOWS;
      if (unlikely(l3_status == PFWL_STATUS_IP_DATA_REBUILT)) {
        free((unsigned char *) infos.pkt);
      }
      break;
    } else {
      real_task->input_output_task_t.L7_output_task_t[i].result =
          pfwl_dissect_L7(state, flow_infos, &(infos));
      if (real_task->input_output_task_t.L7_output_task_t[i].result.status ==
          PFWL_STATUS_TCP_CONNECTION_TERMINATED) {
        if (ipv4_flow != NULL) {
          mc_pfwl_flow_table_delete_flow(
              (pfwl_flow_table_t *) state->flow_table,
              state->flow_cleaner_callback, this->worker_id, ipv4_flow);
        } else {
          mc_pfwl_flow_table_delete_flow((pfwl_flow_table_t *) state->db6,
                                         state->flow_cleaner_callback,
                                         this->worker_id, ipv6_flow);
        }
      }

      if (unlikely(l3_status == PFWL_STATUS_IP_DATA_REBUILT)) {
        free((unsigned char *) infos.pkt);
      }
    }
  }
  return real_task;
}

pfwl_L7_collector::pfwl_L7_collector(mc_pfwl_processing_result_callback **cb,
                                     void **user_data, uint16_t *proc_id,
                                     ff::SWSR_Ptr_Buffer *tasks_pool)
    : cb(cb), user_data(user_data), proc_id(proc_id), tasks_pool(tasks_pool) {
  ;
}

int pfwl_L7_collector::svc_init() {
  worker_debug_print("[worker.cpp]: L7 collector"
                     " mapped on processor: %u\n",
                     *proc_id);
  ff_mapThreadToCpu(*proc_id, -20);
  return 0;
}

void *pfwl_L7_collector::svc(void *task) {
  mc_pfwl_processing_result_t r;
  mc_pfwl_task_t *real_task = (mc_pfwl_task_t *) task;

  for (uint i = 0; i < PFWL_MULTICORE_DEFAULT_GRAIN_SIZE; i++) {
    r.result = real_task->input_output_task_t.L7_output_task_t[i].result;
    r.user_pointer =
        real_task->input_output_task_t.L7_output_task_t[i].user_pointer;
    (*(*cb))(&r, *user_data);
  }
#if PFWL_MULTICORE_USE_TASKS_POOL
  if (tasks_pool->available()) {
    tasks_pool->push(task);
  } else {
    pfwl_free_task(real_task);
  }
#else
  pfwl_free_task(real_task);
#endif
  return (void *) ff::FF_GO_ON;
}

pfwl_L7_collector::~pfwl_L7_collector() {
#if PFWL_MULTICORE_USE_TASKS_POOL
  mc_pfwl_task_t *task = NULL;
  while (!tasks_pool->empty()) {
    tasks_pool->pop((void **) &task);
    pfwl_free_task(task);
  }
#endif
}

pfwl_collapsed_emitter::pfwl_collapsed_emitter(
    mc_pfwl_packet_reading_callback **cb, void **user_data,
    uint8_t *terminating, ff::SWSR_Ptr_Buffer *tasks_pool, pfwl_state_t *state,
    uint16_t num_L7_workers, uint32_t v4_table_size, uint32_t v6_table_size,
    pfwl_L7_scheduler *lb, uint16_t proc_id)
    : pfwl_L7_emitter(lb, num_L7_workers, proc_id), proc_id(proc_id) {
  L3_L4_emitter = new dpi::pfwl_L3_L4_emitter(state, cb, user_data, terminating,
                                              proc_id, tasks_pool);
  L3_L4_worker = new dpi::pfwl_L3_L4_worker(state, 0, num_L7_workers, proc_id,
                                            v4_table_size, v6_table_size);
}

pfwl_collapsed_emitter::~pfwl_collapsed_emitter() {
  delete L3_L4_emitter;
  delete L3_L4_worker;
}

#ifdef ENABLE_RECONFIGURATION
void pfwl_collapsed_emitter::notifyRethreading(size_t oldNumWorkers,
                                               size_t newNumWorkers) {
  L3_L4_emitter->notifyRethreading(oldNumWorkers, newNumWorkers);
  L3_L4_worker->notifyRethreading(oldNumWorkers, newNumWorkers);
}
#endif

int pfwl_collapsed_emitter::svc_init() {
  L3_L4_emitter->svc_init();
  L3_L4_worker->svc_init();
  pfwl_L7_emitter::svc_init();
  worker_debug_print("[worker.cpp]: collapsed emitter mapped "
                     "on processor: %d\n",
                     proc_id);
  return 0;
}

void *pfwl_collapsed_emitter::svc(void *task) {
  void *r = L3_L4_emitter->svc(task);
  if (unlikely(r == (void *) ff::FF_EOS || r == NULL)) {
    return r;
  } else {
    r = L3_L4_worker->svc(r);
    return pfwl_L7_emitter::svc(r);
  }
}
} // namespace dpi
