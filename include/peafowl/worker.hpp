/*
 * worker.hpp
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

#ifndef WORKER_HPP_
#define WORKER_HPP_

#include <peafowl/config.h>
#include <peafowl/peafowl.h>
#include <peafowl/peafowl_mc.h>

#include <ff/farm.hpp>
#include <ff/svector.hpp>

#ifdef ENABLE_RECONFIGURATION
typedef nornir::AdaptiveNode ffnode;
#else
typedef ff::ff_node ffnode;
#endif

#define PFWL_DEBUG_MP_WORKER 0
#define worker_debug_print(fmt, ...)                                           \
  do {                                                                         \
    if (PFWL_DEBUG_MP_WORKER)                                                  \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

namespace dpi {

typedef struct L3_L4_input_task {
  const unsigned char *pkt;
  uint32_t length;
  uint32_t current_time;
  void *user_pointer;
} L3_L4_input_task_struct;

typedef struct L3_L4_output_task {
  uint32_t hash_result;
  uint16_t destination_worker;
  uint8_t status;
  pfwl_pkt_info_t pkt_infos;
  void *user_pointer;
} L3_L4_output_task_struct;

typedef struct L7_output_task {
  pfwl_dissection_info_t result;
  void *user_pointer;
} L7_output_task_struct;

#define PFWL_CACHE_LINES_PADDING_REQUIRED(size)                                \
  (size % PFWL_CACHE_LINE_SIZE == 0 ? 0 : PFWL_CACHE_LINE_SIZE -               \
                                              (size % PFWL_CACHE_LINE_SIZE))

typedef struct mc_pfwl_task {
  union input_output_task {
    L3_L4_input_task_struct
        L3_L4_input_task_t[PFWL_MULTICORE_DEFAULT_GRAIN_SIZE];
    L3_L4_output_task_struct
        L3_L4_output_task_t[PFWL_MULTICORE_DEFAULT_GRAIN_SIZE];
    L7_output_task_struct L7_output_task_t[PFWL_MULTICORE_DEFAULT_GRAIN_SIZE];
  } input_output_task_t;
  char padding[PFWL_CACHE_LINES_PADDING_REQUIRED(sizeof(input_output_task_t))];
} mc_pfwl_task_t;

/*****************************************************/
/*                      L3_L4 nodes.                 */
/*****************************************************/

class pfwl_L3_L4_emitter : public ffnode {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  pfwl_state_t *const state;
  mc_pfwl_packet_reading_callback **const cb;
  void **user_data;
  uint8_t *terminating;
  const uint16_t proc_id;
  ff::SWSR_Ptr_Buffer *tasks_pool;
  uint8_t initialized;
  char padding2[PFWL_CACHE_LINE_SIZE];

public:
  pfwl_L3_L4_emitter(pfwl_state_t *state, mc_pfwl_packet_reading_callback **cb,
                     void **user_data, uint8_t *terminating, uint16_t proc_id,
                     ff::SWSR_Ptr_Buffer *tasks_pool);
  ~pfwl_L3_L4_emitter();
#ifdef ENABLE_RECONFIGURATION
  void notifyRethreading(size_t oldNumWorkers, size_t newNumWorkers);
#endif
  int svc_init();
  void *svc(void *);
};

class pfwl_L3_L4_worker : public ffnode {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  pfwl_state_t *const state;
  L3_L4_input_task_struct *in;
  const uint32_t v4_table_size;
  const uint32_t v6_table_size;
  uint32_t v4_worker_table_size;
  uint32_t v6_worker_table_size;
  const uint16_t worker_id;
  const uint16_t proc_id;
  char padding2[PFWL_CACHE_LINE_SIZE];

public:
  pfwl_L3_L4_worker(pfwl_state_t *state, uint16_t worker_id,
                    uint16_t num_L7_workers, uint16_t proc_id,
                    uint32_t v4_table_size, uint32_t v6_table_size);
  ~pfwl_L3_L4_worker();

  int svc_init();
  void *svc(void *);
#ifdef ENABLE_RECONFIGURATION
  void notifyRethreading(size_t oldNumWorkers, size_t newNumWorkers);
#endif
};

class pfwl_L3_L4_collector : public ffnode {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  const uint16_t proc_id;
  char padding2[PFWL_CACHE_LINE_SIZE];

public:
  pfwl_L3_L4_collector(uint16_t proc_id);

  int svc_init();
  void *svc(void *);
};

/*****************************************************/
/*                        L7 nodes.                  */
/*****************************************************/

class pfwl_L7_scheduler : public ff::ff_loadbalancer {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  int victim;
  char padding2[PFWL_CACHE_LINE_SIZE];

protected:
  inline size_t selectworker() {
    worker_debug_print("[worker.hpp]: select_worker: %u\n", victim);
    return victim;
  }

public:
  pfwl_L7_scheduler(int max_num_workers)
      : ff_loadbalancer(max_num_workers), victim(0) {
  }

  void set_victim(int v) {
    victim = v;
    worker_debug_print("[worker.hpp]: set_victim: %u\n", victim);
  }
};

class pfwl_L7_emitter : public ffnode {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  mc_pfwl_task_t *partially_filled;
  uint *partially_filled_sizes;
  mc_pfwl_task_t **waiting_tasks;
  uint16_t waiting_tasks_size;
  const uint16_t proc_id;
  char padding2[PFWL_CACHE_LINE_SIZE];

protected:
  pfwl_L7_scheduler *const lb;

public:
  pfwl_L7_emitter(pfwl_L7_scheduler *lb, uint16_t num_L7_workers,
                  uint16_t proc_id);
  ~pfwl_L7_emitter();
  int svc_init();
  void *svc(void *task);
};

static inline void sleepns(unsigned long ns) {
  struct timespec req = {0, static_cast<long>(ns)};
  nanosleep(&req, NULL);
}

static inline unsigned long getns() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (unsigned long) (tv.tv_sec * 1e6 + tv.tv_usec) * 1000;
}

class pfwl_L7_worker : public ffnode {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  pfwl_state_t *const state;
  L3_L4_output_task_struct *temp;
  const uint16_t worker_id;
  const uint16_t proc_id;

  char padding2[PFWL_CACHE_LINE_SIZE];

public:
  pfwl_L7_worker(pfwl_state_t *state, uint16_t worker_id, uint16_t proc_id);
  ~pfwl_L7_worker();

  int svc_init();
  void *svc(void *);
};

class pfwl_L7_collector : public ffnode {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  mc_pfwl_processing_result_callback **const cb;
  void **user_data;
  uint16_t *proc_id;
  ff::SWSR_Ptr_Buffer *tasks_pool;
  char padding2[PFWL_CACHE_LINE_SIZE];

public:
  pfwl_L7_collector(mc_pfwl_processing_result_callback **cb, void **user_data,
                    uint16_t *proc_id, ff::SWSR_Ptr_Buffer *tasks_pool);
  ~pfwl_L7_collector();

  int svc_init();
  void *svc(void *);
};

class pfwl_collapsed_emitter : public dpi::pfwl_L7_emitter {
private:
  char padding1[PFWL_CACHE_LINE_SIZE];
  pfwl_L3_L4_emitter *L3_L4_emitter;
  pfwl_L3_L4_worker *L3_L4_worker;
  uint16_t proc_id;
  char padding2[PFWL_CACHE_LINE_SIZE];

public:
  pfwl_collapsed_emitter(mc_pfwl_packet_reading_callback **cb, void **user_data,
                         uint8_t *terminating, ff::SWSR_Ptr_Buffer *tasks_pool,
                         pfwl_state_t *state, uint16_t num_L7_workers,
                         uint32_t v4_table_size, uint32_t v6_table_size,
                         pfwl_L7_scheduler *lb, uint16_t proc_id);
  ~pfwl_collapsed_emitter();
  int svc_init();
  void *svc(void *);
#ifdef ENABLE_RECONFIGURATION
  void notifyRethreading(size_t oldNumWorkers, size_t newNumWorkers);
#endif
};
} // namespace dpi

#endif /* WORKER_HPP_ */
