/*
 * worker.hpp
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

#ifndef WORKER_HPP_
#define WORKER_HPP_

#include "api.h"
#include "mc_api.h"
#include "config.h"

#include <ff/farm.hpp>
#include <ff/svector.hpp>

#ifdef ENABLE_RECONFIGURATION
typedef nornir::AdaptiveNode ffnode;
#else
typedef ff::ff_node ffnode;
#endif

#define DPI_DEBUG_MP_WORKER 0
#define worker_debug_print(fmt, ...)      \
            do { if (DPI_DEBUG_MP_WORKER) \
            fprintf(stdout, fmt, __VA_ARGS__); } while (0)

namespace dpi{

typedef struct L3_L4_input_task{
	const unsigned char* pkt;
	u_int32_t length;
	u_int32_t current_time;
	void* user_pointer;
}L3_L4_input_task_struct;

typedef struct L3_L4_output_task{
	u_int32_t hash_result;
	u_int16_t destination_worker;
	int8_t status;
	dpi_pkt_infos_t pkt_infos;
	void* user_pointer;
}L3_L4_output_task_struct;


typedef struct L7_output_task{
	dpi_identification_result_t result;
	void* user_pointer;
}L7_output_task_struct;

#define DPI_CACHE_LINES_PADDING_REQUIRED(size)             \
	    (size%DPI_CACHE_LINE_SIZE==0?0:DPI_CACHE_LINE_SIZE \
	     -(size%DPI_CACHE_LINE_SIZE))


typedef struct mc_dpi_task{
	union input_output_task{
		L3_L4_input_task_struct
			L3_L4_input_task_t[DPI_MULTICORE_DEFAULT_GRAIN_SIZE];
		L3_L4_output_task_struct
			L3_L4_output_task_t[DPI_MULTICORE_DEFAULT_GRAIN_SIZE];
		L7_output_task_struct
			L7_output_task_t[DPI_MULTICORE_DEFAULT_GRAIN_SIZE];
	}input_output_task_t;
	char padding[DPI_CACHE_LINES_PADDING_REQUIRED(
			sizeof(input_output_task_t))];
}mc_dpi_task_t;


/*****************************************************/
/*                      L3_L4 nodes.                 */
/*****************************************************/

class dpi_L3_L4_emitter: public ffnode{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
        dpi_library_state_t* const state;
	mc_dpi_packet_reading_callback** const cb;
	void** user_data;
	u_int8_t* terminating;
	const u_int16_t proc_id;
	ff::SWSR_Ptr_Buffer* tasks_pool;
	u_int8_t initialized;
	char padding2[DPI_CACHE_LINE_SIZE];
public:
        dpi_L3_L4_emitter(dpi_library_state_t* state,
                          mc_dpi_packet_reading_callback** cb,
			          void** user_data,
			          u_int8_t* terminating,
			          u_int16_t proc_id,
			          ff::SWSR_Ptr_Buffer* tasks_pool);
	~dpi_L3_L4_emitter();
#ifdef ENABLE_RECONFIGURATION
        void notifyRethreading(size_t oldNumWorkers, size_t newNumWorkers);
#endif
	int svc_init();
	void* svc(void*);
};



class dpi_L3_L4_worker: public ffnode{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
	dpi_library_state_t* const state;
	L3_L4_input_task_struct* in;
	const u_int32_t v4_table_size;
	const u_int32_t v6_table_size;
	u_int32_t v4_worker_table_size;
	u_int32_t v6_worker_table_size;
	const u_int16_t worker_id;
	const u_int16_t proc_id;
	char padding2[DPI_CACHE_LINE_SIZE];
public:
	dpi_L3_L4_worker(dpi_library_state_t* state,
						u_int16_t worker_id,
						u_int16_t num_L7_workers,
						u_int16_t proc_id,
						u_int32_t v4_table_size,
						u_int32_t v6_table_size);
	~dpi_L3_L4_worker();

	int svc_init();
	void* svc(void*);
#ifdef ENABLE_RECONFIGURATION
    void notifyRethreading(size_t oldNumWorkers, size_t newNumWorkers);
#endif
};

class dpi_L3_L4_collector: public ffnode{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
	const u_int16_t proc_id;
	char padding2[DPI_CACHE_LINE_SIZE];
public:
	dpi_L3_L4_collector(u_int16_t proc_id);

	int svc_init();
	void* svc(void*);
};


/*****************************************************/
/*                        L7 nodes.                  */
/*****************************************************/

class dpi_L7_scheduler: public ff::ff_loadbalancer{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
	int victim;
	char padding2[DPI_CACHE_LINE_SIZE];
protected:
	inline size_t selectworker(){
		worker_debug_print("[worker.hpp]: select_worker: %u\n",
				           victim);
		return victim;
	}
public:
	dpi_L7_scheduler(int max_num_workers):
		ff_loadbalancer(max_num_workers), victim(0){}

	void set_victim(int v){
		victim=v;
		worker_debug_print("[worker.hpp]: set_victim: %u\n",
				           victim);
	}
};


class dpi_L7_emitter: public ffnode{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
	mc_dpi_task_t* partially_filled;
	uint* partially_filled_sizes;
	mc_dpi_task_t** waiting_tasks;
	u_int16_t waiting_tasks_size;
	const u_int16_t proc_id;
	char padding2[DPI_CACHE_LINE_SIZE];
protected:
	dpi_L7_scheduler* const lb;
public:
	dpi_L7_emitter(dpi_L7_scheduler* lb,
			       u_int16_t num_L7_workers,
			       u_int16_t proc_id);
	~dpi_L7_emitter();
	int svc_init();
	void* svc(void* task);
};

static inline void sleepns(unsigned long ns) {
	struct timespec req = {0, static_cast<long>(ns)};
	nanosleep(&req, NULL);
}

static inline unsigned long getns() {
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return (unsigned long)(tv.tv_sec*1e6+tv.tv_usec)*1000;
}


class dpi_L7_worker: public ffnode{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
	dpi_library_state_t* const state;
	L3_L4_output_task_struct* temp;
	const u_int16_t worker_id;
	const u_int16_t proc_id;

	char padding2[DPI_CACHE_LINE_SIZE];
public:
	dpi_L7_worker(dpi_library_state_t* state,
			      u_int16_t worker_id,
			      u_int16_t proc_id);
	~dpi_L7_worker();

	int svc_init();
	void* svc(void*);
};


class dpi_L7_collector: public ffnode{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
	mc_dpi_processing_result_callback** const cb;
	void** user_data;
	u_int16_t* proc_id;
	ff::SWSR_Ptr_Buffer* tasks_pool;
	char padding2[DPI_CACHE_LINE_SIZE];
public:
	dpi_L7_collector(mc_dpi_processing_result_callback** cb,
			         void** user_data, u_int16_t* proc_id,
			         ff::SWSR_Ptr_Buffer* tasks_pool);
        ~dpi_L7_collector();

	int svc_init();
	void* svc(void*);
};


class dpi_collapsed_emitter: public dpi::dpi_L7_emitter{
private:
	char padding1[DPI_CACHE_LINE_SIZE];
	dpi_L3_L4_emitter* L3_L4_emitter;
	dpi_L3_L4_worker* L3_L4_worker;
	u_int16_t proc_id;
	char padding2[DPI_CACHE_LINE_SIZE];
public:
	dpi_collapsed_emitter(mc_dpi_packet_reading_callback** cb,
			              void** user_data,
			              u_int8_t* terminating,
			              ff::SWSR_Ptr_Buffer* tasks_pool,
			              dpi_library_state_t* state,
			              u_int16_t num_L7_workers,
			              u_int32_t v4_table_size,
			              u_int32_t v6_table_size,
			              dpi_L7_scheduler* lb,
			              u_int16_t proc_id);
	~dpi_collapsed_emitter();
	int svc_init();
	void* svc(void*);
#ifdef ENABLE_RECONFIGURATION
    void notifyRethreading(size_t oldNumWorkers, size_t newNumWorkers);
#endif
};

}


#endif /* WORKER_HPP_ */
