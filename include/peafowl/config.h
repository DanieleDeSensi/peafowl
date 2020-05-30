
/*
 * config.h
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

#ifndef CONFIG_H_
#define CONFIG_H_

#define PFWL_CACHE_LINE_SIZE 64

/*******************************************************************/
/*                  Performance related macros.                    */
/*******************************************************************/
#ifndef PFWL_NUMA_AWARE
#define PFWL_NUMA_AWARE 0
#define PFWL_NUMA_AWARE_FLOW_TABLE_NODE 1
#endif

#ifndef PFWL_USE_MTF
#define PFWL_USE_MTF 1
#endif

#ifndef PFWL_FLOW_TABLE_ALIGN_FLOWS
#define PFWL_FLOW_TABLE_ALIGN_FLOWS 0
#endif

#ifndef PFWL_USE_LIKELY
#define PFWL_USE_LIKELY 1
#endif

#ifndef PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE
#define PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE 8
#endif

#ifndef PFWL_DEFAULT_EXPECTED_IPv4_FLOWS
#define PFWL_DEFAULT_EXPECTED_FLOWS 262143
#endif

#if !defined(likely)
#if defined(__GNUC__) && (PFWL_USE_LIKELY == 1)
#define likely(x) __builtin_expect(!!(x), 1)
#else
#define likely(x) (x)
#endif
#endif

#if !defined(unlikely)
#if defined(__GNUC__) && (PFWL_USE_LIKELY == 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define unlikely(x) (x)
#endif
#endif

#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) ||              \
    defined(__cplusplus)
#define PFWL_USE_INLINING 1
#else
#error "A compiler which supports at least C99 is needed"
#endif

/*******************************************************************/
/*                    Protocol specific macros.                    */
/*******************************************************************/
#ifndef PFWL_HTTP_MAX_HEADERS
#define PFWL_HTTP_MAX_HEADERS 256
#endif

/*******************************************************************/
/*                       Functional macros.                        */
/*******************************************************************/
#define PFWL_DEFAULT_MAX_TRIALS_PER_FLOW 0

#define PFWL_MAX_CPU_SOCKETS 8

#define PFWL_ENABLE_L3_TRUNCATION_PROTECTION
#define PFWL_ENABLE_L4_TRUNCATION_PROTECTION

#ifndef PFWL_FLOW_TABLE_USE_MEMORY_POOL
#define PFWL_FLOW_TABLE_USE_MEMORY_POOL 0
#endif

#if PFWL_FLOW_TABLE_USE_MEMORY_POOL
#define PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4 500000
#define PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6 100
#endif

#define PFWL_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE 512
#define PFWL_IPv4_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT                  \
  102400 /* 100K                                                               \
          */
#define PFWL_IPv4_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT                     \
  10240000 /* 10M. If each host fills its memory limit, we can support up to   \
              1000 hosts. */
#define PFWL_IPv4_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT 30

#define PFWL_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE 512
#define PFWL_IPv6_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT                  \
  102400 /* 100K                                                               \
          */
#define PFWL_IPv6_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT                     \
  10240000 /* 10M. If each host fills its memory limit, we can support up to   \
              1000 hosts. */
#define PFWL_IPv6_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT 60

/** Hash functions choice. **/
#define PFWL_SIMPLE_HASH 0
#define PFWL_FNV_HASH 1
#define PFWL_MURMUR3_HASH 2
#define PFWL_BKDR_HASH 3

#ifndef PFWL_FLOW_TABLE_HASH_VERSION
#define PFWL_FLOW_TABLE_HASH_VERSION PFWL_SIMPLE_HASH
#endif

#define PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE 1

#ifndef PFWL_THREAD_SAFETY_ENABLED
#define PFWL_THREAD_SAFETY_ENABLED 0
#endif

#ifndef PFWL_MAX_SPLT_LENGTH
#define PFWL_MAX_SPLT_LENGTH 10
#endif

#define __STDC_FORMAT_MACROS // To enable inttypes.h macros also for g++

/******************************************************************/
/* Configuration macros for multicore version.                    */
/* Change their value ONLY IF you really know what you are doing. */
/******************************************************************/

#if PFWL_NUMA_AWARE
#define PFWL_NUMA_AWARE_TASKS_NODE 0
#define PFWL_NUMA_AWARE_PACKETS_NODE 0
#endif

#define PFWL_MULTICORE_DEFAULT_GRAIN_SIZE 1 // 256

#ifndef PFWL_MULTICORE_USE_TASKS_POOL
#define PFWL_MULTICORE_USE_TASKS_POOL 1
#endif
#define PFWL_MULTICORE_TASKS_POOL_SIZE 16384

#ifndef PFWL_MULTICORE_PREFETCH
#define PFWL_MULTICORE_PREFETCH 0
#endif

#ifndef PFWL_MULTICORE_ALIGN_TASKS
#define PFWL_MULTICORE_ALIGN_TASKS 1
#endif

#define PFWL_MULTICORE_L3_L4_ORDERED_FARM 0
#define PFWL_MULTICORE_L3_L4_NOT_ORDERED_FARM 1
#define PFWL_MULTICORE_L3_L4_ON_DEMAND 2

#ifndef PFWL_MULTICORE_L3_L4_FARM_TYPE
#define PFWL_MULTICORE_L3_L4_FARM_TYPE PFWL_MULTICORE_L3_L4_ORDERED_FARM
#endif

#ifndef PFWL_MULTICORE_DEFAULT_BUFFER_SIZE
#define PFWL_MULTICORE_DEFAULT_BUFFER_SIZE 32768
#endif

#ifndef PFWL_MULTICORE_L3_L4_FARM_INPUT_BUFFER_SIZE
#define PFWL_MULTICORE_L3_L4_FARM_INPUT_BUFFER_SIZE                            \
  PFWL_MULTICORE_DEFAULT_BUFFER_SIZE
#endif

#ifndef PFWL_MULTICORE_L3_L4_FARM_OUTPUT_BUFFER_SIZE
#define PFWL_MULTICORE_L3_L4_FARM_OUTPUT_BUFFER_SIZE                           \
  PFWL_MULTICORE_DEFAULT_BUFFER_SIZE
#endif

#ifndef PFWL_MULTICORE_L7_FARM_INPUT_BUFFER_SIZE
#define PFWL_MULTICORE_L7_FARM_INPUT_BUFFER_SIZE                               \
  PFWL_MULTICORE_DEFAULT_BUFFER_SIZE
#endif

#ifndef PFWL_MULTICORE_L7_FARM_OUTPUT_BUFFER_SIZE
#define PFWL_MULTICORE_L7_FARM_OUTPUT_BUFFER_SIZE                              \
  PFWL_MULTICORE_DEFAULT_BUFFER_SIZE
#endif

#ifndef PFWL_MULTICORE_PIPELINE_INPUT_BUFFER_SIZE
#define PFWL_MULTICORE_PIPELINE_INPUT_BUFFER_SIZE                              \
  PFWL_MULTICORE_DEFAULT_BUFFER_SIZE
#endif

#ifndef PFWL_MULTICORE_PIPELINE_OUTPUT_BUFFER_SIZE
#define PFWL_MULTICORE_PIPELINE_OUTPUT_BUFFER_SIZE                             \
  PFWL_MULTICORE_DEFAULT_BUFFER_SIZE
#endif

#ifndef MC_PFWL_TICKS_WAIT
#define MC_PFWL_TICKS_WAIT 0
#endif

#ifndef MC_PFWL_AVG_RHO
#define MC_PFWL_AVG_RHO 0
#endif

#ifndef MC_PFWL_POWER_USE_MODEL
#define MC_PFWL_POWER_USE_MODEL 1
#endif

#ifndef SPINTICKS
#define SPINTICKS 1000
#endif

#endif /* CONFIG_H_ */
