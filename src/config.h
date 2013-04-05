/*
 *  config.h
 *
 *  Created on: 23/09/2012
 *
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

#ifndef CONFIG_H_
#define CONFIG_H_

#define DPI_CACHE_LINE_SIZE 64

/*******************************************************************/
/*                  Performance related macros.                    */
/*******************************************************************/
#ifndef DPI_NUMA_AWARE
#define DPI_NUMA_AWARE 0
#define DPI_NUMA_AWARE_FLOW_TABLE_NODE 1
#endif

#ifndef DPI_USE_MTF
#define DPI_USE_MTF 1
#endif

#ifndef DPI_FLOW_TABLE_ALIGN_FLOWS
#define DPI_FLOW_TABLE_ALIGN_FLOWS 0
#endif

#define DPI_USE_LIKELY 1

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
   #define DPI_USE_INLINING 1
#else
   #define DPI_USE_INLINING 0 /** Must always be == 0, 'inline' keyword has been introduced only in C99. **/
#endif



/*******************************************************************/
/*                       Functional macros.                        */
/*******************************************************************/
#define DPI_DEFAULT_MAX_TRIALS_PER_FLOW 0

#define DPI_ENABLE_L3_TRUNCATION_PROTECTION
#define DPI_ENABLE_L4_TRUNCATION_PROTECTION

#ifndef DPI_FLOW_TABLE_USE_MEMORY_POOL
#define DPI_FLOW_TABLE_USE_MEMORY_POOL 0
#endif

#if DPI_FLOW_TABLE_USE_MEMORY_POOL
#define DPI_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4 500000
#define DPI_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6 100
#endif

#define DPI_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE 512
#define DPI_IPv4_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT 102400 /* 100K */
#define DPI_IPv4_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT 10240000 /* 10M. If each host fills its memory limit, we can support up to 1000 hosts. */
#define DPI_IPv4_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT 30

#define DPI_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE 512
#define DPI_IPv6_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT 102400 /* 100K */
#define DPI_IPv6_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT 10240000 /* 10M. If each host fills its memory limit, we can support up to 1000 hosts. */
#define DPI_IPv6_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT 60


/** Hash functions choice. **/
enum hashes{
	DPI_SIMPLE_HASH=0,
	DPI_FNV_HASH,
	DPI_MURMUR3_HASH,
	DPI_BKDR_HASH,
};

#define DPI_FLOW_TABLE_HASH_VERSION DPI_SIMPLE_HASH

#define DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE 1


#define DPI_ENABLE_MP_API 1

#ifndef DPI_THREAD_SAFETY_ENABLED
#if defined(DPI_ENABLE_MP_API) && DPI_ENABLE_MP_API == 1
	#define DPI_THREAD_SAFETY_ENABLED 1
#else
	#define DPI_THREAD_SAFETY_ENABLED 0
#endif
#endif

#define __STDC_FORMAT_MACROS //To enable inttypes.h macros also for g++

#endif /* CONFIG_H_ */
