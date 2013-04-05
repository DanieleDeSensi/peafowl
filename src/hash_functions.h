/*
 * hash_functions.h
 *
 * Created on: 06/10/2012
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

#ifndef HASH_FUNCTIONS_H_
#define HASH_FUNCTIONS_H_
#include <sys/types.h>
#include "api.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DPI_FLOW_TABLE_HASH_VERSION == DPI_FNV_HASH || DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
u_int32_t v4_fnv_hash_function(const dpi_pkt_infos_t* const in);

u_int32_t v6_fnv_hash_function(const dpi_pkt_infos_t* const in);
#endif

#if DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH || DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
u_int32_t v4_hash_murmur3(const dpi_pkt_infos_t* const in, u_int32_t seed);

u_int32_t v6_hash_murmur3(const dpi_pkt_infos_t* const in, u_int32_t seed);
#endif

#if DPI_FLOW_TABLE_HASH_VERSION == DPI_SIMPLE_HASH|| DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
u_int32_t v4_hash_function_simple(const dpi_pkt_infos_t* const in);

u_int32_t v6_hash_function_simple(const dpi_pkt_infos_t* const in);
#endif

#if DPI_FLOW_TABLE_HASH_VERSION == DPI_BKDR_HASH || DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
u_int32_t v4_hash_function_bkdr(const dpi_pkt_infos_t* const in);

u_int32_t v6_hash_function_bkdr(const dpi_pkt_infos_t* const in);
#endif



#ifdef __cplusplus
}
#endif

#endif /* HASH_FUNCTIONS_H_ */
