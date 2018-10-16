/*
 * hash_functions.h
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

#ifndef HASH_FUNCTIONS_H_
#define HASH_FUNCTIONS_H_

#include <peafowl/peafowl.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_FNV_HASH ||                           \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
uint32_t v4_fnv_hash_function(const pfwl_dissection_info_t *const in);

uint32_t v6_fnv_hash_function(const pfwl_dissection_info_t *const in);
#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_MURMUR3_HASH ||                       \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
uint32_t v4_hash_murmur3(const pfwl_dissection_info_t *const in, uint32_t seed);

uint32_t v6_hash_murmur3(const pfwl_dissection_info_t *const in, uint32_t seed);
#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_SIMPLE_HASH ||                        \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
uint32_t v4_hash_function_simple(const pfwl_dissection_info_t *const in);

uint32_t v6_hash_function_simple(const pfwl_dissection_info_t *const in);
#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_BKDR_HASH ||                          \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
uint32_t v4_hash_function_bkdr(const pfwl_dissection_info_t *const in);

uint32_t v6_hash_function_bkdr(const pfwl_dissection_info_t *const in);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HASH_FUNCTIONS_H_ */
