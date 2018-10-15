/*
 * hash_functions.c
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
#include <peafowl/hash_functions.h>

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_FNV_HASH ||                           \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1

#define FNV1A_32_INIT 0x811c9dc5
#define FNV_32_PRIME 0x01000193

#if !defined(__GNUC__)
#define PFWL_HVAL_SECOND_STEP(hval) hval *= FNV_32_PRIME;
#else
#define PFWL_HVAL_SECOND_STEP(hval)                                            \
  hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24);
#endif

#ifndef PFWL_DEBUG
#if PFWL_USE_INLINING == 1
inline
#endif
#endif
    /** FNV-1a 32-bit hash function. **/
    uint32_t
    v4_fnv_hash_function(const pfwl_dissection_info_t *const in) {
  uint32_t low_addr, high_addr;
  uint16_t low_port, high_port;

  if (in->l3.addr_src.ipv4 < in->l3.addr_dst.ipv4 ||
      (in->l3.addr_src.ipv4 == in->l3.addr_dst.ipv4 &&
       in->l4.port_src <= in->l4.port_dst)) {
    low_addr = in->l3.addr_src.ipv4;
    low_port = in->l4.port_src;
    high_addr = in->l3.addr_dst.ipv4;
    high_port = in->l4.port_dst;
  } else {
    high_addr = in->l3.addr_src.ipv4;
    high_port = in->l4.port_src;
    low_addr = in->l3.addr_dst.ipv4;
    low_port = in->l4.port_dst;
  }

  uint32_t hval = FNV1A_32_INIT;

  hval ^= (low_addr & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((low_addr >> 8) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((low_addr >> 16) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((low_addr >> 24) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)

  hval ^= (high_addr & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((high_addr >> 8) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((high_addr >> 16) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((high_addr >> 24) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)

  hval ^= in->l4.protocol;
  PFWL_HVAL_SECOND_STEP(hval)

  hval ^= (low_port & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((low_port >> 8) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)

  hval ^= (high_port & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= ((high_port >> 8) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)

  /* return our new hash value */
  return hval;
}

static void get_v6_low_high_addr_port(const pfwl_dissection_info_t *const in,
                                      struct in6_addr *low_addr,
                                      struct in6_addr *high_addr,
                                      uint16_t *low_port, uint16_t *high_port) {
  uint8_t i = 0;
  for (i = 0; i < 16; i++) {
    if (in->l3.addr_src.ipv6.s6_addr[i] < in->l3.addr_dst.ipv6.s6_addr[i]) {
      *low_addr = in->l3.addr_src.ipv6;
      *high_addr = in->l3.addr_dst.ipv6;
      *low_port = in->l4.port_src;
      *high_port = in->l4.port_dst;
      break;
    } else if (in->l3.addr_src.ipv6.s6_addr[i] >
               in->l3.addr_dst.ipv6.s6_addr[i]) {
      *high_addr = in->l3.addr_src.ipv6;
      *low_addr = in->l3.addr_dst.ipv6;
      *high_port = in->l4.port_src;
      *low_port = in->l4.port_dst;
      break;
    }
  }

  /** If i==16 the addresses are equal. **/
  if (i == 16) {
    if (in->l4.port_src <= in->l4.port_dst) {
      *low_addr = in->l3.addr_src.ipv6;
      *high_addr = in->l3.addr_dst.ipv6;
      *low_port = in->l4.port_src;
      *high_port = in->l4.port_dst;
    } else {
      *high_addr = in->l3.addr_src.ipv6;
      *low_addr = in->l3.addr_dst.ipv6;
      *high_port = in->l4.port_src;
      *low_port = in->l4.port_dst;
    }
  }
}

#ifndef PFWL_DEBUG
#if PFWL_USE_INLINING == 1
inline
#endif
#endif
    /** FNV-1a 32-bit hash function. **/
    uint32_t
    v6_fnv_hash_function(const pfwl_dissection_info_t *const in) {
  struct in6_addr low_addr, high_addr;
  uint16_t low_port, high_port;
  get_v6_low_high_addr_port(in, &low_addr, &high_addr, &low_port, &high_port);
  uint8_t i = 0;
  uint32_t hval = FNV1A_32_INIT;
  for (i = 0; i < 16; i++) {
    hval ^= low_addr.s6_addr[i];
    PFWL_HVAL_SECOND_STEP(hval)
  }

  for (i = 0; i < 16; i++) {
    hval ^= high_addr.s6_addr[i];
    PFWL_HVAL_SECOND_STEP(hval)
  }

  hval ^= in->l4.protocol;
  PFWL_HVAL_SECOND_STEP(hval)

  hval ^= ((low_port >> 8) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= (low_port & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)

  hval ^= ((high_port >> 8) & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)
  hval ^= (high_port & 0xFF);
  PFWL_HVAL_SECOND_STEP(hval)

  return hval;
}
#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_MURMUR3_HASH ||                       \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1

//-----------------------------------------------------------------------------
// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

// Note - The x86 and x64 versions do _not_ produce the same results, as the
// algorithms are optimized for their respective platforms. You can still
// compile and run any of them on any platform, but your performance with the
// non-native version will be less than optimal.

//-----------------------------------------------------------------------------
// Platform-specific functions and macros

// Microsoft Visual Studio

#if defined(_MSC_VER)

typedef unsigned char uint8_t;
typedef unsigned long uint32_t;
typedef unsigned __int64 uint64_t;
#define FORCE_INLINE __forceinline

#include <stdlib.h>

#define ROTL32(x, y) _rotl(x, y)
#define ROTL64(x, y) _rotl64(x, y)

#define BIG_CONSTANT(x) (x)

// Other compilers

#else // defined(_MSC_VER)

#include <stdint.h>

#define FORCE_INLINE inline __attribute__((always_inline))

inline uint32_t rotl32(uint32_t x, int8_t r) {
  return (x << r) | (x >> (32 - r));
}

inline uint64_t rotl64(uint64_t x, int8_t r) {
  return (x << r) | (x >> (64 - r));
}

#define ROTL32(x, y) rotl32(x, y)
#define ROTL64(x, y) rotl64(x, y)

#define BIG_CONSTANT(x) (x##LLU)

#endif // !defined(_MSC_VER)

//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

FORCE_INLINE uint32_t getblock(const uint32_t *p, int i) {
  return p[i];
}

FORCE_INLINE uint64_t getblock(const uint64_t *p, int i) {
  return p[i];
}

//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche

FORCE_INLINE uint32_t fmix(uint32_t h) {
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;

  return h;
}

//----------

FORCE_INLINE uint64_t fmix(uint64_t k) {
  k ^= k >> 33;
  k *= BIG_CONSTANT(0xff51afd7ed558ccd);
  k ^= k >> 33;
  k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
  k ^= k >> 33;

  return k;
}

//-----------------------------------------------------------------------------

void MurmurHash3_x86_32(const void *key, int len, uint32_t seed, void *out) {
  const uint8_t *data = (const uint8_t *) key;
  const int nblocks = len / 4;

  uint32_t h1 = seed;

  uint32_t c1 = 0xcc9e2d51;
  uint32_t c2 = 0x1b873593;

  //----------
  // body

  const uint32_t *blocks = (const uint32_t *) (data + nblocks * 4);

  for (int i = -nblocks; i; i++) {
    uint32_t k1 = getblock(blocks, i);

    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1, 13);
    h1 = h1 * 5 + 0xe6546b64;
  }

  //----------
  // tail

  const uint8_t *tail = (const uint8_t *) (data + nblocks * 4);

  uint32_t k1 = 0;

  switch (len & 3) {
  case 3:
    k1 ^= tail[2] << 16;
  case 2:
    k1 ^= tail[1] << 8;
  case 1:
    k1 ^= tail[0];
    k1 *= c1;
    k1 = ROTL32(k1, 15);
    k1 *= c2;
    h1 ^= k1;
  };

  //----------
  // finalization

  h1 ^= len;

  h1 = fmix(h1);

  *(uint32_t *) out = h1;
}

static void get_v4_key(const pfwl_dissection_info_t *const in, char *v4_key) {
  uint32_t lower_addr = 0, higher_addr = 0;
  uint16_t lower_port = 0, higher_port = 0;

  if (in->l3.addr_src.ipv4 < in->l3.addr_dst.ipv4 ||
      (in->l3.addr_src.ipv4 == in->l3.addr_dst.ipv4 &&
       in->l4.port_src <= in->l4.port_dst)) {
    lower_addr = in->l3.addr_src.ipv4;
    higher_addr = in->l3.addr_dst.ipv4;
    lower_port = in->l4.port_src;
    higher_port = in->l4.port_dst;
  } else {
    lower_addr = in->l3.addr_dst.ipv4;
    higher_addr = in->l3.addr_src.ipv4;
    lower_port = in->l4.port_dst;
    higher_port = in->l4.port_src;
  }

  v4_key[0] = ((lower_addr >> 24) & 0xFF);
  v4_key[1] = ((lower_addr >> 16) & 0xFF);
  v4_key[2] = ((lower_addr >> 8) & 0xFF);
  v4_key[3] = (lower_addr & 0xFF);

  v4_key[4] = ((higher_addr >> 24) & 0xFF);
  v4_key[5] = ((higher_addr >> 16) & 0xFF);
  v4_key[6] = ((higher_addr >> 8) & 0xFF);
  v4_key[7] = (higher_addr & 0xFF);

  v4_key[8] = in->l4.protocol;

  v4_key[9] = ((lower_port >> 8) & 0xFF);
  v4_key[10] = (lower_port & 0xFF);

  v4_key[11] = ((higher_port >> 8) & 0xFF);
  v4_key[12] = (higher_port & 0xFF);
}

uint32_t v4_hash_murmur3(const pfwl_dissection_info_t *const in,
                         uint32_t seed) {
  char v4_key[13];
  get_v4_key(in, v4_key);
  uint32_t result;
  MurmurHash3_x86_32(v4_key, 13, seed, &result);
  return result;
}

static void get_v6_key(const pfwl_dissection_info_t *const in, char *v6_key) {
  struct in6_addr low_addr, high_addr;
  uint16_t low_port, high_port;
  get_v6_low_high_addr_port(in, &low_addr, &high_addr, &low_port, &high_port);
  uint8_t i = 0;
  for (i = 0; i < 16; i++) {
    v6_key[i] = low_addr.s6_addr[i];
  }

  for (i = 0; i < 16; i++) {
    v6_key[i + 16] = high_addr.s6_addr[i];
  }

  v6_key[32] = in->l4.protocol;

  v6_key[33] = ((low_port >> 8) & 0xFF);
  v6_key[34] = (low_port & 0xFF);

  v6_key[35] = ((high_port >> 8) & 0xFF);
  v6_key[36] = (high_port & 0xFF);
}

uint32_t v6_hash_murmur3(const pfwl_dissection_info_t *const in,
                         uint32_t seed) {
  char v6_key[37];
  get_v6_key(in, v6_key);
  uint32_t result;
  MurmurHash3_x86_32(v6_key, 37, seed, &result);
  return result;
}
#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_SIMPLE_HASH ||                        \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
uint32_t v4_hash_function_simple(const pfwl_dissection_info_t *const in) {
  return in->l4.port_src + in->l4.port_dst + in->l3.addr_src.ipv4 +
         in->l3.addr_dst.ipv4 + in->l4.protocol;
}

uint32_t v6_hash_function_simple(const pfwl_dissection_info_t *const in) {
  uint8_t i;
  uint32_t partsrc = 0, partdst = 0;
  for (i = 0; i < 16; i++) {
    partsrc += in->l3.addr_src.ipv6.s6_addr[i];
    partdst += in->l3.addr_dst.ipv6.s6_addr[i];
  }
  return in->l4.port_src + in->l4.port_dst + partsrc + partdst +
         in->l4.protocol;
}

#endif

#if PFWL_FLOW_TABLE_HASH_VERSION == PFWL_BKDR_HASH ||                          \
    PFWL_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
uint32_t v4_hash_function_bkdr(const pfwl_dissection_info_t *const in) {
  uint32_t seed = 131; // 31 131 1313 13131 131313 etc..
  uint32_t hash = 0;
  char v4_key[13];
  get_v4_key(in, v4_key);
  for (int i = 0; i < 13; i++) {
    hash = (hash * seed) + v4_key[i];
  }

  return (hash & 0x7FFFFFFF);
}

uint32_t v6_hash_function_bkdr(const pfwl_dissection_info_t *const in) {
  uint32_t seed = 131; // 31 131 1313 13131 131313 etc..
  uint32_t hash = 0;

  char v6_key[37];
  get_v6_key(in, v6_key);
  for (int i = 0; i < 37; i++) {
    hash = (hash * seed) + v6_key[i];
  }

  return (hash & 0x7FFFFFFF);
}
#endif
