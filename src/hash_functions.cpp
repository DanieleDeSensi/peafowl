/*
 * hash_functions.c
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
#include "hash_functions.h"


#if DPI_FLOW_TABLE_HASH_VERSION == DPI_FNV_HASH || DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1

#define FNV1A_32_INIT 0x811c9dc5
#define FNV_32_PRIME 0x01000193

#if !defined(__GNUC__)
#define DPI_HVAL_SECOND_STEP(hval) hval*=FNV_32_PRIME;
#else
#define DPI_HVAL_SECOND_STEP(hval) hval+=(hval<<1)+(hval<<4)+(hval<<7)+(hval<<8)+(hval<<24);
#endif


#ifndef DPI_DEBUG
#if DPI_USE_INLINING == 1
inline
#endif
#endif
/** FNV-1a 32-bit hash function. **/
u_int32_t v4_fnv_hash_function(const dpi_pkt_infos_t* const in){
	u_int32_t low_addr, high_addr;
	u_int16_t low_port, high_port;

	if(in->src_addr_t.ipv4_srcaddr<in->dst_addr_t.ipv4_dstaddr || (in->src_addr_t.ipv4_srcaddr==in->dst_addr_t.ipv4_dstaddr && in->srcport<=in->dstport)){
		low_addr=in->src_addr_t.ipv4_srcaddr;
		low_port=in->srcport;
		high_addr=in->dst_addr_t.ipv4_dstaddr;
		high_port=in->dstport;
	}else{
		high_addr=in->src_addr_t.ipv4_srcaddr;
		high_port=in->srcport;
		low_addr=in->dst_addr_t.ipv4_dstaddr;
		low_port=in->dstport;
	}

	u_int32_t hval=FNV1A_32_INIT;

	hval^=(low_addr & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((low_addr >> 8) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((low_addr >> 16) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((low_addr >> 24) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)

	hval^=(high_addr & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((high_addr >> 8) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((high_addr >> 16) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((high_addr >> 24) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)

    hval^=in->l4prot;
	DPI_HVAL_SECOND_STEP(hval)

	hval^=(low_port & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((low_port >> 8) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)

	hval^=(high_port & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=((high_port >> 8) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)

    /* return our new hash value */
    return hval;
}


#ifndef DPI_DEBUG
#if DPI_USE_INLINING == 1
inline
#endif
#endif
/** FNV-1a 32-bit hash function. **/
u_int32_t v6_fnv_hash_function(const dpi_pkt_infos_t* const in){
	struct in6_addr low_addr, high_addr;
	u_int16_t low_port, high_port;

	u_int8_t i=0;
	for(i=0; i<16; i++){
		if(in->src_addr_t.ipv6_srcaddr.s6_addr[i]<in->src_addr_t.ipv6_srcaddr.s6_addr[i]){
			low_addr=in->src_addr_t.ipv6_srcaddr;
			high_addr=in->dst_addr_t.ipv6_dstaddr;
			low_port=in->srcport;
			high_port=in->dstport;
			break;
		}else if(in->src_addr_t.ipv6_srcaddr.s6_addr[i]>in->src_addr_t.ipv6_srcaddr.s6_addr[i]){
			high_addr=in->src_addr_t.ipv6_srcaddr;
			low_addr=in->dst_addr_t.ipv6_dstaddr;
			high_port=in->srcport;
			low_port=in->dstport;
			break;
		}
	}

	/** If i==16 the addresses are equal. **/
	if(i==16){
		if(in->srcport<=in->dstport){
			low_addr=in->src_addr_t.ipv6_srcaddr;
			high_addr=in->dst_addr_t.ipv6_dstaddr;
			low_port=in->srcport;
			high_port=in->dstport;
		}else{
			high_addr=in->src_addr_t.ipv6_srcaddr;
			low_addr=in->dst_addr_t.ipv6_dstaddr;
			high_port=in->srcport;
			low_port=in->dstport;
		}
	}

	u_int32_t hval=FNV1A_32_INIT;
	for(i=0; i<16; i++){
		hval^=low_addr.s6_addr[i];
		DPI_HVAL_SECOND_STEP(hval)
	}

	for(i=0; i<16; i++){
		hval^=high_addr.s6_addr[i];
		DPI_HVAL_SECOND_STEP(hval)
	}

	hval^=in->l4prot;
	DPI_HVAL_SECOND_STEP(hval)

	hval^=((low_port >> 8) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=(low_port & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)

	hval^=((high_port >> 8) & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)
	hval^=(high_port & 0xFF);
	DPI_HVAL_SECOND_STEP(hval)

	return hval;
}
#endif


#if DPI_FLOW_TABLE_HASH_VERSION == DPI_MURMUR3_HASH || DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1

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
#define FORCE_INLINE	__forceinline

#include <stdlib.h>

#define ROTL32(x,y)	_rotl(x,y)
#define ROTL64(x,y)	_rotl64(x,y)

#define BIG_CONSTANT(x) (x)

// Other compilers

#else	// defined(_MSC_VER)

#include <stdint.h>

#define	FORCE_INLINE inline __attribute__((always_inline))

inline uint32_t rotl32 ( uint32_t x, int8_t r )
{
  return (x << r) | (x >> (32 - r));
}

inline uint64_t rotl64 ( uint64_t x, int8_t r )
{
  return (x << r) | (x >> (64 - r));
}

#define	ROTL32(x,y)	rotl32(x,y)
#define ROTL64(x,y)	rotl64(x,y)

#define BIG_CONSTANT(x) (x##LLU)

#endif // !defined(_MSC_VER)

//-----------------------------------------------------------------------------
// Block read - if your platform needs to do endian-swapping or can only
// handle aligned reads, do the conversion here

FORCE_INLINE uint32_t getblock ( const uint32_t * p, int i )
{
  return p[i];
}

FORCE_INLINE uint64_t getblock ( const uint64_t * p, int i )
{
  return p[i];
}

//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche

FORCE_INLINE uint32_t fmix ( uint32_t h )
{
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;

  return h;
}

//----------

FORCE_INLINE uint64_t fmix ( uint64_t k )
{
  k ^= k >> 33;
  k *= BIG_CONSTANT(0xff51afd7ed558ccd);
  k ^= k >> 33;
  k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
  k ^= k >> 33;

  return k;
}

//-----------------------------------------------------------------------------

void MurmurHash3_x86_32 ( const void * key, int len,
                          uint32_t seed, void * out )
{
  const uint8_t * data = (const uint8_t*)key;
  const int nblocks = len / 4;

  uint32_t h1 = seed;

  uint32_t c1 = 0xcc9e2d51;
  uint32_t c2 = 0x1b873593;

  //----------
  // body

  const uint32_t * blocks = (const uint32_t *)(data + nblocks*4);

  for(int i = -nblocks; i; i++)
  {
    uint32_t k1 = getblock(blocks,i);

    k1 *= c1;
    k1 = ROTL32(k1,15);
    k1 *= c2;

    h1 ^= k1;
    h1 = ROTL32(h1,13);
    h1 = h1*5+0xe6546b64;
  }

  //----------
  // tail

  const uint8_t * tail = (const uint8_t*)(data + nblocks*4);

  uint32_t k1 = 0;

  switch(len & 3)
  {
  case 3: k1 ^= tail[2] << 16;
  case 2: k1 ^= tail[1] << 8;
  case 1: k1 ^= tail[0];
          k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
  };

  //----------
  // finalization

  h1 ^= len;

  h1 = fmix(h1);

  *(uint32_t*)out = h1;
}

u_int32_t v4_hash_murmur3(const dpi_pkt_infos_t* const in, u_int32_t seed){
	char v4_key[13];
	u_int32_t lower_addr=0, higher_addr=0;
	u_int16_t lower_port=0, higher_port=0;

	if(in->src_addr_t.ipv4_srcaddr<in->dst_addr_t.ipv4_dstaddr || (in->src_addr_t.ipv4_srcaddr==in->dst_addr_t.ipv4_dstaddr && in->srcport<=in->dstport)){
		lower_addr=in->src_addr_t.ipv4_srcaddr;
		higher_addr=in->dst_addr_t.ipv4_dstaddr;
		lower_port=in->srcport;
		higher_port=in->dstport;
	}else{
		lower_addr=in->dst_addr_t.ipv4_dstaddr;
		higher_addr=in->src_addr_t.ipv4_srcaddr;
		lower_port=in->dstport;
		higher_port=in->srcport;
	}

	v4_key[0]=((lower_addr >> 24) & 0xFF);
	v4_key[1]=((lower_addr >> 16) & 0xFF);
	v4_key[2]=((lower_addr >> 8) & 0xFF);
	v4_key[3]=(lower_addr & 0xFF);

	v4_key[4]=((higher_addr >> 24) & 0xFF);
	v4_key[5]=((higher_addr >> 16) & 0xFF);
	v4_key[6]=((higher_addr >> 8) & 0xFF);
	v4_key[7]=(higher_addr & 0xFF);

	v4_key[8]=in->l4prot;

	v4_key[9]=((lower_port >> 8) & 0xFF);
	v4_key[10]=(lower_port & 0xFF);

	v4_key[11]=((higher_port >> 8) & 0xFF);
	v4_key[12]=(higher_port & 0xFF);

	u_int32_t result;
	MurmurHash3_x86_32(v4_key, 13, seed, &result);
	return result;
}

u_int32_t v6_hash_murmur3(const dpi_pkt_infos_t* const in, u_int32_t seed){
	char v6_key[37];

	struct in6_addr low_addr, high_addr;
	u_int16_t low_port, high_port;

	u_int8_t i=0;
	for(i=0; i<16; i++){
		if(in->src_addr_t.ipv6_srcaddr.s6_addr[i]<in->src_addr_t.ipv6_srcaddr.s6_addr[i]){
			low_addr=in->src_addr_t.ipv6_srcaddr;
			high_addr=in->dst_addr_t.ipv6_dstaddr;
			low_port=in->srcport;
			high_port=in->dstport;
			break;
		}else if(in->src_addr_t.ipv6_srcaddr.s6_addr[i]>in->src_addr_t.ipv6_srcaddr.s6_addr[i]){
			high_addr=in->src_addr_t.ipv6_srcaddr;
			low_addr=in->dst_addr_t.ipv6_dstaddr;
			high_port=in->srcport;
			low_port=in->dstport;
			break;
		}
	}

	/** If i==16 the addresses are equal. **/
	if(i==16){
		if(in->srcport<=in->dstport){
			low_addr=in->src_addr_t.ipv6_srcaddr;
			high_addr=in->dst_addr_t.ipv6_dstaddr;
			low_port=in->srcport;
			high_port=in->dstport;
		}else{
			high_addr=in->src_addr_t.ipv6_srcaddr;
			low_addr=in->dst_addr_t.ipv6_dstaddr;
			high_port=in->srcport;
			low_port=in->dstport;
		}
	}

	for(i=0; i<16; i++){
		v6_key[i]=low_addr.s6_addr[i];
	}

	for(i=0; i<16; i++){
		v6_key[i+16]=high_addr.s6_addr[i];
	}

	v6_key[32]=in->l4prot;

	v6_key[33]=((low_port >> 8) & 0xFF);
	v6_key[34]=(low_port & 0xFF);

	v6_key[35]=((high_port >> 8) & 0xFF);
	v6_key[36]=(high_port & 0xFF);

	u_int32_t result;
	MurmurHash3_x86_32(v6_key, 37, seed, &result);
	return result;
}
#endif

#if DPI_FLOW_TABLE_HASH_VERSION == DPI_SIMPLE_HASH || DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
u_int32_t v4_hash_function_simple(const dpi_pkt_infos_t* const in){
	return in->srcport+in->dstport+in->src_addr_t.ipv4_srcaddr+in->dst_addr_t.ipv4_dstaddr+in->l4prot;
}



u_int32_t v6_hash_function_simple(const dpi_pkt_infos_t* const in){
	u_int8_t i;
	u_int32_t partsrc=0,partdst=0;
	for(i=0; i<16; i++){
		partsrc+=in->src_addr_t.ipv6_srcaddr.s6_addr[i];
		partdst+=in->dst_addr_t.ipv6_dstaddr.s6_addr[i];
	}
	return in->srcport+in->dstport+partsrc+partdst+in->l4prot;
}

#endif


#if DPI_FLOW_TABLE_HASH_VERSION == DPI_BKDR_HASH || DPI_ACTIVATE_ALL_HASH_FUNCTIONS_CODE == 1
u_int32_t v4_hash_function_bkdr(const dpi_pkt_infos_t* const in){
	u_int32_t seed = 131; // 31 131 1313 13131 131313 etc..
	u_int32_t hash = 0;
	char v4_key[13];
	u_int32_t lower_addr=0, higher_addr=0;
	u_int16_t lower_port=0, higher_port=0;

	if(in->src_addr_t.ipv4_srcaddr<in->dst_addr_t.ipv4_dstaddr || (in->src_addr_t.ipv4_srcaddr==in->dst_addr_t.ipv4_dstaddr && in->srcport<=in->dstport)){
		lower_addr=in->src_addr_t.ipv4_srcaddr;
		higher_addr=in->dst_addr_t.ipv4_dstaddr;
		lower_port=in->srcport;
		higher_port=in->dstport;
	}else{
		lower_addr=in->dst_addr_t.ipv4_dstaddr;
		higher_addr=in->src_addr_t.ipv4_srcaddr;
		lower_port=in->dstport;
		higher_port=in->srcport;
	}

	v4_key[0]=((lower_addr >> 24) & 0xFF);
	v4_key[1]=((lower_addr >> 16) & 0xFF);
	v4_key[2]=((lower_addr >> 8) & 0xFF);
	v4_key[3]=(lower_addr & 0xFF);

	v4_key[4]=((higher_addr >> 24) & 0xFF);
	v4_key[5]=((higher_addr >> 16) & 0xFF);
	v4_key[6]=((higher_addr >> 8) & 0xFF);
	v4_key[7]=(higher_addr & 0xFF);

	v4_key[8]=in->l4prot;

	v4_key[9]=((lower_port >> 8) & 0xFF);
	v4_key[10]=(lower_port & 0xFF);

	v4_key[11]=((higher_port >> 8) & 0xFF);
	v4_key[12]=(higher_port & 0xFF);

	for(int i=0; i<13; i++){
		hash=(hash*seed)+v4_key[i];
	}

	return (hash & 0x7FFFFFFF);
}

u_int32_t v6_hash_function_bkdr(const dpi_pkt_infos_t* const in){
	u_int32_t seed = 131; // 31 131 1313 13131 131313 etc..
	u_int32_t hash = 0;

	char v6_key[37];
	struct in6_addr low_addr, high_addr;
	u_int16_t low_port, high_port;

	u_int8_t i=0;
	for(i=0; i<16; i++){
		if(in->src_addr_t.ipv6_srcaddr.s6_addr[i]<in->src_addr_t.ipv6_srcaddr.s6_addr[i]){
			low_addr=in->src_addr_t.ipv6_srcaddr;
			high_addr=in->dst_addr_t.ipv6_dstaddr;
			low_port=in->srcport;
			high_port=in->dstport;
			break;
		}else if(in->src_addr_t.ipv6_srcaddr.s6_addr[i]>in->src_addr_t.ipv6_srcaddr.s6_addr[i]){
			high_addr=in->src_addr_t.ipv6_srcaddr;
			low_addr=in->dst_addr_t.ipv6_dstaddr;
			high_port=in->srcport;
			low_port=in->dstport;
			break;
		}
	}

	/** If i==16 the addresses are equal. **/
	if(i==16){
		if(in->srcport<=in->dstport){
			low_addr=in->src_addr_t.ipv6_srcaddr;
			high_addr=in->dst_addr_t.ipv6_dstaddr;
			low_port=in->srcport;
			high_port=in->dstport;
		}else{
			high_addr=in->src_addr_t.ipv6_srcaddr;
			low_addr=in->dst_addr_t.ipv6_dstaddr;
			high_port=in->srcport;
			low_port=in->dstport;
		}
	}

	for(i=0; i<16; i++){
		v6_key[i]=low_addr.s6_addr[i];
	}

	for(i=0; i<16; i++){
		v6_key[i+16]=high_addr.s6_addr[i];
	}

	v6_key[32]=in->l4prot;

	v6_key[33]=((low_port >> 8) & 0xFF);
	v6_key[34]=(low_port & 0xFF);

	v6_key[35]=((high_port >> 8) & 0xFF);
	v6_key[36]=(high_port & 0xFF);

	for(int i=0; i<37; i++){
		hash=(hash*seed)+v6_key[i];
	}

	return (hash & 0x7FFFFFFF);
}
#endif
