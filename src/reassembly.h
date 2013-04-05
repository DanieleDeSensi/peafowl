/*
 * reassembly.h
 *
 * Created on: 05/10/2012
 *
 * Contains data structures used for both IPv4 and IPv6
 * fragmentation and for TCP stream reassembly. Here for
 * 'fragments' we mean both the IP fragments
 * and the TCP segments.
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

#ifndef REASSEMBLY_H_
#define REASSEMBLY_H_

#include <sys/types.h>
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dpi_reassembly_timer dpi_reassembly_timer_t;
typedef struct dpi_reassembly_fragment dpi_reassembly_fragment_t;


/**If tail insertion, then the head will be the first to expire. **/
struct dpi_reassembly_timer{
	dpi_reassembly_timer_t *prev;
	dpi_reassembly_timer_t *next;
	void* data;
	u_int32_t expiration_time;
};

/* Describe an IP fragment (or TCP segment). */
struct dpi_reassembly_fragment{
	/* Offset of fragment. */
	u_int32_t offset;
	/* Last byte of data in fragment. */
	u_int32_t end;
	/**
	 * This is needed because when a segment contains a FIN,
	 * then the expected sequence number in the other direction
	 * will be incremented by one.
	 */
	u_int8_t tcp_fin:1;
	/* Pointer into real fragment data. */
	unsigned char* ptr;
	/* Linked list pointers to the other fragments. */
	dpi_reassembly_fragment_t *next;
	dpi_reassembly_fragment_t *prev;
};



/**
 * Returns 1 if the sequence number x is before y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is before y, 0 otherwise.
 */
u_int8_t dpi_reassembly_before(u_int32_t x, u_int32_t y);


/**
 * Returns 1 if the sequence number x is before or equal y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is before or equal y, 0 otherwise.
 */
u_int8_t dpi_reassembly_before_or_equal(u_int32_t x, u_int32_t y);

/**
 * Returns 1 if the sequence number x is after y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is after y, 0 otherwise.
 */
u_int8_t dpi_reassembly_after(u_int32_t x, u_int32_t y);

/**
 * Returns 1 if the sequence number x is after or equal y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is after or equal y, 0 otherwise.
 */
u_int8_t dpi_reassembly_after_or_equal(u_int32_t x, u_int32_t y);

/**
 * Returns the length of a TCP segment (or IP fragment).
 * @param offset The offset where the segment starts.
 * @param end The last byte of the segment.
 * @return The length of the TCP segment (or IP fragment).
 */
u_int32_t dpi_reassembly_fragment_length(u_int32_t offset, u_int32_t end);

/**
 * Add a new timer to the list of IP reassembly timers.
 * @param head A pointer to the head of the timers list.
 * @param tail A pointer to the tail of the timers list.
 * @param timer The timer to insert.
 */
void dpi_reassembly_add_timer(dpi_reassembly_timer_t** head,
		                      dpi_reassembly_timer_t** tail,
		                      dpi_reassembly_timer_t* timer);

/**
 * Remove a timer to the list of IP reassembly timers.
 * @param head A pointer to the head of the timers list.
 * @param tail A pointer to the tail of the timers list.
 * @param timer The timer to remove.
 */
void dpi_reassembly_delete_timer(dpi_reassembly_timer_t** head,
		                         dpi_reassembly_timer_t** tail,
		                         dpi_reassembly_timer_t* timer);


/**
 * Insert a fragment in the correct position in the list of fragments,
 * considering overlaps, etc..
 * @param head The head of the list of fragments.
 * @param data The data contained in the fragment (without IP header).
 * @param offset The offset of this fragment.
 * @param end The end of this fragment.
 * @param bytes_removed The total number of bytes removed
 *                      (in the fragments) by this call.
 * @param bytes_inserted The total number of byte inserted
 *                       (in the fragments) by this call.
 *
 * @return The created fragment.
 */
dpi_reassembly_fragment_t* dpi_reassembly_insert_fragment(
		dpi_reassembly_fragment_t** head,
		const unsigned char* data,
		u_int32_t offset, u_int32_t end, u_int32_t* bytes_removed,
		u_int32_t* bytes_inserted);

/**
 * See there is a train of contiguous fragments.
 * @param head The pointer to the head of the list of fragments.
 * @return 0 if there are missing fragments, 1 otherwise.
 */
u_int8_t dpi_reassembly_ip_check_train_of_contiguous_fragments(
		dpi_reassembly_fragment_t* head);

/**
 * Compacts a train of contiguous fragments and returns it.
 * @param head A pointer to the head of the train.
 * @param where A pointer to a buffer where to put the data.
 * @param len The data_length of the buffer where to put the data.
 * @return The data_length of the recompacted data. If an error
 * occurred (e.g. misbehaving packet), -1 is returned.
 */
int32_t dpi_reassembly_ip_compact_fragments(
		dpi_reassembly_fragment_t* head,
		unsigned char** where,
		u_int32_t len);

#ifdef __cplusplus
}
#endif

#endif /* REASSEMBLY_H_ */
