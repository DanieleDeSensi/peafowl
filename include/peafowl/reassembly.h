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

#ifndef PFWL_REASSEMBLY_H_
#define PFWL_REASSEMBLY_H_

#include <peafowl/utils.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pfwl_reassembly_timer pfwl_reassembly_timer_t;
typedef struct pfwl_reassembly_fragment pfwl_reassembly_fragment_t;

/**If tail insertion, then the head will be the first to expire. **/
struct pfwl_reassembly_timer {
  pfwl_reassembly_timer_t *prev;
  pfwl_reassembly_timer_t *next;
  void *data;
  uint32_t expiration_time;
};

/* Describe an IP fragment (or TCP segment). */
struct pfwl_reassembly_fragment {
  /* Offset of fragment. */
  uint32_t offset;
  /* Last byte of data in fragment. */
  uint32_t end;
  /**
   * This is needed because when a segment contains a FIN,
   * then the expected sequence number in the other direction
   * will be incremented by one.
   */
  uint8_t tcp_fin : 1;
  /* Pointer into real fragment data. */
  unsigned char *ptr;
  /* Linked list pointers to the other fragments. */
  pfwl_reassembly_fragment_t *next;
  pfwl_reassembly_fragment_t *prev;
};

/**
 * Returns 1 if the sequence number x is before y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is before y, 0 otherwise.
 */
uint8_t pfwl_reassembly_before(uint32_t x, uint32_t y);

/**
 * Returns 1 if the sequence number x is before or equal y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is before or equal y, 0 otherwise.
 */
uint8_t pfwl_reassembly_before_or_equal(uint32_t x, uint32_t y);

/**
 * Returns 1 if the sequence number x is after y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is after y, 0 otherwise.
 */
uint8_t pfwl_reassembly_after(uint32_t x, uint32_t y);

/**
 * Returns 1 if the sequence number x is after or equal y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is after or equal y, 0 otherwise.
 */
uint8_t pfwl_reassembly_after_or_equal(uint32_t x, uint32_t y);

/**
 * Returns the length of a TCP segment (or IP fragment).
 * @param offset The offset where the segment starts.
 * @param end The last byte of the segment.
 * @return The length of the TCP segment (or IP fragment).
 */
uint32_t pfwl_reassembly_fragment_length(uint32_t offset, uint32_t end);

/**
 * Add a new timer to the list of IP reassembly timers.
 * @param head A pointer to the head of the timers list.
 * @param tail A pointer to the tail of the timers list.
 * @param timer The timer to insert.
 */
void pfwl_reassembly_add_timer(pfwl_reassembly_timer_t **head,
                               pfwl_reassembly_timer_t **tail,
                               pfwl_reassembly_timer_t *timer);

/**
 * Remove a timer to the list of IP reassembly timers.
 * @param head A pointer to the head of the timers list.
 * @param tail A pointer to the tail of the timers list.
 * @param timer The timer to remove.
 */
void pfwl_reassembly_delete_timer(pfwl_reassembly_timer_t **head,
                                  pfwl_reassembly_timer_t **tail,
                                  pfwl_reassembly_timer_t *timer);

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
pfwl_reassembly_fragment_t *
pfwl_reassembly_insert_fragment(pfwl_reassembly_fragment_t **head,
                                const unsigned char *data, uint32_t offset,
                                uint32_t end, uint32_t *bytes_removed,
                                uint32_t *bytes_inserted);

/**
 * See there is a train of contiguous fragments.
 * @param head The pointer to the head of the list of fragments.
 * @return 0 if there are missing fragments, 1 otherwise.
 */
uint8_t pfwl_reassembly_ip_check_train_of_contiguous_fragments(
    pfwl_reassembly_fragment_t *head);

/**
 * Compacts a train of contiguous fragments and returns it.
 * @param head A pointer to the head of the train.
 * @param where A pointer to a buffer where to put the data.
 * @param len The data_length of the buffer where to put the data.
 * @return The data_length of the recompacted data. If an error
 * occurred (e.g. misbehaving packet), -1 is returned.
 */
int32_t pfwl_reassembly_ip_compact_fragments(pfwl_reassembly_fragment_t *head,
                                             unsigned char **where,
                                             uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* PFWL_REASSEMBLY_H_ */
