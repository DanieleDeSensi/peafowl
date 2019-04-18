/*
 * reassembly.cpp
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
#include <peafowl/config.h>
#include <peafowl/reassembly.h>
#include <peafowl/utils.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void pfwl_reassembly_add_timer(pfwl_reassembly_timer_t **head,
                               pfwl_reassembly_timer_t **tail,
                               pfwl_reassembly_timer_t *timer) {
  if (*tail) {
    (*tail)->next = timer;
    timer->prev = (*tail);
    timer->next = NULL;
    (*tail) = timer;
  } else {
    timer->prev = NULL;
    timer->next = NULL;
    (*tail) = (*head) = timer;
  }
}

void pfwl_reassembly_delete_timer(pfwl_reassembly_timer_t **head,
                                  pfwl_reassembly_timer_t **tail,
                                  pfwl_reassembly_timer_t *timer) {
  if (timer->prev)
    timer->prev->next = timer->next;
  else
    (*head) = timer->next;

  if (timer->next)
    timer->next->prev = timer->prev;
  else
    (*tail) = timer->prev;
}

uint8_t pfwl_reassembly_before(uint32_t x, uint32_t y) {
  return x < y || (x - y) > PFWL_TCP_MAX_IN_TRAVEL_DATA;
}

uint8_t pfwl_reassembly_before_or_equal(uint32_t x, uint32_t y) {
  return x <= y || (x - y) >= PFWL_TCP_MAX_IN_TRAVEL_DATA;
}

uint8_t pfwl_reassembly_after(uint32_t x, uint32_t y) {
  return x > y || (y - x) > PFWL_TCP_MAX_IN_TRAVEL_DATA;
}

uint8_t pfwl_reassembly_after_or_equal(uint32_t x, uint32_t y) {
  return x >= y || (y - x) >= PFWL_TCP_MAX_IN_TRAVEL_DATA;
}

uint32_t pfwl_reassembly_fragment_length(uint32_t offset, uint32_t end) {
  if (end >= offset)
    return end - offset;
  else
    return PFWL_MAX_INT_32 - offset + 1 + end;
}

#ifndef PFWL_DEBUG
static
#endif
    pfwl_reassembly_fragment_t *
    pfwl_reassembly_create_fragment(uint32_t offset, uint32_t end,
                                    const unsigned char *ptr) {
  pfwl_reassembly_fragment_t *fragment;
  fragment = (pfwl_reassembly_fragment_t *) calloc(
      1, sizeof(pfwl_reassembly_fragment_t));
  if (unlikely(fragment == NULL)) {
    free(fragment);
    return NULL;
  }

  /* Fill in the structure. */
  fragment->offset = offset;
  fragment->end = end;
  fragment->tcp_fin = 0;

  uint32_t length = pfwl_reassembly_fragment_length(offset, end);
  fragment->ptr = (unsigned char *) malloc(sizeof(unsigned char) * (length));

  if (unlikely(fragment->ptr == NULL)) {
    free(fragment);
    return NULL;
  }
  memcpy(fragment->ptr, ptr, length);
  return fragment;
}

pfwl_reassembly_fragment_t *
pfwl_reassembly_insert_fragment(pfwl_reassembly_fragment_t **head,
                                const unsigned char *data, uint32_t offset,
                                uint32_t end, uint32_t *bytes_removed,
                                uint32_t *bytes_inserted) {
  pfwl_reassembly_fragment_t *prev, *next, *iterator, *tmp;
  uint32_t fragment_start = 0;
  *bytes_removed = 0;
  *bytes_inserted = 0;

  /*
   * Find the position in which this fragment must be put.
   */

  prev = NULL;
  for (next = (*head); next != NULL; next = next->next) {
    if (pfwl_reassembly_after_or_equal(next->offset, offset)) {
      break;
    }
    prev = next;
  }

  /**
   *  If there are no overlaps, I should put the fragment after prev
   *  and before next.
   *
   *  In the general case we will have (in sequence, some of this points
   *  may be missing):
   *   1. Partially or total overlap with the previous fragment.
   *      (The overlapped part will be left in the old data).
   *   2. A gap in which we have to insert a part of the new fragment.
   *      (The new part will be inserted from the new fragment).
   *   3. A train of completely overlapped fragments.
   *      (Will be replaced by new fragment)
   *   4. A partially overlapped fragment. (The overlapped part will
   *      be left in the old data).
   */

  /**
   *  Check for overlaps with the previous fragment. We will leave the
   *  previous fragment untouched and in case copy the new part.
   **/
  if (prev != NULL && pfwl_reassembly_before(offset, prev->end)) {
    /** If is contained in the previous fragment don't do anything.**/
    if (pfwl_reassembly_before_or_equal(end, prev->end)) {
      return NULL;
    }
    offset = prev->end;
    fragment_start = pfwl_reassembly_fragment_length(offset, prev->end);
  }

  /**
   *  Check for overlaps with the subsequent segments (can be more
   *  than one). If there are completely overlapped segments, they
   *  will be removed and replaced by the new fragment. The
   *  alternative was to add only the missing parts, but this could
   *  lead to an high number of small fragments. Anyway, to avoid
   *  this and to have a more compact list of fragments we incur in
   *  the cost of reallocate and copy again already present data.
   */
  for (iterator = next; iterator != NULL;) {
    /**
     * This data doesn't overlaps. The data are ordered so the
     * successive will not overlap too.
     **/
    if (pfwl_reassembly_after_or_equal(iterator->offset, end)) {
      break;
    }

    /**
     * If the fragment 'iterator' is completely overlapped by the
     * new fragment, then remove it.
     **/
    if (pfwl_reassembly_after_or_equal(end, iterator->end)) {
      if (iterator->prev != NULL) {
        iterator->prev->next = iterator->next;
      } else {
        (*head) = iterator->next;
      }

      if (iterator->next != NULL)
        iterator->next->prev = iterator->prev;

      tmp = iterator->next;

      (*bytes_removed) +=
          pfwl_reassembly_fragment_length(iterator->offset, iterator->end);

      free(iterator->ptr);
      free(iterator);

      /**
       * We deleted iterator, so we put the pointer back to the
       * previous fragment. The for loop will then go to the
       * successive data.
       **/
      iterator = tmp;
      /** We have also to update next. **/
      next = tmp;
    } else {
      /**
       * If it is partially overlapped, then we left the overlapped
       * part in the old fragment.
       **/
      end = iterator->offset;
      iterator = iterator->next;
    }
  }

  /** Insert the new fragment in the list. **/
  tmp = pfwl_reassembly_create_fragment(offset, end, data + fragment_start);

  if (unlikely(tmp == NULL))
    return NULL;

  (*bytes_inserted) += pfwl_reassembly_fragment_length(offset, end);

  tmp->prev = prev;
  tmp->next = next;
  if (prev)
    prev->next = tmp;
  else
    (*head) = tmp;

  if (next)
    next->prev = tmp;
  return tmp;
}

uint8_t pfwl_reassembly_ip_check_train_of_contiguous_fragments(
    pfwl_reassembly_fragment_t *head) {
  if (!head)
    return 0;
  uint16_t offset = 0;

  /* Check all fragment offsets to see if they connect. */
  while (head) {
    if (head->offset > offset)
      return 0;
    offset = head->end;
    head = head->next;
  }
  return 1;
}

int32_t pfwl_reassembly_ip_compact_fragments(pfwl_reassembly_fragment_t *head,
                                             unsigned char **where,
                                             uint32_t len) {
  /* Copy the data portions of all fragments into the new buffer. */
  uint32_t count = 0;
  while (head != NULL) {
    uint32_t fragment_length = head->end - head->offset;
    if (unlikely(head->offset + fragment_length > len)) {
      return -1;
    }
    memcpy(((*where) + head->offset), head->ptr, fragment_length);
    count += fragment_length;
    head = head->next;
  }
  return count;
}
