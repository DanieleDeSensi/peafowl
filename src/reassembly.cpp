/*
 * reassembly.c
 *
 * Created on: 06/10/2012
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

#include "reassembly.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/**
 * Add a new timer to the list of IP reassembly timers.
 * @param head A pointer to the head of the timers list.
 * @param tail A pointer to the tail of the timers list.
 * @param timer The timer to insert.
 */
void dpi_reassembly_add_timer(dpi_reassembly_timer_t** head,
		                      dpi_reassembly_timer_t** tail,
		                      dpi_reassembly_timer_t* timer){
	if(*tail){
		(*tail)->next=timer;
		timer->prev=(*tail);
		timer->next=NULL;
		(*tail)=timer;
	}else{
		timer->prev=NULL;
		timer->next=NULL;
		(*tail)=(*head)=timer;
	}
}

/**
 * Remove a timer to the list of IP reassembly timers.
 * @param head A pointer to the head of the timers list.
 * @param tail A pointer to the tail of the timers list.
 * @param timer The timer to remove.
 */
void dpi_reassembly_delete_timer(dpi_reassembly_timer_t** head,
		                         dpi_reassembly_timer_t** tail,
		                         dpi_reassembly_timer_t* timer){
	if(timer->prev)
		timer->prev->next=timer->next;
	else
		(*head)=timer->next;

	if(timer->next)
		timer->next->prev=timer->prev;
	else
		(*tail)=timer->prev;
}


/**
 * Returns 1 if the sequence number x is before y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is before y, 0 otherwise.
 */
u_int8_t dpi_reassembly_before(u_int32_t x, u_int32_t y){
	return x<y || (x-y)>DPI_TCP_MAX_IN_TRAVEL_DATA;
}


/**
 * Returns 1 if the sequence number x is before or equal y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is before or equal y, 0 otherwise.
 */
u_int8_t dpi_reassembly_before_or_equal(u_int32_t x, u_int32_t y){
	return x<=y || (x-y)>=DPI_TCP_MAX_IN_TRAVEL_DATA;
}

/**
 * Returns 1 if the sequence number x is after y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is after y, 0 otherwise.
 */
u_int8_t dpi_reassembly_after(u_int32_t x, u_int32_t y){
	return x>y || (y-x)>DPI_TCP_MAX_IN_TRAVEL_DATA;
}

/**
 * Returns 1 if the sequence number x is after or equal y, 0 otherwise.
 * @param x First sequence number.
 * @param y Second sequence number.
 * @return 1 if x is after or equal y, 0 otherwise.
 */
u_int8_t dpi_reassembly_after_or_equal(u_int32_t x, u_int32_t y){
	return x>=y || (y-x)>=DPI_TCP_MAX_IN_TRAVEL_DATA;
}

/**
 * Returns the length of a TCP segment (or IP fragment).
 * @param offset The offset where the segment starts.
 * @param end The last byte of the segment.
 * @return The length of the TCP segment (or IP fragment).
 */
u_int32_t dpi_reassembly_fragment_length(u_int32_t offset, u_int32_t end){
	if(end>=offset)
		return end-offset;
	else
		return DPI_MAX_INT_32-offset+1+end;
}


#ifndef DPI_DEBUG
static
#endif
/**
 * Builds a new fragment.
 * @param offset The offset where the fragment start.
 * @param end The last byte of the fragment.
 * @param ptr The content of the fragment.
 * @return The created fragment.
 */
dpi_reassembly_fragment_t* dpi_reassembly_create_fragment(
		u_int32_t offset, u_int32_t end, const unsigned char *ptr){
	dpi_reassembly_fragment_t* fragment;
	fragment=(dpi_reassembly_fragment_t*)
			   calloc(1, sizeof(dpi_reassembly_fragment_t));
    if(unlikely(fragment==NULL)){
        free(fragment);
		return NULL;
    }

	/* Fill in the structure. */
	fragment->offset=offset;
	fragment->end=end;
	fragment->tcp_fin=0;

	u_int32_t length=dpi_reassembly_fragment_length(offset, end);
	fragment->ptr=(unsigned char*) malloc(sizeof(unsigned char)*(length));

	if(unlikely(fragment->ptr==NULL)){
		free(fragment);
		return NULL;
	}
	memcpy(fragment->ptr, ptr, length);
	return fragment;
}


/**
 * Insert a fragment in the correct position in the list of fragments,
 * considering overlaps, etc..
 * @param head The head of the list of fragments.
 * @param data The data contained in the fragment (without IP header).
 * @param offset The offset of this fragment.
 * @param end The end of this fragment.
 * @param bytes_removed The total number of bytes removed (in the fragments) by this call.
 * @param bytes_inserted The total number of byte inserted (in the fragments) by this call.
 *
 * @return The created fragment.
 */
dpi_reassembly_fragment_t* dpi_reassembly_insert_fragment(
		dpi_reassembly_fragment_t** head,
		const unsigned char* data,
		u_int32_t offset, u_int32_t end, u_int32_t* bytes_removed,
		u_int32_t* bytes_inserted){
	dpi_reassembly_fragment_t *prev, *next, *iterator, *tmp;
	u_int32_t fragment_start=0;
	*bytes_removed=0;
	*bytes_inserted=0;

	/*
	 * Find the position in which this fragment must be put.
	 */

	prev=NULL;
	for(next=(*head); next!=NULL; next=next->next){
		if(dpi_reassembly_after_or_equal(next->offset, offset)){
			break;
		}
		prev=next;
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
	 *  Check for overlaps with the previous fragment. We will left the
	 *  previous fragment untouched and in case copy the new part.
	 **/
	if(prev!=NULL && dpi_reassembly_before(offset, prev->end)){
		/** If is contained in the previous fragment don't do anything.**/
		if(dpi_reassembly_before_or_equal(end, prev->end)){
			return NULL;
		}
		offset=prev->end;
		fragment_start=dpi_reassembly_fragment_length(offset, prev->end);
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
	for(iterator=next; iterator!=NULL; ){
		/**
		 * This data doesn't overlaps. The data are ordered so the
		 * successive will not overlap too.
		 **/
		if(dpi_reassembly_after_or_equal(iterator->offset, end)){
			break;
		}

		/**
		 * If the fragment 'iterator' is completely overlapped by the
		 * new fragment, then remove it.
		 **/
		if(dpi_reassembly_after_or_equal(end, iterator->end)){
			if (iterator->prev!=NULL){
				iterator->prev->next=iterator->next;
			}else{
				(*head)=iterator->next;
			}

			if (iterator->next!=NULL)
				iterator->next->prev=iterator->prev;

			tmp=iterator->next;

			(*bytes_removed)+=dpi_reassembly_fragment_length(
					iterator->offset, iterator->end);

			free(iterator->ptr);
			free(iterator);

			/**
			 * We deleted iterator, so we put the pointer back to the
			 * previous fragment. The for loop will then go to the
			 * successive data.
			 **/
			iterator=tmp;
			/** We have also to update next. **/
			next=tmp;
		}else{
		/**
		 * If it is partially overlapped, then we left the overlapped
		 * part in the old fragment.
		 **/
			end=iterator->offset;
			iterator=iterator->next;
		}

	}

	/** Insert the new fragment in the list. **/
	tmp=dpi_reassembly_create_fragment(offset, end, data+fragment_start);

	if(unlikely(tmp==NULL))
		return NULL;

	(*bytes_inserted)+=dpi_reassembly_fragment_length(offset, end);


	tmp->prev=prev;
	tmp->next=next;
	if(prev)
		prev->next=tmp;
	else
		(*head)=tmp;

	if(next)
		next->prev=tmp;
	return tmp;
}


/**
 * See there is a train of contiguous fragments.
 * @param head The pointer to the head of the list of fragments.
 * @return 0 if there are missing fragments, 1 otherwise.
 */
u_int8_t dpi_reassembly_ip_check_train_of_contiguous_fragments(
		    dpi_reassembly_fragment_t* head){
	if(!head) return 0;
	u_int16_t offset=0;

	/* Check all fragment offsets to see if they connect. */
	while(head){
		if(head->offset>offset)
			return 0;
		offset=head->end;
		head=head->next;
	}
	return 1;
}


/**
 * Compacts a train of contiguous fragments and returns it.
 * @param head A pointer to the head of the train.
 * @param where A pointer to a buffer where to put the data.
 * @param len The data_length of the buffer where to put the data.
 * @return The data_length of the recompacted data. If an error
 *                         occurred (e.g. misbehaving packet),
 *                         -1 is returned.
 */
int32_t dpi_reassembly_ip_compact_fragments(
		dpi_reassembly_fragment_t* head,
		unsigned char** where,
		u_int32_t len){
	/* Copy the data portions of all fragments into the new buffer. */
	u_int32_t fragment_length,count=0;
	while(head!=NULL){
		fragment_length=head->end-head->offset;
		if(unlikely(head->offset+fragment_length>len)){
			return -1;
		}
		memcpy(((*where)+head->offset), head->ptr, fragment_length);
		count+=fragment_length;
		head=head->next;
	}
	return count;
}
