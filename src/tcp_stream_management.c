/*
 * tcp_stream_management.c
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


#include "tcp_stream_management.h"
#include "reassembly.h"
#include "utils.h"
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <assert.h>


#define DPI_DEBUG_TCP_REORDERING 0
#define debug_print(fmt, ...)                  \
            do { if (DPI_DEBUG_TCP_REORDERING) \
            fprintf(stdout, fmt, __VA_ARGS__); } while (0)


/**
 * Deletes all the pendent fragments belonging to a certain flow.
 * @param victim
 */
void dpi_reordering_tcp_delete_all_fragments(
		dpi_tracking_informations_t *victim){
	if(victim){
		dpi_reassembly_fragment_t *frag=victim->segments[0],
				                  *temp_frag;

		while(frag){
			temp_frag=frag->next;
			free(frag->ptr);
			free(frag);
			frag=temp_frag;
		}

		frag=victim->segments[1];
		while(frag){
			temp_frag=frag->next;
			free(frag->ptr);
			free(frag);
			frag=temp_frag;
		}
	}
}

#ifndef DPI_DEBUG
static
#endif
u_int32_t dpi_reordering_tcp_length_contiguous_segments(
			dpi_reassembly_fragment_t* head){
	u_int32_t r=0;
	u_int32_t last_end=head->offset;
	while(head){
		if(head->offset!=last_end){
			return r;
		}
		r+=dpi_reassembly_fragment_length(head->offset, head->end);
		if(head->tcp_fin){
			++r;
		}
		last_end=head->end;
		head=head->next;
	}
	return r;
}


/**
 * Group a certain number of contiguous segments copying them in
 * where and freeing the old structures used to store them.
 */
#ifndef DPI_DEBUG
static
#endif
void dpi_reordering_tcp_group_contiguous_segments(
			dpi_reassembly_fragment_t** head, unsigned char** where){
	/* Copy the data portions of all segments into the new buffer. */
	u_int32_t fragment_length;
	u_int32_t offset=0, last_end=(*head)->offset;
	dpi_reassembly_fragment_t *fragment=*head;
	dpi_reassembly_fragment_t *tmp;
	while(fragment!=NULL && fragment->offset==last_end){
		fragment_length=dpi_reassembly_fragment_length(fragment->offset,
				                                       fragment->end);
		if(fragment_length!=0)
			memcpy(((*where)+offset), fragment->ptr, fragment_length);
		offset+=fragment_length;
		tmp=fragment->next;
		last_end=fragment->end;
		free(fragment->ptr);
		free(fragment);
		fragment=tmp;
	}
	*head=fragment;
	if(fragment) fragment->prev=NULL;
}

/**
 * According to RFC 1072 and RFC 793:
 * "TCP determines if a data segment is "old" or "new" by testing if
 * its sequence number is within 2**31 bytes of the left edge of the
 * window.  If not, the data is "old" and discarded."
 *
 * The left edge of the receiver correspond to its highest ack sent.
 * For this reason to ensure that the segment is new, we should check
 * that its sequence number is between highest_ack[1-pkt->direction] and
 * highest_ack[1-pkt->direction]+DPI_TCP_MAX_IN_TRAVEL_DATA.
 *
 * Anyway, expected_seq_num[direction] is in general >=
 * highest_ack_num[1-direction], so we consider
 * as left margin of the window expected_seq_num[direction]
 *
 **/
#ifndef DPI_DEBUG
static
#endif
u_int8_t dpi_reordering_tcp_is_new_segment(
		u_int32_t seqnum, dpi_tracking_informations_t* tracking,
		u_int8_t direction){
	u_int32_t lowest=tracking->expected_seq_num[direction];
	u_int32_t highest=lowest+DPI_TCP_MAX_IN_TRAVEL_DATA;

	debug_print("Window: [%"PRIu32", %"PRIu32"]\n", lowest, highest);
	if(lowest<=highest){
		return seqnum>=lowest && seqnum<=highest;
	}else{
		return !(seqnum<lowest && seqnum>highest);
	}
}

#ifndef DPI_DEBUG
static
#endif
void dpi_reordering_tcp_analyze_out_of_order(
		dpi_pkt_infos_t* pkt, dpi_tracking_informations_t* tracking,
		u_int32_t received_seq_num){
	u_int32_t end=received_seq_num+pkt->data_length;
	struct tcphdr* tcph=(struct tcphdr*) ((pkt->pkt)+(pkt->l4offset));

	if(tcph->rst==1){
		tracking->seen_rst=1;
	}
	/**
	 * We pass a dummy variable because the memory bound on TCP
	 * reordering is not implemented at the moment.
	 **/
	u_int32_t dummy;
	dpi_reassembly_fragment_t* frag;

	if(pkt->data_length==0){
		debug_print("%s\n", "The segment has no payload");
		if(tcph->fin==1 &&
		   !BIT_IS_SET(tracking->seen_fin, pkt->direction) &&
		   (frag=dpi_reassembly_insert_fragment(
				   &(tracking->segments[pkt->direction]),
			pkt->pkt+pkt->l7offset, received_seq_num, end,
			&dummy, &dummy))){
			frag->tcp_fin=1;
			SET_BIT(tracking->seen_fin, pkt->direction);
		}

		return;
	}

	frag=dpi_reassembly_insert_fragment(
			&(tracking->segments[pkt->direction]),
			pkt->pkt+pkt->l7offset,
			received_seq_num, end, &dummy, &dummy);
	if(frag && tcph->fin==1){
		frag->tcp_fin=1;
		SET_BIT(tracking->seen_fin, pkt->direction);
	}
}



/**
 * Analyze the sequence numbers and puts the data in order.
 * @param state The state of TCP reordering module.
 * @param pkt The informations about the packet.
 * @param tracking A pointer to the structure containing the
 *                 informations about the TCP connection.
 * @return Returns NULL if the packet is out of order, if it
 *         has already been received or if an error occurred.
 * 		   Otherwise it returns the reordered data. If the
 * 		   data is in order but doesn't fill an 'hole' in the
 * 		   segment space, the field 'status' is zero, the field
 * 		   'data' points to the application data and 'data_length'
 * 		   is the data_length of the application data. If the data
 * 		   fills an hole in the sequence numbers space, the field
 * 		   'status' is one, 'data' will contain a pointer to the
 * 		   status segment (it must be freed after using it) and
 * 		   'data_length' will contain the data_length of the new
 * 		   reordered segment (data part only).
 */
#ifndef DPI_DEBUG
static
#endif
dpi_tcp_reordering_reordered_segment_t
		dpi_reordering_tcp_analyze_sequence_numbers(
				dpi_pkt_infos_t* pkt,
				dpi_tracking_informations_t* tracking){

	dpi_tcp_reordering_reordered_segment_t to_return;
	to_return.data=NULL;
	to_return.data_length=0;
	to_return.connection_terminated=0;
	to_return.status=DPI_TCP_REORDERING_STATUS_IN_ORDER;

	struct tcphdr* tcph=(struct tcphdr*) ((pkt->pkt)+(pkt->l4offset));
	u_int32_t received_seq_num=ntohl(tcph->seq);
	u_int32_t expected_seq_num=tracking->expected_seq_num[pkt->direction];
	/** Automatically wrapped when exceed the 32bit limit. **/
	u_int32_t end=received_seq_num+pkt->data_length;

	debug_print("Direction: %d\n",pkt->direction);
	debug_print("Received Seq Num: %"PRIu32" Expected: %"PRIu32"\n",
			    received_seq_num,
			    tracking->expected_seq_num[pkt->direction]);

	if(received_seq_num==expected_seq_num){
		debug_print("%s\n", "Received in order segment");
		to_return.status=DPI_TCP_REORDERING_STATUS_IN_ORDER;
		tracking->expected_seq_num[pkt->direction]=end;
		if(tcph->fin==1){
			++tracking->expected_seq_num[pkt->direction];
			SET_BIT(tracking->seen_fin, pkt->direction);
		}
		if(tcph->rst==1){
			++tracking->expected_seq_num[pkt->direction];
			tracking->seen_rst=1;
		}

		/**
		 * If both FIN segments arrived and there are no more out of
		 * order segments, then the TCP connection is terminated and
		 * we can delete the flow informations.
		 **/
		if((BIT_IS_SET(tracking->seen_fin, 0) &&
            BIT_IS_SET(tracking->seen_fin, 1) &&
            tracking->segments[0]==NULL &&
            tracking->segments[1]==NULL)){
			to_return.connection_terminated=1;
		}

		if(pkt->data_length==0){
			debug_print("%s\n", "The segment has no payload");
			return to_return;
		}

		/**
		 * If there was out of order segments and this segment fills an
		 * hole, then group the segment together to make a bigger ordered
		 * segment. We check offset<=end because the received fragment
		 * could overlap with the pool_head of the segments.
		 **/
		if(tracking->segments[pkt->direction] &&
		   tracking->segments[pkt->direction]->offset<=end){
			u_int32_t overlap=
					end-tracking->segments[pkt->direction]->offset;
			u_int32_t pkt_length=pkt->data_length-overlap;

			debug_print("%s\n", "The segment fills an 'hole'");

			u_int32_t new_length=
					dpi_reordering_tcp_length_contiguous_segments(
							tracking->segments[pkt->direction])+
							pkt_length;
			unsigned char* buffer=(unsigned char*)
					malloc(sizeof(char)*(new_length));
			assert(buffer);

			memcpy(buffer, pkt->pkt+pkt->l7offset, pkt_length);
			unsigned char* where=buffer+pkt_length;
			dpi_reordering_tcp_group_contiguous_segments(
					&(tracking->segments[pkt->direction]), &where);

			to_return.data=buffer;
			to_return.data_length=new_length;
			to_return.status=DPI_TCP_REORDERING_STATUS_REBUILT;

			/**Update expected sequence number. **/
			tracking->expected_seq_num[pkt->direction]=
					received_seq_num+new_length;
		}else{
			debug_print("%s\n", "The segment doesn't fill an 'hole'");
		}
		return to_return;
	}else if(dpi_reordering_tcp_is_new_segment(received_seq_num,
			                                   tracking, pkt->direction)){
		/** Out of order segment. **/
		debug_print("Received out of order segment. Expected: %"PRIu32""
				     " Received: %"PRIu32"\n", expected_seq_num,
				     received_seq_num);
		to_return.status=DPI_TCP_REORDERING_STATUS_OUT_OF_ORDER;

		if(dpi_reassembly_fragment_length(
				expected_seq_num, received_seq_num)>
					DPI_TCP_MAX_OUT_OF_ORDER_BYTES){
			return to_return;
		}else{
			dpi_reordering_tcp_analyze_out_of_order(pkt, tracking,
					                                received_seq_num);
		}
		return to_return;
	}else{
		debug_print("Received old segment. SeqNum: %"PRIu32"\n",
				    received_seq_num);
		to_return.status=DPI_TCP_REORDERING_STATUS_OUT_OF_ORDER;
		return to_return;
	}
}

/**
 * Only checks if the connection terminates.
 * @param pkt The informations about the packet.
 * @param tracking A pointer to the structure containing the
 *                 informations about the TCP connection.
 * @return 1 if the connection is terminated, 0 otherwise.
 */
u_int8_t dpi_reordering_tcp_track_connection_light(
			dpi_pkt_infos_t* pkt, dpi_tracking_informations_t* tracking){
	struct tcphdr* tcph=(struct tcphdr*) ((pkt->pkt)+(pkt->l4offset));
	if(tcph->fin==1){
		SET_BIT(tracking->seen_fin, pkt->direction);
	}
	if(tcph->rst==1){
		tracking->seen_rst=1;
	}
	/**
	 * If both FIN segments arrived, then the TCP connection is
	 * terminated and we can delete the flow informations.
	 **/
	if((BIT_IS_SET(tracking->seen_fin, 0) &&
	   BIT_IS_SET(tracking->seen_fin, 1))){
		return 1;
	}
	return 0;
}

/**
 * Tracks the TCP connection.
 * @param pkt The informations about the packet.
 * @param tracking A pointer to the structure containing the information
 *                 about the TCP connection.
 * @return If the packet is out of order, if it has already been received
 *         or if an error occurred, the returned structure contains
 *         DPI_TCP_REORDERING_STATUS_OUT_OF_ORDER in the 'status' field.
 *         The 'data' and 'data_length' fields in this case have no
 *         meaning.
 *
 * 		   If the data is in order but doesn't fill an 'hole' in the
 * 		   segment space, the returned structure contains
 * 		   DPI_TCP_REORDERING_STATUS_IN_ORDER in the 'status' field.
 * 		   The 'data' and 'data_length' fields in this case have no
 * 		   meaning.
 *
 *         If the received data is in order and fills an 'hole' in
 *         the segment space, the returned structure contains
 *         DPI_TCP_REORDERING_STATUS_REBUILT in the 'status' field.
 *         The 'data' field will contain a pointer to the new (longer)
 *         segment. This pointer must be freed after the use. The
 *         'data_length' field contains the length of the new (longer)
 *         segment.
 */
dpi_tcp_reordering_reordered_segment_t dpi_reordering_tcp_track_connection(
		dpi_pkt_infos_t* pkt, dpi_tracking_informations_t* tracking){
	dpi_tcp_reordering_reordered_segment_t to_return;
	to_return.data=NULL;
	to_return.data_length=0;
	to_return.connection_terminated=0;
	to_return.status=DPI_TCP_REORDERING_STATUS_IN_ORDER;

	struct tcphdr* tcph=(struct tcphdr*) ((pkt->pkt)+(pkt->l4offset));

	if(tracking->seen_ack){
		debug_print("%s\n", "Connection already established, check "
				    "sequence numbers");

		return dpi_reordering_tcp_analyze_sequence_numbers(pkt, tracking);
	}else if(tcph->syn!=0 && tcph->ack==0 && tracking->seen_syn==0 &&
			 tracking->seen_syn_ack==0 && tracking->seen_ack==0){
		tracking->seen_syn=1;
		tracking->expected_seq_num[pkt->direction]=ntohl(tcph->seq)+1;

		debug_print("%s\n", "Syn received.");
		debug_print("Chosen sequence number: %"PRIu32" for direction: "
				    "%d\n", tracking->expected_seq_num[pkt->direction],
				    pkt->direction);

		to_return.status=DPI_TCP_REORDERING_STATUS_IN_ORDER;
		return to_return;
	}else if(tcph->syn!=0 && tcph->ack!=0 && tracking->seen_syn==1 &&
			 tracking->seen_syn_ack==0	&& tracking->seen_ack==0){
		tracking->seen_syn_ack=1;
		tracking->expected_seq_num[pkt->direction]=ntohl(tcph->seq)+1;

		debug_print("%s\n", "SynAck received.");
		debug_print("Chosen sequence number: %"PRIu32" for direction: "
				    "%d\n", tracking->expected_seq_num[pkt->direction],
				    pkt->direction);

		to_return.status=DPI_TCP_REORDERING_STATUS_IN_ORDER;
		return to_return;
	}else if(tcph->syn==0 && tcph->ack==1 && tracking->seen_syn==1 &&
			 tracking->seen_syn_ack==1 && tracking->seen_ack==0){
		debug_print("%s\n", "Ack received, handshake concluded.");
	    tracking->seen_ack=1;
	    /**
	     * Some TCP implementations carry data with the 3-rd handshake
	     * segment. Moreover if the 3-rd handshake segment is lost,
	     * this branch of the 'if' will be triggered by the successive
	     * segments, which can carry data. For this reason we don't
	     * exit from the function and we analyze the sequence numebers.
	     */
	    return dpi_reordering_tcp_analyze_sequence_numbers(pkt, tracking);
	}else{
		/**
		 *  Received segments from connections from which we didn't see
		 *  the syn. We observe the sequence numbers and acknowledgment
		 *  numbers in the two direction up to the point in which we
		 *  are able to understand which is the real status of the
		 *  connection (when seq and ack numbers in the two directions
		 *  coincide).
		 *  Notice that doing it in this way we will lose the data of
		 *  the first packets.
		 */
		to_return.status=DPI_TCP_REORDERING_STATUS_OUT_OF_ORDER;

		u_int32_t seq=ntohl(tcph->seq);
		u_int32_t ack=ntohl(tcph->ack_seq);
		debug_print("NOSYN branch. Direction: %d\n", pkt->direction);

		if(!BIT_IS_SET(tracking->first_packet_arrived, pkt->direction)){
			if(!tcph->syn)
				tracking->expected_seq_num[pkt->direction]=
						seq+pkt->data_length;
			else
				tracking->expected_seq_num[pkt->direction]=
						seq+1;

			tracking->highest_ack[pkt->direction]=ack;

			SET_BIT(tracking->first_packet_arrived, pkt->direction);
		}else{
			if(dpi_reassembly_after(
					seq, tracking->expected_seq_num[pkt->direction])){
				tracking->expected_seq_num[pkt->direction]=
						seq+pkt->data_length;
			}

			if(dpi_reassembly_after(
					ack, tracking->highest_ack[pkt->direction])){
				tracking->highest_ack[pkt->direction]=ack;
			}
		}

		debug_print("expected[0]: %"PRIu32" highestack[1]: %"PRIu32"\n",
				tracking->expected_seq_num[0], tracking->highest_ack[1]);
		debug_print("expected[1]: %"PRIu32" highestack[0]: %"PRIu32"\n",
				tracking->expected_seq_num[1], tracking->highest_ack[0]);

		/** Hooked! **/
		if(BIT_IS_SET(tracking->first_packet_arrived, 0) &&
		   BIT_IS_SET(tracking->first_packet_arrived, 1) &&
		   tracking->expected_seq_num[0]==tracking->highest_ack[1] &&
		   tracking->expected_seq_num[1]==tracking->highest_ack[0]){
			debug_print("%s\n", "Hooked!!!");
			/**
			 * We left seen_syn=0 because in this way we can signal that
			 * this is a connection that we didn't start looking
			 * from the beginning.
			 */
			tracking->seen_ack=1;
		    return dpi_reordering_tcp_analyze_sequence_numbers(
		    		pkt, tracking);
		}else
			return to_return;
	}
}



