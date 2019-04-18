/*
 * tcp_stream_management.c
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
#include <peafowl/flow_table.h>
#include <peafowl/reassembly.h>
#include <peafowl/tcp_stream_management.h>
#include <peafowl/utils.h>

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define PFWL_DEBUG_TCP_REORDERING 0
#define debug_print(fmt, ...)                                                  \
  do {                                                                         \
    if (PFWL_DEBUG_TCP_REORDERING)                                             \
      fprintf(stdout, fmt, __VA_ARGS__);                                       \
  } while (0)

void pfwl_reordering_tcp_delete_all_fragments(
    pfwl_flow_info_private_t *victim) {
  if (victim) {
    pfwl_reassembly_fragment_t *frag = victim->segments[0], *temp_frag;

    while (frag) {
      temp_frag = frag->next;
      free(frag->ptr);
      free(frag);
      frag = temp_frag;
    }

    frag = victim->segments[1];
    while (frag) {
      temp_frag = frag->next;
      free(frag->ptr);
      free(frag);
      frag = temp_frag;
    }
  }
}

#ifndef PFWL_DEBUG
static
#endif
    uint32_t
    pfwl_reordering_tcp_length_contiguous_segments(
        pfwl_reassembly_fragment_t *head) {
  uint32_t r = 0;
  uint32_t last_end = head->offset;
  while (head) {
    if (head->offset != last_end) {
      return r;
    }
    r += pfwl_reassembly_fragment_length(head->offset, head->end);
    if (head->tcp_fin) {
      ++r;
    }
    last_end = head->end;
    head = head->next;
  }
  return r;
}

/**
 * Group a certain number of contiguous segments copying them in
 * where and freeing the old structures used to store them.
 */
#ifndef PFWL_DEBUG
static
#endif
    void
    pfwl_reordering_tcp_group_contiguous_segments(
        pfwl_reassembly_fragment_t **head, unsigned char **where) {
  /* Copy the data portions of all segments into the new buffer. */
  uint32_t offset = 0, last_end = (*head)->offset;
  pfwl_reassembly_fragment_t *fragment = *head;
  pfwl_reassembly_fragment_t *tmp;
  while (fragment != NULL && fragment->offset == last_end) {
    uint32_t fragment_length =
        pfwl_reassembly_fragment_length(fragment->offset, fragment->end);
    if (fragment_length != 0)
      memcpy(((*where) + offset), fragment->ptr, fragment_length);
    offset += fragment_length;
    tmp = fragment->next;
    last_end = fragment->end;
    free(fragment->ptr);
    free(fragment);
    fragment = tmp;
  }
  *head = fragment;
  if (fragment)
    fragment->prev = NULL;
}

/**
 * According to RFC 1072 and RFC 793:
 * "TCP determines if a data segment is "old" or "new" by testing if
 * its sequence number is within 2**31 bytes of the left edge of the
 * window.  If not, the data is "old" and discarded."
 *
 * The left edge of the receiver correspond to its highest ack sent.
 * For this reason to ensure that the segment is new, we should check
 * that its sequence number is between highest_ack[1-pkt->l4.direction] and
 * highest_ack[1-pkt->l4.direction]+PFWL_TCP_MAX_IN_TRAVEL_DATA.
 *
 * Anyway, expected_seq_num[direction] is in general >=
 * highest_ack_num[1-direction], so we consider
 * as left margin of the window expected_seq_num[direction]
 *
 **/
#ifndef PFWL_DEBUG
static
#endif
    uint8_t
    pfwl_reordering_tcp_is_new_segment(uint32_t seqnum,
                                       pfwl_flow_info_private_t *tracking,
                                       uint8_t direction) {
  uint32_t lowest = tracking->expected_seq_num[direction];
  uint32_t highest = lowest + PFWL_TCP_MAX_IN_TRAVEL_DATA;

  debug_print("Window: [%" PRIu32 ", %" PRIu32 "]\n", lowest, highest);
  if (lowest <= highest) {
    return seqnum >= lowest && seqnum <= highest;
  } else {
    return !(seqnum < lowest && seqnum > highest);
  }
}

#ifndef PFWL_DEBUG
static
#endif
    void
    pfwl_reordering_tcp_analyze_out_of_order(
        const unsigned char *pkt, pfwl_dissection_info_t *dissection_info,
        pfwl_flow_info_private_t *tracking, uint32_t received_seq_num) {
  uint32_t end = received_seq_num + dissection_info->l4.payload_length;
  struct tcphdr *tcph = (struct tcphdr *) (pkt);

  if (tcph->rst == 1) {
    tracking->seen_rst = 1;
  }
  /**
   * We pass a dummy variable because the memory bound on TCP
   * reordering is not implemented at the moment.
   **/
  uint32_t dummy;
  pfwl_reassembly_fragment_t *frag;

  if (dissection_info->l4.payload_length == 0) {
    debug_print("%s\n", "The segment has no payload");
    if (tcph->fin == 1 &&
        !BIT_IS_SET(tracking->seen_fin, dissection_info->l4.direction) &&
        (frag = pfwl_reassembly_insert_fragment(
             &(tracking->segments[dissection_info->l4.direction]),
             pkt + dissection_info->l4.length, received_seq_num, end, &dummy,
             &dummy))) {
      frag->tcp_fin = 1;
      SET_BIT(tracking->seen_fin, dissection_info->l4.direction);
    }

    return;
  }

  frag = pfwl_reassembly_insert_fragment(
      &(tracking->segments[dissection_info->l4.direction]),
      pkt + dissection_info->l4.length, received_seq_num, end, &dummy, &dummy);
  if (frag && tcph->fin == 1) {
    frag->tcp_fin = 1;
    SET_BIT(tracking->seen_fin, dissection_info->l4.direction);
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
#ifndef PFWL_DEBUG
static
#endif
    pfwl_tcp_reordering_reordered_segment_t
    pfwl_reordering_tcp_analyze_sequence_numbers(
        const unsigned char *pkt, pfwl_dissection_info_t *dissection_info,
        pfwl_flow_info_private_t *tracking) {

  pfwl_tcp_reordering_reordered_segment_t to_return;
  to_return.data = NULL;
  to_return.data_length = 0;
  to_return.connection_terminated = 0;
  to_return.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;

  struct tcphdr *tcph = (struct tcphdr *) (pkt);
  pfwl_direction_t direction = dissection_info->l4.direction;
  uint32_t received_seq_num = ntohl(tcph->seq);
  uint32_t expected_seq_num =
      tracking->expected_seq_num[direction];
  /** Automatically wrapped when exceed the 32bit limit. **/
  uint32_t end = received_seq_num + dissection_info->l4.payload_length;

  debug_print("Direction: %d\n", direction);
  debug_print("Received Seq Num: %" PRIu32 " Expected: %" PRIu32 "\n",
              received_seq_num,
              tracking->expected_seq_num[direction]);

  if (received_seq_num == expected_seq_num) {
    debug_print("%s\n", "Received in order segment");
    to_return.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;
    tracking->expected_seq_num[direction] = end;
    if (tcph->fin == 1) {
      ++tracking->expected_seq_num[direction];
      SET_BIT(tracking->seen_fin, direction);
    }
    if (tcph->rst == 1) {
      ++tracking->expected_seq_num[direction];
      tracking->seen_rst = 1;
    }

    /**
     * If both FIN segments arrived and there are no more out of
     * order segments, then the TCP connection is terminated and
     * we can delete the flow informations.
     **/
    if ((BIT_IS_SET(tracking->seen_fin, 0) &&
         BIT_IS_SET(tracking->seen_fin, 1) && tracking->segments[0] == NULL &&
         tracking->segments[1] == NULL)) {
      if (BIT_IS_SET(tracking->seen_fin_ack, 0)) {
        to_return.connection_terminated = 1;
      } else {
        SET_BIT(tracking->seen_fin_ack, 0);
      }
    }

    if (dissection_info->l4.payload_length == 0) {
      debug_print("%s\n", "The segment has no payload");
      if(!tracking->seen_fin &&
         (!pfwl_reordering_tcp_is_new_segment(received_seq_num, tracking, direction) ||
          (tracking->last_seq[direction] == tcph->seq && tracking->last_ack[direction] == tcph->ack_seq))){
        to_return.status = PFWL_TCP_REORDERING_STATUS_RETRANSMISSION;
      }
      tracking->last_seq[direction] = tcph->seq;
      tracking->last_ack[direction] = tcph->ack_seq;
      return to_return;
    }

    tracking->last_seq[direction] = tcph->seq;
    tracking->last_ack[direction] = tcph->ack_seq;

    /**
     * If there was out of order segments and this segment fills an
     * hole, then group the segment together to make a bigger ordered
     * segment. We check offset<=end because the received fragment
     * could overlap with the pool_head of the segments.
     **/
    if (tracking->segments[direction] &&
        tracking->segments[direction]->offset <= end) {
      uint32_t overlap =
          end - tracking->segments[dissection_info->l4.direction]->offset;
      uint32_t pkt_length = dissection_info->l4.payload_length - overlap;

      debug_print("%s\n", "The segment fills an 'hole'");

      uint32_t new_length =
          pfwl_reordering_tcp_length_contiguous_segments(
              tracking->segments[dissection_info->l4.direction]) +
          pkt_length;
      unsigned char *buffer =
          (unsigned char *) malloc(sizeof(char) * (new_length));
      assert(buffer);

      memcpy(buffer, pkt + dissection_info->l4.length, pkt_length);
      unsigned char *where = buffer + pkt_length;
      pfwl_reordering_tcp_group_contiguous_segments(
          &(tracking->segments[dissection_info->l4.direction]), &where);

      to_return.data = buffer;
      to_return.data_length = new_length;
      to_return.status = PFWL_TCP_REORDERING_STATUS_REBUILT;

      /**Update expected sequence number. **/
      tracking->expected_seq_num[dissection_info->l4.direction] =
          received_seq_num + new_length;
    } else {
      debug_print("%s\n", "The segment doesn't fill an 'hole'");
    }
    return to_return;
  } else if (pfwl_reordering_tcp_is_new_segment(
                 received_seq_num, tracking, dissection_info->l4.direction)) {
    /** Out of order segment. **/
    debug_print("Received out of order segment. Expected: %" PRIu32 ""
                " Received: %" PRIu32 "\n",
                expected_seq_num, received_seq_num);
    to_return.status = PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER;

    if (pfwl_reassembly_fragment_length(expected_seq_num, received_seq_num) >
        PFWL_TCP_MAX_OUT_OF_ORDER_BYTES) {
      return to_return;
    } else {
      pfwl_reordering_tcp_analyze_out_of_order(pkt, dissection_info, tracking,
                                               received_seq_num);
    }
    return to_return;
  } else {
    debug_print("Received old segment. SeqNum: %" PRIu32 "\n",
                received_seq_num);
    to_return.status = PFWL_TCP_REORDERING_STATUS_RETRANSMISSION;
    return to_return;
  }
}

uint8_t pfwl_reordering_tcp_track_connection_light(
    const unsigned char *pkt, pfwl_dissection_info_t *dissection_info,
    pfwl_flow_info_private_t *tracking) {
  struct tcphdr *tcph = (struct tcphdr *) pkt;
  if (tcph->fin == 1) {
    SET_BIT(tracking->seen_fin, dissection_info->l4.direction);
  }
  if (tcph->rst == 1) {
    tracking->seen_rst = 1;
  }
  /**
   * If both FIN segments arrived, then the TCP connection is
   * terminated and we can delete the flow informations.
   **/
  if ((BIT_IS_SET(tracking->seen_fin, 0) &&
       BIT_IS_SET(tracking->seen_fin, 1))) {
    if (BIT_IS_SET(tracking->seen_fin_ack, 0)) {
      return 1;
    } else {
      SET_BIT(tracking->seen_fin_ack, 0);
    }
  }
  return 0;
}

pfwl_tcp_reordering_reordered_segment_t
pfwl_reordering_tcp_track_connection(pfwl_dissection_info_t *dissection_info,
                                     pfwl_flow_info_private_t *tracking,
                                     const unsigned char *pkt) {
  pfwl_tcp_reordering_reordered_segment_t to_return;
  to_return.data = NULL;
  to_return.data_length = 0;
  to_return.connection_terminated = 0;
  to_return.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;

  struct tcphdr *tcph = (struct tcphdr *) pkt;

  if (tracking->seen_ack) {
    debug_print("%s\n", "Connection already established, check "
                        "sequence numbers");

    return pfwl_reordering_tcp_analyze_sequence_numbers(pkt, dissection_info,
                                                        tracking);
  } else if (tcph->syn != 0 && tcph->ack == 0 && tracking->seen_syn == 0 &&
             tracking->seen_syn_ack == 0 && tracking->seen_ack == 0) {
    tracking->seen_syn = 1;
    tracking->expected_seq_num[dissection_info->l4.direction] =
        ntohl(tcph->seq) + 1;

    debug_print("%s\n", "Syn received.");
    debug_print("Chosen sequence number: %" PRIu32 " for direction: "
                "%d\n",
                tracking->expected_seq_num[dissection_info->l4.direction],
                dissection_info->l4.direction);

    to_return.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;
    return to_return;
  } else if (tcph->syn != 0 && tcph->ack != 0 && tracking->seen_syn == 1 &&
             tracking->seen_syn_ack == 0 && tracking->seen_ack == 0) {
    tracking->seen_syn_ack = 1;
    tracking->expected_seq_num[dissection_info->l4.direction] =
        ntohl(tcph->seq) + 1;

    debug_print("%s\n", "SynAck received.");
    debug_print("Chosen sequence number: %" PRIu32 " for direction: "
                "%d\n",
                tracking->expected_seq_num[dissection_info->l4.direction],
                dissection_info->l4.direction);

    to_return.status = PFWL_TCP_REORDERING_STATUS_IN_ORDER;
    return to_return;
  } else if (tcph->syn == 0 && tcph->ack == 1 && tracking->seen_syn == 1 &&
             tracking->seen_syn_ack == 1 && tracking->seen_ack == 0) {
    debug_print("%s\n", "Ack received, handshake concluded.");
    tracking->seen_ack = 1;
    /**
     * Some TCP implementations carry data with the 3-rd handshake
     * segment. Moreover if the 3-rd handshake segment is lost,
     * this branch of the 'if' will be triggered by the successive
     * segments, which can carry data. For this reason we don't
     * exit from the function and we analyze the sequence numebers.
     */
    return pfwl_reordering_tcp_analyze_sequence_numbers(pkt, dissection_info,
                                                        tracking);
  } else {
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
    to_return.status = PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER;

    uint32_t seq = ntohl(tcph->seq);
    uint32_t ack = ntohl(tcph->ack_seq);
    debug_print("NOSYN branch. Direction: %d\n", dissection_info->l4.direction);

    if (!BIT_IS_SET(tracking->first_packet_arrived,
                    dissection_info->l4.direction)) {
      if (!tcph->syn)
        tracking->expected_seq_num[dissection_info->l4.direction] =
            seq + dissection_info->l4.payload_length;
      else
        tracking->expected_seq_num[dissection_info->l4.direction] = seq + 1;

      tracking->highest_ack[dissection_info->l4.direction] = ack;

      SET_BIT(tracking->first_packet_arrived, dissection_info->l4.direction);
    } else {
      if (pfwl_reassembly_after(
              seq, tracking->expected_seq_num[dissection_info->l4.direction])) {
        tracking->expected_seq_num[dissection_info->l4.direction] =
            seq + dissection_info->l4.payload_length;
      }

      if (pfwl_reassembly_after(
              ack, tracking->highest_ack[dissection_info->l4.direction])) {
        tracking->highest_ack[dissection_info->l4.direction] = ack;
      }
    }

    debug_print("expected[0]: %" PRIu32 " highestack[1]: %" PRIu32 "\n",
                tracking->expected_seq_num[0], tracking->highest_ack[1]);
    debug_print("expected[1]: %" PRIu32 " highestack[0]: %" PRIu32 "\n",
                tracking->expected_seq_num[1], tracking->highest_ack[0]);

    /** Hooked! **/
    if (BIT_IS_SET(tracking->first_packet_arrived, 0) &&
        BIT_IS_SET(tracking->first_packet_arrived, 1) &&
        tracking->expected_seq_num[0] == tracking->highest_ack[1] &&
        tracking->expected_seq_num[1] == tracking->highest_ack[0]) {
      debug_print("%s\n", "Hooked!!!");
      /**
       * We left seen_syn=0 because in this way we can signal that
       * this is a connection that we didn't start looking
       * from the beginning.
       */
      tracking->seen_ack = 1;
      return pfwl_reordering_tcp_analyze_sequence_numbers(pkt, dissection_info,
                                                          tracking);
    } else
      return to_return;
  }
}
