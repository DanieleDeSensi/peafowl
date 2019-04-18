/*
 * tcp_stream_management.h
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

#ifndef TCP_STREAM_MANAGEMENT_H_
#define TCP_STREAM_MANAGEMENT_H_

#include <peafowl/peafowl.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * If the sequence number of the received segment is 'x',
 * and the expected sequence number is 'y',
 * if x-y > PFWL_TCP_MAX_OUT_OF_ORDER_BYTES, the segment will
 * not be buffered.
 */
#define PFWL_TCP_MAX_OUT_OF_ORDER_BYTES 32768

enum pfwl_tcp_reordering_statuses {
  PFWL_TCP_REORDERING_STATUS_IN_ORDER = 0,
  PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER,
  PFWL_TCP_REORDERING_STATUS_RETRANSMISSION,
  PFWL_TCP_REORDERING_STATUS_REBUILT
};

typedef struct pfwl_tcp_reordering_reordered_segment {
  unsigned char *data;
  uint32_t data_length;
  uint8_t status : 2;
  uint8_t connection_terminated : 1;
} pfwl_tcp_reordering_reordered_segment_t;

/**
 * Deletes all the pendent fragments belonging to a certain flow.
 * @param victim
 */
void pfwl_reordering_tcp_delete_all_fragments(pfwl_flow_info_private_t *victim);

/**
 * Tracks the TCP connection.
 * @param dissection_info The informations about the packet.
 * @param tracking A pointer to the structure containing the information
 *                 about the TCP connection.
 * @param pkt A pointer to the L4 packet
 * @return If the packet is out of order, if it has already been received
 *         or if an error occurred, the returned structure contains
 *         PFWL_TCP_REORDERING_STATUS_OUT_OF_ORDER in the 'status' field.
 *         The 'data' and 'data_length' fields in this case have no
 *         meaning.
 *
 * 		   If the data is in order but doesn't fill an 'hole' in the
 * 		   segment space, the returned structure contains
 * 		   PFWL_TCP_REORDERING_STATUS_IN_ORDER in the 'status' field.
 * 		   The 'data' and 'data_length' fields in this case have no
 * 		   meaning.
 *
 *         If the received data is in order and fills an 'hole' in
 *         the segment space, the returned structure contains
 *         PFWL_TCP_REORDERING_STATUS_REBUILT in the 'status' field.
 *         The 'data' field will contain a pointer to the new (longer)
 *         segment. This pointer must be freed after the use. The
 *         'data_length' field contains the length of the new (longer)
 *         segment.
 */
pfwl_tcp_reordering_reordered_segment_t
pfwl_reordering_tcp_track_connection(pfwl_dissection_info_t *dissection_info,
                                     pfwl_flow_info_private_t *tracking,
                                     const unsigned char *pkt);

/**
 * Only checks if the connection terminates.
 * @param pkt pointer to L4 packeet
 * @param dissection_info The informations about the packet.
 * @param tracking A pointer to the structure containing the informations
 *                 about the TCP connection.
 * @return 1 if the connection is terminated, 0 otherwise.
 */
uint8_t pfwl_reordering_tcp_track_connection_light(
    const unsigned char *pkt, pfwl_dissection_info_t *dissection_info,
    pfwl_flow_info_private_t *tracking);

#ifdef __cplusplus
}
#endif

#endif /* TCP_STREAM_MANAGEMENT_H_ */
