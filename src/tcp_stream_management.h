/*
 * tcp_stream_management.h
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

#ifndef TCP_STREAM_MANAGEMENT_H_
#define TCP_STREAM_MANAGEMENT_H_

#include <sys/types.h>
#include "api.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * If the sequence number of the received segment is 'x',
 * and the expected sequence number is 'y',
 * if x-y > DPI_TCP_MAX_OUT_OF_ORDER_BYTES, the segment will
 * not be buffered.
 */
#define DPI_TCP_MAX_OUT_OF_ORDER_BYTES 32768


enum dpi_tcp_reordering_statuses{
	DPI_TCP_REORDERING_STATUS_IN_ORDER=0
   ,DPI_TCP_REORDERING_STATUS_OUT_OF_ORDER
   ,DPI_TCP_REORDERING_STATUS_REBUILT
};



typedef struct dpi_tcp_reordering_reordered_segment{
	unsigned char* data;
	u_int32_t data_length;
	u_int8_t status:2;
	u_int8_t connection_terminated:1;
}dpi_tcp_reordering_reordered_segment_t;


/**
 * Deletes all the pendent fragments belonging to a certain flow.
 * @param victim
 */
void dpi_reordering_tcp_delete_all_fragments(
		dpi_tracking_informations_t *victim);


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
dpi_tcp_reordering_reordered_segment_t dpi_reordering_tcp_track_connection
	(dpi_pkt_infos_t* pkt, dpi_tracking_informations_t* tracking);

/**
 * Only checks if the connection terminates.
 * @param pkt The informations about the packet.
 * @param tracking A pointer to the structure containing the informations
 *                 about the TCP connection.
 * @return 1 if the connection is terminated, 0 otherwise.
 */
u_int8_t dpi_reordering_tcp_track_connection_light
	(dpi_pkt_infos_t* pkt, dpi_tracking_informations_t* tracking);

#ifdef __cplusplus
}
#endif

#endif /* TCP_STREAM_MANAGEMENT_H_ */
