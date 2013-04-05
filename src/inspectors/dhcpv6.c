/*
 * dhcpv6.c
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



#include "inspectors.h"

u_int8_t check_dhcpv6(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, u_int32_t data_length, dpi_tracking_informations_t* t){
	if (data_length >= 4 &&
		((pkt->srcport==port_dhcpv6_1 && pkt->dstport==port_dhcpv6_2) ||
		(pkt->srcport==port_dhcpv6_2 && pkt->dstport==port_dhcpv6_1)) &&
		(app_data)[0] >= 1 && (app_data)[0] <= 13) {
		return DPI_PROTOCOL_MATCHES;
	}
	return DPI_PROTOCOL_NO_MATCHES;
}

