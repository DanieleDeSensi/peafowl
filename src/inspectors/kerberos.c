/*
 * Kerberos.c
 * author :indu
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
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>
#define get_u_int32_t(X,O)  (*(u_int32_t *)(((u_int8_t *)X) + O))

uint8_t check_kerberos(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
if (data_length >= 4 && ntohl(get_u_int32_t(app_data, 0)) == data_length - 4)
     {

if (data_length > 19 && app_data[14] == 0x05 &&
	(app_data[19] == 0x0a ||app_data[19] == 0x0c || app_data[19] == 0x0d || app_data[19] == 0x0e))
{ return PFWL_PROTOCOL_MATCHES;}

if (data_length > 21 && app_data[16] == 0x05 && 
(app_data[21] == 0x0a || app_data[21] == 0x0c || app_data[21] == 0x0d || app_data[21] == 0x0e)) 

{
      return PFWL_PROTOCOL_MATCHES;
    } 
}
else
      return PFWL_PROTOCOL_NO_MATCHES;

}


/*
void ndpi_search_kerberos(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
	struct ndpi_packet_struct *packet = &flow->packet;

	NDPI_LOG_DBG(ndpi_struct, "search KERBEROS\n");

	// I have observed 0a,0c,0d,0e at packet->payload[19/21], maybe there are other possibilities 
	if (packet->payload_packet_len >= 4 && ntohl(get_u_int32_t(packet->payload, 0)) == packet->payload_packet_len - 4) {
		if (packet->payload_packet_len > 19 &&
			packet->payload[14] == 0x05 &&
			(packet->payload[19] == 0x0a ||
			 packet->payload[19] == 0x0c || packet->payload[19] == 0x0d || packet->payload[19] == 0x0e)) {
			ndpi_int_kerberos_add_connection(ndpi_struct, flow);
			return;

		}
		if (packet->payload_packet_len > 21 &&
			packet->payload[16] == 0x05 &&
			(packet->payload[21] == 0x0a ||
			 packet->payload[21] == 0x0c || packet->payload[21] == 0x0d || packet->payload[21] == 0x0e)) {
			ndpi_int_kerberos_add_connection(ndpi_struct, flow);
			return;

		}
	}
	NDPI_EXCLUDE_PROTO(ndpi_struct, flow);
}


*/
