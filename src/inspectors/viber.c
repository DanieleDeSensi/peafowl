/*
 * viber.c
 * Created by : Indu 
 * Created on: 30/05/2019
 * SignatureDerived from : nDPI
 * =========================================================================
 * 
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
uint8_t check_viber(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
 
if(app_data)
//printf("%x %x %x\n",app_data[0],app_data[2],app_data[3]);
  if((data_length == 12 && app_data[2] == 0x03 && app_data[3] == 0x00)
       || (data_length == 20 && app_data[2] == 0x09 && app_data[3] == 0x00)
       || ((data_length < 135) && (app_data[0] == 0x11))) {
     printf("%s","protocol matches\n");
      return PFWL_PROTOCOL_MATCHES;
    } else
      return PFWL_PROTOCOL_NO_MATCHES;


  } 



/*

    if((packet->payload_packet_len == 12 && packet->payload[2] == 0x03 && packet->payload[3] == 0x00)
       || (packet->payload_packet_len == 20 && packet->payload[2] == 0x09 && packet->payload[3] == 0x00)
       || ((packet->payload_packet_len < 135) && (packet->payload[0] == 0x11))) {
      NDPI_LOG_DBG(ndpi_struct, "found VIBER\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VIBER, NDPI_PROTOCOL_UNKNOWN);
      return;
*/
