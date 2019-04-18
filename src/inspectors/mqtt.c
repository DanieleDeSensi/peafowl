/*
 * mqtt.c
 * (http://www.steves-internet-guide.com/mqtt-protocol-messages-overview/)
 *
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

static uint8_t mqtt_validate_length(const unsigned char *app_data, size_t data_length){
  size_t current_length = 0;
  size_t byte_idx = 1;
  uint8_t continuation = 1;
  while(data_length > byte_idx && byte_idx <= 4){
    current_length = (current_length << 8) | (app_data[byte_idx] & 0x7F);
    continuation = app_data[byte_idx] & 0x80;
    if(!continuation){
      break;
    }
    byte_idx++;
  }
  if(continuation ||
     current_length != data_length - 1 - byte_idx){
    return 0;
  }
  return 1;
}

uint8_t check_mqtt(pfwl_state_t *state, const unsigned char *app_data,
                      size_t data_length, pfwl_dissection_info_t *pkt_info,
                      pfwl_flow_info_private_t *flow_info_private) {
  uint8_t control_hdr = app_data[0];
  uint8_t pkt_type = control_hdr >> 4;
  uint8_t len_valid = mqtt_validate_length(app_data, data_length);
  //uint8_t flags = control_hdr | 0xF;
  if(flow_info_private->seen_syn){
    if(pkt_info->flow_info.statistics[PFWL_STAT_L7_PACKETS][0] == 1){
      if(pkt_type & 0x1 && len_valid){
        return PFWL_PROTOCOL_MORE_DATA_NEEDED;
      }
    }else if(pkt_info->flow_info.statistics[PFWL_STAT_L7_PACKETS][1] == 1){
      if(pkt_type & 0x2 && len_valid){
        return PFWL_PROTOCOL_MATCHES;
      }
    }
  }else if(len_valid){
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
