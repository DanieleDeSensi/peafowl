/*
 * whatsapp.c
 *
 * This protocol inspector is adapted from
 * the nDPI WhatsApp dissector (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/whatsapp.c)
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
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
#include <peafowl/peafowl.h>
#include <peafowl/inspectors/inspectors.h>

static uint8_t whatsapp_sequence[] = {
    0x45, 0x44, 0x0, 0x01, 0x0, 0x0, 0x02, 0x08,
    0x0, 0x57, 0x41, 0x02, 0x0, 0x0, 0x0
 };

#define MIN(x, y) ({	       \
      __typeof__ (x) _x = (x); \
      __typeof__ (y) _y = (y); \
      _x < _y ? _x : _y;       \
})

uint8_t check_whatsapp(pfwl_state_t* state, const unsigned char* app_data, size_t data_length, pfwl_dissection_info_t* pkt_info,
                      pfwl_flow_info_private_t* flow_info_private){
  if(flow_info_private->whatsapp_matched_sequence < sizeof(whatsapp_sequence)) {
    if(memcmp(app_data, &whatsapp_sequence[flow_info_private->whatsapp_matched_sequence], 
      MIN(sizeof(whatsapp_sequence) - flow_info_private->whatsapp_matched_sequence, data_length))) {
      return PFWL_PROTOCOL_NO_MATCHES;
    } else {
      flow_info_private->whatsapp_matched_sequence += data_length;
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    }
  } else {
    return PFWL_PROTOCOL_MATCHES;
  }
}
