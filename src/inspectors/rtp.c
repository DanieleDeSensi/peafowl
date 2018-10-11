/**
 * rtp.c
 *
 * Created on: 29/06/2016
 *
 * =========================================================================
 *  Copyright (C) 2012-2019, Daniele De Sensi (d.desensi.software@gmail.com)
 *  Copyright (C) 2016, Lorenzo Mangani (lorenzo.mangani@gmail.com), QXIP BV
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

#include <stdio.h>
#include <string.h>

#define PFWL_DEBUG_RTP 0
#define debug_print(fmt, ...)                             \
  do {                                                    \
    if (PFWL_DEBUG_RTP) fprintf(stdout, fmt, __VA_ARGS__); \
  } while (0)

static uint8_t isValidMSRTPType(uint8_t payloadType) {
  switch (payloadType) {
    case 0:   /* G.711 u-Law */
    case 3:   /* GSM 6.10 */
    case 4:   /* G.723.1  */
    case 8:   /* G.711 A-Law */
    case 9:   /* G.722 */
    case 13:  /* Comfort Noise */
    case 18:  /* G.729 */
    case 34:  /* H.263 [MS-H26XPF] */
    case 96:  /* Dynamic RTP */
    case 97:  /* Redundant Audio Data Payload */
    case 101: /* DTMF */
    case 103: /* SILK Narrowband */
    case 104: /* SILK Wideband */
    case 111: /* Siren */
    case 112: /* G.722.1 */
    case 114: /* RT Audio Wideband */
    case 115: /* RT Audio Narrowband */
    case 116: /* G.726 */
    case 117: /* G.722 */
    case 118: /* Comfort Noise Wideband */
    case 121: /* RT Video */
    case 122: /* H.264 [MS-H264PF] */
    case 123: /* H.264 FEC [MS-H264PF] */
    case 127: /* x-data */
      return (1 /* RTP */);
      break;

    case 200: /* RTCP PACKET SENDER */
    case 201: /* RTCP PACKET RECEIVER */
    case 202: /* RTCP Source Description */
    case 203: /* RTCP Bye */
      return (2 /* RTCP */);
      break;

    default:
      return (0);
  }
}

uint8_t check_rtp(pfwl_state_t* state, const unsigned char* app_data, size_t data_length, pfwl_dissection_info_t* pkt_info,
                  pfwl_flow_info_private_t* flow_info_private) {
  if (pkt_info->l4.protocol != IPPROTO_UDP) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }
  if (data_length < 2 || pkt_info->l4.port_dst <= 1024 || pkt_info->l4.port_src <= 1024) {
    return PFWL_PROTOCOL_NO_MATCHES;
  }

  uint8_t data_type = app_data[1] & 0x7F;
  // TODO: Accede ad app_data[8] senza controllare che la lunghezza di app_data
  // (data_length) sia almeno 8
  uint32_t* ssid = (uint32_t*)&app_data[8];

  if (data_length >= 12) {
    if ((app_data[0] & 0xFF) == 0x80 ||
        (app_data[0] & 0xFF) == 0xA0) /* RTP magic byte[1] */
    {
      uint8_t payloadType;
      if (((data_type < 72) || (data_type > 76)) &&
          ((data_type <= 34) || ((data_type >= 96) && (data_type <= 127))) &&
          (*ssid != 0)) {
        return PFWL_PROTOCOL_MATCHES;
      }

      else if ((payloadType = isValidMSRTPType(app_data[1] & 0xFF)) &&
               (payloadType == 1)) {
        return PFWL_PROTOCOL_MATCHES;
      }
    } else {
      return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    }
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
