/*
 * stun.c
 *
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
 * Copyright (c) 2018-2019 Michele Campus (michelecampus5@gmail.com)
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
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define STUN_MAGIC_COOKIE 0x42A41221
#elif __BYTE_ORDER == __BIG_ENDIAN
#define STUN_MAGIC_COOKIE 0x2112A442
#else
#error "Please fix <bits/endian.h>"
#endif

struct stun_header {
  uint8_t zeros : 2;
  uint16_t msg_type : 14;
  uint16_t msg_len;
  uint32_t magic_cookie;
  uint32_t transaction_id_0;
  uint32_t transaction_id_1;
  uint32_t transaction_id_2;
} __attribute__((packed));

uint8_t check_stun(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
  struct stun_header* stun_packet = (struct stun_header*) app_data;
  if(stun_packet->zeros == 0 &&
     stun_packet->magic_cookie == STUN_MAGIC_COOKIE){
    return PFWL_PROTOCOL_MATCHES;
  }else{
    return PFWL_PROTOCOL_NO_MATCHES;
  }
}
