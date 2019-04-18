/*
 * ssh.c
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

/*
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static void ssh_zap_cr(char *str, int len) {
    len--;

    while(len > 0) {
        if((str[len] == '\n') || (str[len] == '\r')) {
            str[len] = '\0';
            len--;
        } else
            break;
    }
}
*/

#define PFWL_SSH_MAX_ATTEMPTS 6

uint8_t check_ssh(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
  if (pkt_info->l4.direction == 0) {
    // Client -> Server)
    if (data_length > 7 && data_length < 100 &&
        memcmp(app_data, "SSH-", 4) == 0) {
      /*
      if (pfwl_metadata_extraction(PFWL_PROTOCOL_SSH)) {
          t->ssh_client_signature = malloc(sizeof(char)*(data_length + 1));
          strncpy(t->ssh_client_signature, (const char *) app_data,
      data_length); t->ssh_client_signature[data_length] = '\0';
          ssh_zap_cr(t->ssh_client_signature, data_length);
      }
      */
      ++flow_info_private->ssh_stage;
    }
  } else {
    // Server -> Client
    if (data_length > 7 && data_length < 500 &&
        memcmp(app_data, "SSH-", 4) == 0) {
      /*
      if (pfwl_metadata_extraction(PFWL_PROTOCOL_SSH)) {
          t->ssh_server_signature = malloc(sizeof(char)*(data_length + 1));
          strncpy(t->ssh_server_signature, (const char *) app_data,
      data_length); t->ssh_server_signature[data_length] = '\0';
          ssh_zap_cr(t->ssh_server_signature, data_length);
      }
      */
      ++flow_info_private->ssh_stage;
    }
  }

  if (flow_info_private->ssh_stage >= 2) {
    return PFWL_PROTOCOL_MATCHES;
  } else if(flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][0] +
            flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][1] < PFWL_SSH_MAX_ATTEMPTS){
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
