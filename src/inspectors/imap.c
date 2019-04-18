/*
 * imap.c
 *
 * This protocol inspector is adapted from
 * the nDPI IMAP dissector
 * (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/mail_imap.c)
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

uint8_t check_imap(pfwl_state_t *state, const unsigned char *app_data,
                   size_t data_length, pfwl_dissection_info_t *pkt_info,
                   pfwl_flow_info_private_t *flow_info_private) {
  uint16_t i = 0;
  uint16_t space_pos = 0;
  uint16_t command_start = 0;
  uint8_t saw_command = 0;

  if (flow_info_private->imap_starttls == 2) {
    return PFWL_PROTOCOL_MATCHES;
  }

  if (data_length >= 4 && ntohs(get_u16(app_data, data_length - 2)) == 0x0d0a) {
    // the DONE command appears without a tag
    if (data_length == 6 && ((app_data[0] == 'D' || app_data[0] == 'd') &&
                             (app_data[1] == 'O' || app_data[1] == 'o') &&
                             (app_data[2] == 'N' || app_data[2] == 'n') &&
                             (app_data[3] == 'E' || app_data[3] == 'e'))) {
      flow_info_private->imap_stage += 1;
      saw_command = 1;
    } else {
      if (flow_info_private->imap_stage < 4) {
        // search for the first space character (end of the tag)
        while (i < 20 && i < data_length) {
          if (i > 0 && app_data[i] == ' ') {
            space_pos = i;
            break;
          }
          if (!((app_data[i] >= 'a' && app_data[i] <= 'z') ||
                (app_data[i] >= 'A' && app_data[i] <= 'Z') ||
                (app_data[i] >= '0' && app_data[i] <= '9') ||
                app_data[i] == '*' || app_data[i] == '.')) {
            goto imap_excluded;
          }
          i++;
        }
        if (space_pos == 0 || space_pos == (data_length - 1)) {
          goto imap_excluded;
        }
        // now walk over a possible mail number to the next space
        i++;
        if (i < data_length && (app_data[i] >= '0' && app_data[i] <= '9')) {
          while (i < 20 && i < data_length) {
            if (i > 0 && app_data[i] == ' ') {
              space_pos = i;
              break;
            }
            if (!(app_data[i] >= '0' && app_data[i] <= '9')) {
              goto imap_excluded;
            }
            i++;
          }
          if (space_pos == 0 || space_pos == (data_length - 1)) {
            goto imap_excluded;
          }
        }
        command_start = space_pos + 1;
        /* command = &(app_data[command_start]); */
      } else {
        command_start = 0;
        /* command = &(app_data[command_start]); */
      }

      if ((command_start + 3) < data_length) {
        if ((app_data[command_start] == 'O' ||
             app_data[command_start] == 'o') &&
            (app_data[command_start + 1] == 'K' ||
             app_data[command_start + 1] == 'k') &&
            app_data[command_start + 2] == ' ') {
          flow_info_private->imap_stage += 1;
          if (flow_info_private->imap_starttls == 1)
            flow_info_private->imap_starttls = 2;
          saw_command = 1;
        } else if ((app_data[command_start] == 'U' ||
                    app_data[command_start] == 'u') &&
                   (app_data[command_start + 1] == 'I' ||
                    app_data[command_start + 1] == 'i') &&
                   (app_data[command_start + 2] == 'D' ||
                    app_data[command_start + 2] == 'd')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        }
      }
      if ((command_start + 10) < data_length) {
        if ((app_data[command_start] == 'C' ||
             app_data[command_start] == 'c') &&
            (app_data[command_start + 1] == 'A' ||
             app_data[command_start + 1] == 'a') &&
            (app_data[command_start + 2] == 'P' ||
             app_data[command_start + 2] == 'p') &&
            (app_data[command_start + 3] == 'A' ||
             app_data[command_start + 3] == 'a') &&
            (app_data[command_start + 4] == 'B' ||
             app_data[command_start + 4] == 'b') &&
            (app_data[command_start + 5] == 'I' ||
             app_data[command_start + 5] == 'i') &&
            (app_data[command_start + 6] == 'L' ||
             app_data[command_start + 6] == 'l') &&
            (app_data[command_start + 7] == 'I' ||
             app_data[command_start + 7] == 'i') &&
            (app_data[command_start + 8] == 'T' ||
             app_data[command_start + 8] == 't') &&
            (app_data[command_start + 9] == 'Y' ||
             app_data[command_start + 9] == 'y')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        }
      }
      if ((command_start + 8) < data_length) {
        if ((app_data[command_start] == 'S' ||
             app_data[command_start] == 's') &&
            (app_data[command_start + 1] == 'T' ||
             app_data[command_start + 1] == 't') &&
            (app_data[command_start + 2] == 'A' ||
             app_data[command_start + 2] == 'a') &&
            (app_data[command_start + 3] == 'R' ||
             app_data[command_start + 3] == 'r') &&
            (app_data[command_start + 4] == 'T' ||
             app_data[command_start + 4] == 't') &&
            (app_data[command_start + 5] == 'T' ||
             app_data[command_start + 5] == 't') &&
            (app_data[command_start + 6] == 'L' ||
             app_data[command_start + 6] == 'l') &&
            (app_data[command_start + 7] == 'S' ||
             app_data[command_start + 7] == 's')) {
          flow_info_private->imap_stage += 1;
          flow_info_private->imap_starttls = 1;
          saw_command = 1;
        }
      }
      if ((command_start + 5) < data_length) {
        if ((app_data[command_start] == 'L' ||
             app_data[command_start] == 'l') &&
            (app_data[command_start + 1] == 'O' ||
             app_data[command_start + 1] == 'o') &&
            (app_data[command_start + 2] == 'G' ||
             app_data[command_start + 2] == 'g') &&
            (app_data[command_start + 3] == 'I' ||
             app_data[command_start + 3] == 'i') &&
            (app_data[command_start + 4] == 'N' ||
             app_data[command_start + 4] == 'n')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'F' ||
                    app_data[command_start] == 'f') &&
                   (app_data[command_start + 1] == 'E' ||
                    app_data[command_start + 1] == 'e') &&
                   (app_data[command_start + 2] == 'T' ||
                    app_data[command_start + 2] == 't') &&
                   (app_data[command_start + 3] == 'C' ||
                    app_data[command_start + 3] == 'c') &&
                   (app_data[command_start + 4] == 'H' ||
                    app_data[command_start + 4] == 'h')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'F' ||
                    app_data[command_start] == 'f') &&
                   (app_data[command_start + 1] == 'L' ||
                    app_data[command_start + 1] == 'l') &&
                   (app_data[command_start + 2] == 'A' ||
                    app_data[command_start + 2] == 'a') &&
                   (app_data[command_start + 3] == 'G' ||
                    app_data[command_start + 3] == 'g') &&
                   (app_data[command_start + 4] == 'S' ||
                    app_data[command_start + 4] == 's')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'C' ||
                    app_data[command_start] == 'c') &&
                   (app_data[command_start + 1] == 'H' ||
                    app_data[command_start + 1] == 'h') &&
                   (app_data[command_start + 2] == 'E' ||
                    app_data[command_start + 2] == 'e') &&
                   (app_data[command_start + 3] == 'C' ||
                    app_data[command_start + 3] == 'c') &&
                   (app_data[command_start + 4] == 'K' ||
                    app_data[command_start + 4] == 'k')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'S' ||
                    app_data[command_start] == 's') &&
                   (app_data[command_start + 1] == 'T' ||
                    app_data[command_start + 1] == 't') &&
                   (app_data[command_start + 2] == 'O' ||
                    app_data[command_start + 2] == 'o') &&
                   (app_data[command_start + 3] == 'R' ||
                    app_data[command_start + 3] == 'r') &&
                   (app_data[command_start + 4] == 'E' ||
                    app_data[command_start + 4] == 'e')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        }
      }
      if ((command_start + 12) < data_length) {
        if ((app_data[command_start] == 'A' ||
             app_data[command_start] == 'a') &&
            (app_data[command_start + 1] == 'U' ||
             app_data[command_start + 1] == 'u') &&
            (app_data[command_start + 2] == 'T' ||
             app_data[command_start + 2] == 't') &&
            (app_data[command_start + 3] == 'H' ||
             app_data[command_start + 3] == 'h') &&
            (app_data[command_start + 4] == 'E' ||
             app_data[command_start + 4] == 'e') &&
            (app_data[command_start + 5] == 'N' ||
             app_data[command_start + 5] == 'n') &&
            (app_data[command_start + 6] == 'T' ||
             app_data[command_start + 6] == 't') &&
            (app_data[command_start + 7] == 'I' ||
             app_data[command_start + 7] == 'i') &&
            (app_data[command_start + 8] == 'C' ||
             app_data[command_start + 8] == 'c') &&
            (app_data[command_start + 9] == 'A' ||
             app_data[command_start + 9] == 'a') &&
            (app_data[command_start + 10] == 'T' ||
             app_data[command_start + 10] == 't') &&
            (app_data[command_start + 11] == 'E' ||
             app_data[command_start + 11] == 'e')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        }
      }
      if ((command_start + 9) < data_length) {
        if ((app_data[command_start] == 'N' ||
             app_data[command_start] == 'n') &&
            (app_data[command_start + 1] == 'A' ||
             app_data[command_start + 1] == 'a') &&
            (app_data[command_start + 2] == 'M' ||
             app_data[command_start + 2] == 'm') &&
            (app_data[command_start + 3] == 'E' ||
             app_data[command_start + 3] == 'e') &&
            (app_data[command_start + 4] == 'S' ||
             app_data[command_start + 4] == 's') &&
            (app_data[command_start + 5] == 'P' ||
             app_data[command_start + 5] == 'p') &&
            (app_data[command_start + 6] == 'A' ||
             app_data[command_start + 6] == 'a') &&
            (app_data[command_start + 7] == 'C' ||
             app_data[command_start + 7] == 'c') &&
            (app_data[command_start + 8] == 'E' ||
             app_data[command_start + 8] == 'e')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        }
      }
      if ((command_start + 4) < data_length) {
        if ((app_data[command_start] == 'L' ||
             app_data[command_start] == 'l') &&
            (app_data[command_start + 1] == 'S' ||
             app_data[command_start + 1] == 's') &&
            (app_data[command_start + 2] == 'U' ||
             app_data[command_start + 2] == 'u') &&
            (app_data[command_start + 3] == 'B' ||
             app_data[command_start + 3] == 'b')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'L' ||
                    app_data[command_start] == 'l') &&
                   (app_data[command_start + 1] == 'I' ||
                    app_data[command_start + 1] == 'i') &&
                   (app_data[command_start + 2] == 'S' ||
                    app_data[command_start + 2] == 's') &&
                   (app_data[command_start + 3] == 'T' ||
                    app_data[command_start + 3] == 't')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'N' ||
                    app_data[command_start] == 'n') &&
                   (app_data[command_start + 1] == 'O' ||
                    app_data[command_start + 1] == 'o') &&
                   (app_data[command_start + 2] == 'O' ||
                    app_data[command_start + 2] == 'o') &&
                   (app_data[command_start + 3] == 'P' ||
                    app_data[command_start + 3] == 'p')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'I' ||
                    app_data[command_start] == 'i') &&
                   (app_data[command_start + 1] == 'D' ||
                    app_data[command_start + 1] == 'd') &&
                   (app_data[command_start + 2] == 'L' ||
                    app_data[command_start + 2] == 'l') &&
                   (app_data[command_start + 3] == 'E' ||
                    app_data[command_start + 3] == 'e')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        }
      }
      if ((command_start + 6) < data_length) {
        if ((app_data[command_start] == 'S' ||
             app_data[command_start] == 's') &&
            (app_data[command_start + 1] == 'E' ||
             app_data[command_start + 1] == 'e') &&
            (app_data[command_start + 2] == 'L' ||
             app_data[command_start + 2] == 'l') &&
            (app_data[command_start + 3] == 'E' ||
             app_data[command_start + 3] == 'e') &&
            (app_data[command_start + 4] == 'C' ||
             app_data[command_start + 4] == 'c') &&
            (app_data[command_start + 5] == 'T' ||
             app_data[command_start + 5] == 't')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'E' ||
                    app_data[command_start] == 'e') &&
                   (app_data[command_start + 1] == 'X' ||
                    app_data[command_start + 1] == 'x') &&
                   (app_data[command_start + 2] == 'I' ||
                    app_data[command_start + 2] == 'i') &&
                   (app_data[command_start + 3] == 'S' ||
                    app_data[command_start + 3] == 's') &&
                   (app_data[command_start + 4] == 'T' ||
                    app_data[command_start + 4] == 't') &&
                   (app_data[command_start + 5] == 'S' ||
                    app_data[command_start + 5] == 's')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        } else if ((app_data[command_start] == 'A' ||
                    app_data[command_start] == 'a') &&
                   (app_data[command_start + 1] == 'P' ||
                    app_data[command_start + 1] == 'p') &&
                   (app_data[command_start + 2] == 'P' ||
                    app_data[command_start + 2] == 'p') &&
                   (app_data[command_start + 3] == 'E' ||
                    app_data[command_start + 3] == 'e') &&
                   (app_data[command_start + 4] == 'N' ||
                    app_data[command_start + 4] == 'n') &&
                   (app_data[command_start + 5] == 'D' ||
                    app_data[command_start + 5] == 'd')) {
          flow_info_private->imap_stage += 1;
          saw_command = 1;
        }
      }
    }

    if (saw_command == 1) {
      if (flow_info_private->imap_stage == 3 ||
          flow_info_private->imap_stage == 5) {
        return PFWL_PROTOCOL_MATCHES;
      }
    }
  }

  if (data_length > 1 && app_data[data_length - 1] == ' ') {
    flow_info_private->imap_stage = 4;
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

imap_excluded:

  // skip over possible authentication hashes etc. that cannot be identified as
  // imap commands or responses if the packet count is low enough and at least
  // one command or response was seen before
  if ((data_length >= 2 &&
       ntohs(get_u16(app_data, data_length - 2)) == 0x0d0a) &&
      flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][0] +
              flow_info_private->info_public->statistics[PFWL_STAT_L7_PACKETS][1] <
          6 &&
      flow_info_private->imap_stage >= 1) {
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
  }

  return PFWL_PROTOCOL_NO_MATCHES;
}
