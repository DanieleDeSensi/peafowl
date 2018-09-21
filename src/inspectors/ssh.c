/*
 * ssh.c
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
#include <peafowl/peafowl.h>
#include <peafowl/inspectors/inspectors.h>

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

uint8_t check_ssh(pfwl_library_state_t* state, pfwl_pkt_infos_t* pkt,
                  const unsigned char* app_data, uint32_t data_length,
                  pfwl_tracking_informations_t* t) {
    if (pkt->direction == 0) {
        // Client -> Server)
        if (data_length > 7 && data_length < 100 &&
            memcmp(app_data, "SSH-", 4) == 0) {
            /*
            if (pfwl_metadata_extraction(PFWL_PROTOCOL_SSH)) {
                t->ssh_client_signature = malloc(sizeof(char)*(data_length + 1));
                strncpy(t->ssh_client_signature, (const char *) app_data, data_length);
                t->ssh_client_signature[data_length] = '\0';
                ssh_zap_cr(t->ssh_client_signature, data_length);
            }
            */
            ++t->ssh_stage;
        }
    } else {
        // Server -> Client
        if (data_length > 7 && data_length < 500 &&
            memcmp(app_data, "SSH-", 4) == 0) {
            /*
            if (pfwl_metadata_extraction(PFWL_PROTOCOL_SSH)) {
                t->ssh_server_signature = malloc(sizeof(char)*(data_length + 1));
                strncpy(t->ssh_server_signature, (const char *) app_data, data_length);
                t->ssh_server_signature[data_length] = '\0';
                ssh_zap_cr(t->ssh_server_signature, data_length);
            }
            */
            ++t->ssh_stage;
        }
    }

    if (t->ssh_stage >= 2) {
        return PFWL_PROTOCOL_MATCHES;
    } else {
        return PFWL_PROTOCOL_MORE_DATA_NEEDED;
    }

    return PFWL_PROTOCOL_NO_MATCHES;
}
