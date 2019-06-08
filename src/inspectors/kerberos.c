/*
 * kerberos.c
 * author: (https://github.com/InSdi) (indu.mss@gmail.com)
 * Created on: 07/06/2019
 * This protocol inspector is adapted from
 * the nDPI kerberos dissector
 * (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/kerberos.c)
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

uint8_t check_kerberos(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) {
    if(data_length >= 4 && ntohl(get_u32(app_data, 0)) == data_length - 4){
        if(data_length > 19 && 
           app_data[14] == 0x05 &&
	       (app_data[19] == 0x0a || app_data[19] == 0x0c || app_data[19] == 0x0d || app_data[19] == 0x0e)){ 
            return PFWL_PROTOCOL_MATCHES;
        }

        if(data_length > 21 && app_data[16] == 0x05 &&
           (app_data[21] == 0x0a || app_data[21] == 0x0c || app_data[21] == 0x0d || app_data[21] == 0x0e)){
            return PFWL_PROTOCOL_MATCHES;
        } 
    }
    return PFWL_PROTOCOL_NO_MATCHES;
}
