/*
 * mysql.c
 * author: (https://github.com/InSdi) (indu.mss@gmail.com)
 * Created on: 07/06/2019
 * This protocol inspector is adapted from
 * the nDPI mysql dissector
 * (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/mysql.c)
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

uint8_t check_mysql(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private){

    if(data_length > 38
        && get_u16(app_data,0) == data_length - 4	//first 3 bytes are length
      	&& get_u8(app_data, 2) == 0x00	//3rd byte of packet length
   	    && get_u8(app_data, 3) == 0x00	//packet sequence number is 0 for startup packet
   	    && get_u8(app_data, 5) > 0x30	//server version > 0
   	    && get_u8(app_data, 5) < 0x37	//server version < 7
   	    && get_u8(app_data, 6) == 0x2e	//dot
	  ){
        u_int32_t a;
        for(a = 7; a + 31 < data_length; a++){
            if(app_data[a] == 0x00){
                if(get_u8(app_data, a + 13) == 0x00	//filler byte
                   && get_u64(app_data, a + 19) == 0x0ULL	//13 more
                   && get_u32(app_data, a + 27) == 0x0	//filler bytes
                   && get_u8(app_data, a + 31) == 0x0){       
                    return PFWL_PROTOCOL_MATCHES;
                }else{
                    return PFWL_PROTOCOL_NO_MATCHES;
                } 
            }
        }
    }
    return PFWL_PROTOCOL_MORE_DATA_NEEDED;
}

