/* tor.c
* Author : Indu  29/5/2019
* Signature Derived From:nDPI
*/

#include <peafowl/inspectors/inspectors.h>
#include <peafowl/peafowl.h>

uint8_t check_tor(pfwl_state_t *state, const unsigned char *app_data,
                  size_t data_length, pfwl_dissection_info_t *pkt_info,
                  pfwl_flow_info_private_t *flow_info_private) 
{


//if((((pkt_info->l4.port_dst == 9001) || (pkt_info->l4.port_src == 9001)) || ((pkt_info->l4.port_dst == 9030) || (pkt_info->l4.port_src == 9030)))
	//&&
 if (((app_data[0] == 0x17) || (app_data[0] == 0x16)) 
	&& (app_data[1] == 0x03) 
	&& (app_data[2] == 0x01) 
	&& (app_data[3] == 0x00))
     {
      printf("%s","Protocol Matches\n");
      return PFWL_PROTOCOL_MATCHES;
    } else
      return PFWL_PROTOCOL_NO_MATCHES;
  } 
