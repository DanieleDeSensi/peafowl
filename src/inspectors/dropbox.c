/*
 * dropbox.c
 *
 * This protocol inspector is adapted from
 * the nDPI Dropbox dissector (https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/dropbox.c)
 *
 * Infos about Dropbox LAN sync protocol: https://blogs.dropbox.com/tech/2015/10/inside-lan-sync/
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

static inline uint8_t lowCheck(const char* app_data) {
  return strstr((const char*) app_data, "\"host_int\"")?1:0;
}

static inline uint8_t midCheck(const char* app_data) {
  return strstr((const char*) app_data, "\"namespaces\"")?1:0;
}

static inline uint8_t highCheck(const char* app_data) {
  return (strstr((const char*) app_data, "\"version\"")?1:0) &&
         (strstr((const char*) app_data, "\"port\"")?1:0);
}

static inline uint8_t hasDropboxFields(const char* app_data, pfwl_inspector_accuracy_t accuracy) {
  switch(accuracy){
    case PFWL_INSPECTOR_ACCURACY_LOW:{
      return lowCheck(app_data);
    }break;
    case PFWL_INSPECTOR_ACCURACY_MEDIUM:{
      return lowCheck(app_data) && midCheck(app_data);
    }break;
    case PFWL_INSPECTOR_ACCURACY_HIGH:{
      return lowCheck(app_data) && midCheck(app_data) && highCheck(app_data);
    }break;
    default:{
      return 0;
    }
  }
}

uint8_t check_dropbox(const unsigned char* app_data, uint32_t data_length, pfwl_identification_result_t* pkt_info,
                   pfwl_tracking_informations_t* tracking_info, pfwl_inspector_accuracy_t accuracy, uint8_t *required_fields){
  if(pkt_info->protocol_l4 == IPPROTO_UDP &&
     pkt_info->port_src == port_dropbox && pkt_info->port_dst == port_dropbox &&
     data_length > 2 && hasDropboxFields((const char*) app_data, accuracy)) {
    return PFWL_PROTOCOL_MATCHES;
  }
  return PFWL_PROTOCOL_NO_MATCHES;
}
