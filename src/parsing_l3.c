/*
 * peafowl_l3_parsing.c
 *
 * Created on: 19/09/2012
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
#include <peafowl/config.h>
#include <peafowl/flow_table.h>
#include <peafowl/hash_functions.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/ipv4_reassembly.h>
#include <peafowl/ipv6_reassembly.h>
#include <peafowl/peafowl.h>
#include <peafowl/tcp_stream_management.h>
#include <peafowl/utils.h>

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

pfwl_status_t mc_pfwl_parse_L3_header(pfwl_state_t *state,
                                      const unsigned char *p_pkt,
                                      size_t p_length, double current_time,
                                      int tid,
                                      pfwl_dissection_info_t *dissection_info) {
  if (unlikely(p_length == 0)) {
    return PFWL_STATUS_OK;
  }
  uint8_t version;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  version = (p_pkt[0] >> 4) & 0x0F;
#elif __BYTE_ORDER == __BIG_ENDIAN
  version = (p_pkt[0] << 4) & 0x0F;
#else
#error "Please fix <bits/endian.h>"
#endif

  unsigned char *pkt = (unsigned char *) p_pkt;
  uint32_t length = p_length;

  /** Offset starting from the beginning of p_pkt. **/
  uint32_t application_offset;
  /**
   * Offset starting from the last identified IPv4 or IPv6 header
   * (used to support tunneling).
   **/
  uint32_t relative_offset;
  uint32_t tmp;
  uint8_t next_header, stop = 0;

  int8_t to_return = PFWL_STATUS_OK;

  struct ip6_hdr *ip6 = NULL;
  struct iphdr *ip4 = NULL;

  if (version == PFWL_PROTO_L3_IPV4) { /** IPv4 **/
    ip4 = (struct iphdr *) (p_pkt);
    uint16_t tot_len = ntohs(ip4->tot_len);

#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
    if (unlikely(length < (sizeof(struct iphdr)) || tot_len > length ||
                 tot_len <= ((ip4->ihl) * 4))) {
      return PFWL_ERROR_L3_PARSING;
    }
#endif
    /**
     * At this point we are sure that tot_len<=length, so we set
     * length=tot_len. In some cases indeed there may be an L2 padding
     * at the end of the packet, so capture length (length) may be
     * greater than the effective datagram length.
     */
    length = tot_len;

    uint16_t offset = ntohs(ip4->frag_off);
    uint8_t more_fragments;
    if (unlikely((offset & PFWL_IPv4_FRAGMENTATION_MF))) {
      more_fragments = 1;
    } else {
      more_fragments = 0;
    }

    /*
     * Offset is in 8-byte blocks. Multiplying by 8 correspond to a
     * right shift by 3 position, but the offset was 13 bit, so it can
     * still fit in a 16 bit integer.
     */
    offset = (offset & PFWL_IPv4_FRAGMENTATION_OFFSET_MASK) * 8;

    if (likely((!more_fragments) && (offset == 0))) {
      pkt = (unsigned char *) p_pkt;
    } else if (state->ipv4_frag_state != NULL) {
      pkt = pfwl_reordering_manage_ipv4_fragment(state->ipv4_frag_state, p_pkt,
                                                 current_time, offset,
                                                 more_fragments, tid);
      if (pkt == NULL) {
        return PFWL_STATUS_IP_FRAGMENT;
      }
      to_return = PFWL_STATUS_IP_DATA_REBUILT;
      ip4 = (struct iphdr *) (pkt);
      length = ntohs(((struct iphdr *) (pkt))->tot_len);
    } else {
      return PFWL_STATUS_IP_FRAGMENT;
    }

    dissection_info->l3.addr_src.ipv4 = ip4->saddr;
    dissection_info->l3.addr_dst.ipv4 = ip4->daddr;

    application_offset = (ip4->ihl) * 4;
    relative_offset = application_offset;
    next_header = ip4->protocol;
  } else if (version == PFWL_PROTO_L3_IPV6) { /** IPv6 **/
    ip6 = (struct ip6_hdr *) (pkt);
    uint16_t tot_len =
        ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
    if (unlikely(tot_len > length)) {
      return PFWL_ERROR_L3_PARSING;
    }
#endif

    /**
     * At this point we are sure that tot_len<=length, so we set
     * length=tot_len. In some cases indeed there may be an L2 padding
     * at the end of the packet, so capture length (length) may be
     * greater than the effective datagram length.
     */
    length = tot_len;

    dissection_info->l3.addr_src.ipv6 = ip6->ip6_src;
    dissection_info->l3.addr_dst.ipv6 = ip6->ip6_dst;

    application_offset = sizeof(struct ip6_hdr);
    relative_offset = application_offset;
    next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  } else {
    return PFWL_ERROR_WRONG_IPVERSION;
  }

  while (!stop) {
    switch (next_header) {
    case IPPROTO_HOPOPTS: { /* Hop by hop options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
      if (unlikely(application_offset + sizeof(struct ip6_hbh) > length)) {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_L3_PARSING;
      }
#endif
      if (likely(version == 6)) {
        struct ip6_hbh *hbh_hdr = (struct ip6_hbh *) (pkt + application_offset);
        tmp = (8 + hbh_hdr->ip6h_len * 8);
        application_offset += tmp;
        relative_offset += tmp;
        next_header = hbh_hdr->ip6h_nxt;
      } else {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_IPV6_HDR_PARSING;
      }
    } break;
    case IPPROTO_DSTOPTS: { /* Destination options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
      if (unlikely(application_offset + sizeof(struct ip6_dest) > length)) {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_L3_PARSING;
      }
#endif
      if (likely(version == 6)) {
        struct ip6_dest *dst_hdr =
            (struct ip6_dest *) (pkt + application_offset);
        tmp = (8 + dst_hdr->ip6d_len * 8);
        application_offset += tmp;
        relative_offset += tmp;
        next_header = dst_hdr->ip6d_nxt;
      } else {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_IPV6_HDR_PARSING;
      }
    } break;
    case IPPROTO_ROUTING: { /* Routing header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
      if (unlikely(application_offset + sizeof(struct ip6_rthdr) > length)) {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_L3_PARSING;
      }
#endif
      if (likely(version == 6)) {
        struct ip6_rthdr *rt_hdr =
            (struct ip6_rthdr *) (pkt + application_offset);
        tmp = (8 + rt_hdr->ip6r_len * 8);
        application_offset += tmp;
        relative_offset += tmp;
        next_header = rt_hdr->ip6r_nxt;
      } else {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_IPV6_HDR_PARSING;
      }
    } break;
    case IPPROTO_FRAGMENT: { /* Fragment header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
      if (unlikely(application_offset + sizeof(struct ip6_frag) > length)) {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_L3_PARSING;
      }
#endif
      if (likely(version == 6)) {
        if (state->ipv6_frag_state) {
          struct ip6_frag *frg_hdr =
              (struct ip6_frag *) (pkt + application_offset);
          uint16_t offset = ((frg_hdr->ip6f_offlg & IP6F_OFF_MASK) >> 3) * 8;
          uint8_t more_fragments =
              ((frg_hdr->ip6f_offlg & IP6F_MORE_FRAG)) ? 1 : 0;
          offset = ntohs(offset);
          uint32_t fragment_size = ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) +
                                   sizeof(struct ip6_hdr) - relative_offset -
                                   sizeof(struct ip6_frag);

          /**
           * If this fragment has been obtained from a
           * defragmentation (e.g. tunneling), then delete
           * it after that the defragmentation support has
           * copied it.
           */
          unsigned char *to_delete = NULL;
          if (pkt != p_pkt) {
            to_delete = pkt;
          }

          /*
           * For our purposes, from the unfragmentable part
           * we need only the IPv6 header, any other
           * optional header can be discarded, for this
           * reason we copy only the IPv6 header bytes.
           */
          pkt = pfwl_reordering_manage_ipv6_fragment(
              state->ipv6_frag_state, (unsigned char *) ip6,
              sizeof(struct ip6_hdr),
              ((unsigned char *) ip6) + relative_offset +
                  sizeof(struct ip6_frag),
              fragment_size, offset, more_fragments, frg_hdr->ip6f_ident,
              frg_hdr->ip6f_nxt, current_time, tid);

          if (to_delete)
            free(to_delete);

          if (pkt == NULL) {
            return PFWL_STATUS_IP_FRAGMENT;
          }

          to_return = PFWL_STATUS_IP_DATA_REBUILT;
          next_header = IPPROTO_IPV6;
          length = ((struct ip6_hdr *) (pkt))->ip6_ctlun.ip6_un1.ip6_un1_plen +
                   sizeof(struct ip6_hdr);
          /**
           * Force the next iteration to analyze the
           * reassembled IPv6 packet.
           **/
          application_offset = relative_offset = 0;
        } else {
          return PFWL_STATUS_IP_FRAGMENT;
        }
      } else {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_IPV6_HDR_PARSING;
      }
    } break;
    case IPPROTO_IPV6: /** 6in4 and 6in6 tunneling **/
      /** The real packet is now ipv6. **/
      version = 6;
      ip6 = (struct ip6_hdr *) (pkt + application_offset);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
      if (unlikely(ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) +
                       sizeof(struct ip6_hdr) >
                   length - application_offset)) {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_L3_PARSING;
      }
#endif

      dissection_info->l3.addr_src.ipv6 = ip6->ip6_src;
      dissection_info->l3.addr_dst.ipv6 = ip6->ip6_dst;

      application_offset += sizeof(struct ip6_hdr);
      relative_offset = sizeof(struct ip6_hdr);
      next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
      break;
    case 4: /* 4in4 and 4in6 tunneling */
      /** The real packet is now ipv4. **/
      version = 4;
      ip4 = (struct iphdr *) (pkt + application_offset);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
      if (unlikely(application_offset + sizeof(struct iphdr) > length ||
                   application_offset + ((ip4->ihl) * 4) > length ||
                   application_offset + ntohs(ip4->tot_len) > length)) {
        if (unlikely(pkt != p_pkt))
          free(pkt);
        return PFWL_ERROR_L3_PARSING;
      }
#endif
      dissection_info->l3.addr_src.ipv4 = ip4->saddr;
      dissection_info->l3.addr_dst.ipv4 = ip4->daddr;
      next_header = ip4->protocol;
      tmp = (ip4->ihl) * 4;
      application_offset += tmp;
      relative_offset = tmp;
      break;
    case IPPROTO_TCP: /* TCP */
    case IPPROTO_UDP: /* UDP */
    default: {        /* ICMP, RSVP, etc... */
      dissection_info->l3.length = application_offset;
      dissection_info->l4.protocol = next_header;
      stop = 1;
    } break;
    }
  }

  dissection_info->l3.protocol = version;
  if (to_return == PFWL_STATUS_IP_DATA_REBUILT) {
    dissection_info->l3.refrag_pkt = pkt;
    dissection_info->l3.refrag_pkt_len = length;
  }
  dissection_info->l3.payload_length = length - dissection_info->l3.length;
  return to_return;
}

pfwl_status_t pfwl_dissect_L3(pfwl_state_t *state, const unsigned char *pkt,
                              size_t length, double current_time,
                              pfwl_dissection_info_t *dissection_info) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  return mc_pfwl_parse_L3_header(state, pkt, length, current_time, 0,
                                 dissection_info);
}

static const char* pfwl_l3_protocols_names[PFWL_PROTO_L3_NUM] = {
  [0 ... PFWL_PROTO_L3_NUM - 1] = "",
  [PFWL_PROTO_L3_IPV4] = "IPv4",
  [PFWL_PROTO_L3_IPV6] = "IPv6",
};

const char *pfwl_get_L3_protocol_name(pfwl_protocol_l3_t protocol){
  if(protocol < PFWL_PROTO_L3_NUM){
    return pfwl_l3_protocols_names[protocol];
  }else{
    return "Unknown";
  }
}

pfwl_protocol_l3_t pfwl_get_L3_protocol_id(const char *const name){
  for(size_t i = 0; i < PFWL_PROTO_L3_NUM; i++){
    if(!strcasecmp(name, pfwl_l3_protocols_names[i])){
      return (pfwl_protocol_l3_t) i;
    }
  }
  return PFWL_PROTO_L3_NUM;
}


const char **const pfwl_get_L3_protocols_names(){
  return pfwl_l3_protocols_names;
}
