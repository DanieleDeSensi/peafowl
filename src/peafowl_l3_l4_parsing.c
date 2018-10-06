/*
 * peafowl_l3_l4_parsing.c
 *
 * Created on: 19/09/2012
 * =========================================================================
 * Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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
#include <peafowl/config.h>
#include <peafowl/flow_table.h>
#include <peafowl/hash_functions.h>
#include <peafowl/inspectors/inspectors.h>
#include <peafowl/ipv4_reassembly.h>
#include <peafowl/ipv6_reassembly.h>
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

void mc_pfwl_parse_L3_L4_header(pfwl_state_t* state,
                                const unsigned char* p_pkt,
                                uint32_t p_length,
                                uint32_t current_time, int tid,
                                pfwl_dissection_info_t* dissection_info) {
  memset(dissection_info, 0, sizeof(*dissection_info));
  dissection_info->status = PFWL_STATUS_OK;
  if (unlikely(p_length == 0)) return;
  uint8_t version;
#if __BYTE_ORDER == __LITTLE_ENDIAN
  version = (p_pkt[0] >> 4) & 0x0F;
#elif __BYTE_ORDER == __BIG_ENDIAN
  version = (p_pkt[0] << 4) & 0x0F;
#else
#error "Please fix <bits/endian.h>"
#endif

  unsigned char* pkt = (unsigned char*) p_pkt;
  uint32_t length = p_length;
  uint16_t offset;
  uint8_t more_fragments;

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

  struct ip6_hdr* ip6 = NULL;
  struct iphdr* ip4 = NULL;

  if (version == PFWL_IP_VERSION_4) { /** IPv4 **/
    ip4 = (struct iphdr*)(p_pkt);
    uint16_t tot_len = ntohs(ip4->tot_len);

#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
    if (unlikely(length < (sizeof(struct iphdr)) || tot_len > length ||
                 tot_len <= ((ip4->ihl) * 4))) {
      dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
      return;
    }
#endif
    /**
     * At this point we are sure that tot_len<=length, so we set
     * length=tot_len. In some cases indeed there may be an L2 padding
     * at the end of the packet, so capture length (length) may be
     * greater than the effective datagram length.
     */
    length = tot_len;

    offset = ntohs(ip4->frag_off);
    if (unlikely((offset & PFWL_IPv4_FRAGMENTATION_MF))) {
      more_fragments = 1;
    } else
      more_fragments = 0;

    /*
     * Offset is in 8-byte blocks. Multiplying by 8 correspond to a
     * right shift by 3 position, but the offset was 13 bit, so it can
     * still fit in a 16 bit integer.
     */
    offset = (offset & PFWL_IPv4_FRAGMENTATION_OFFSET_MASK) * 8;

    if (likely((!more_fragments) && (offset == 0))) {
      pkt = (unsigned char*)p_pkt;
    } else if (state->ipv4_frag_state != NULL) {
      pkt = pfwl_reordering_manage_ipv4_fragment(state->ipv4_frag_state, p_pkt,
                                                current_time, offset,
                                                more_fragments, tid);
      if (pkt == NULL) {
        dissection_info->status = PFWL_STATUS_IP_FRAGMENT;
        return;
      }
      to_return = PFWL_STATUS_IP_LAST_FRAGMENT;
      ip4 = (struct iphdr*)(pkt);
      length = ntohs(((struct iphdr*)(pkt))->tot_len);
    } else {
      dissection_info->status = PFWL_STATUS_IP_FRAGMENT;
      return;
    }

    dissection_info->addr_src.ipv4 = ip4->saddr;
    dissection_info->addr_dst.ipv4 = ip4->daddr;

    application_offset = (ip4->ihl) * 4;
    relative_offset = application_offset;

    next_header = ip4->protocol;
  } else if (version == PFWL_IP_VERSION_6) { /** IPv6 **/
    ip6 = (struct ip6_hdr*)(pkt);
    uint16_t tot_len =
        ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) + sizeof(struct ip6_hdr);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
    if (unlikely(tot_len > length)) {
      dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
      return;
    }
#endif

    /**
     * At this point we are sure that tot_len<=length, so we set
     * length=tot_len. In some cases indeed there may be an L2 padding
     * at the end of the packet, so capture length (length) may be
     * greater than the effective datagram length.
     */
    length = tot_len;

    dissection_info->addr_src.ipv6 = ip6->ip6_src;
    dissection_info->addr_dst.ipv6 = ip6->ip6_dst;

    application_offset = sizeof(struct ip6_hdr);
    relative_offset = application_offset;
    next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  } else {
    dissection_info->status = PFWL_ERROR_WRONG_IPVERSION;
    return;
  }

  while (!stop) {
    switch (next_header) {
      case IPPROTO_TCP: { /* TCP */
        struct tcphdr* tcp = (struct tcphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct tcphdr) > length ||
                     application_offset + tcp->doff * 4 > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L4_TRUNCATED_PACKET;
          return;
        }
#endif
        dissection_info->port_src = tcp->source;
        dissection_info->port_dst = tcp->dest;
        dissection_info->offset_l4 = application_offset;
        application_offset += (tcp->doff * 4);
        stop = 1;
      } break;
      case IPPROTO_UDP: { /* UDP */
        struct udphdr* udp = (struct udphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct udphdr) > length ||
                     application_offset + ntohs(udp->len) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L4_TRUNCATED_PACKET;
          return;
        }
#endif
        dissection_info->port_src = udp->source;
        dissection_info->port_dst = udp->dest;
        dissection_info->offset_l4 = application_offset;
        application_offset += 8;
        stop = 1;
      } break;
      case IPPROTO_HOPOPTS: { /* Hop by hop options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_hbh) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return;
        }
#endif
        if (likely(version == 6)) {
          struct ip6_hbh* hbh_hdr = (struct ip6_hbh*)(pkt + application_offset);
          tmp = (8 + hbh_hdr->ip6h_len * 8);
          application_offset += tmp;
          relative_offset += tmp;
          next_header = hbh_hdr->ip6h_nxt;
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return;
        }
      } break;
      case IPPROTO_DSTOPTS: { /* Destination options */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_dest) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return;
        }
#endif
        if (likely(version == 6)) {
          struct ip6_dest* dst_hdr =
              (struct ip6_dest*)(pkt + application_offset);
          tmp = (8 + dst_hdr->ip6d_len * 8);
          application_offset += tmp;
          relative_offset += tmp;
          next_header = dst_hdr->ip6d_nxt;
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return;
        }
      } break;
      case IPPROTO_ROUTING: { /* Routing header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_rthdr) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return;
        }
#endif
        if (likely(version == 6)) {
          struct ip6_rthdr* rt_hdr =
              (struct ip6_rthdr*)(pkt + application_offset);
          tmp = (8 + rt_hdr->ip6r_len * 8);
          application_offset += tmp;
          relative_offset += tmp;
          next_header = rt_hdr->ip6r_nxt;
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return;
        }
      } break;
      case IPPROTO_FRAGMENT: { /* Fragment header */
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct ip6_frag) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return;
        }
#endif
        if (likely(version == 6)) {
          if (state->ipv6_frag_state) {
            struct ip6_frag* frg_hdr =
                (struct ip6_frag*)(pkt + application_offset);
            uint16_t offset = ((frg_hdr->ip6f_offlg & IP6F_OFF_MASK) >> 3) * 8;
            uint8_t more_fragments =
                ((frg_hdr->ip6f_offlg & IP6F_MORE_FRAG)) ? 1 : 0;
            offset = ntohs(offset);
            uint32_t fragment_size =
                ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) +
                sizeof(struct ip6_hdr) - relative_offset -
                sizeof(struct ip6_frag);

            /**
             * If this fragment has been obtained from a
             * defragmentation (e.g. tunneling), then delete
             * it after that the defragmentation support has
             * copied it.
             */
            unsigned char* to_delete = NULL;
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
                state->ipv6_frag_state, (unsigned char*)ip6,
                sizeof(struct ip6_hdr),
                ((unsigned char*)ip6) + relative_offset +
                    sizeof(struct ip6_frag),
                fragment_size, offset, more_fragments, frg_hdr->ip6f_ident,
                frg_hdr->ip6f_nxt, current_time, tid);

            if (to_delete) free(to_delete);

            if (pkt == NULL) {
              dissection_info->status = PFWL_STATUS_IP_FRAGMENT;
              return;
            }

            to_return = PFWL_STATUS_IP_LAST_FRAGMENT;
            next_header = IPPROTO_IPV6;
            length = ((struct ip6_hdr*)(pkt))->ip6_ctlun.ip6_un1.ip6_un1_plen +
                     sizeof(struct ip6_hdr);
            /**
             * Force the next iteration to analyze the
             * reassembled IPv6 packet.
             **/
            application_offset = relative_offset = 0;
          } else {
            dissection_info->status = PFWL_STATUS_IP_FRAGMENT;
            return;
          }
        } else {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_TRANSPORT_PROTOCOL_NOTSUPPORTED;
          return;
        }
      } break;
      case IPPROTO_IPV6: /** 6in4 and 6in6 tunneling **/
        /** The real packet is now ipv6. **/
        version = 6;
        ip6 = (struct ip6_hdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen) +
                         sizeof(struct ip6_hdr) >
                     length - application_offset)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return;
        }
#endif

        dissection_info->addr_src.ipv6 = ip6->ip6_src;
        dissection_info->addr_dst.ipv6 = ip6->ip6_dst;

        application_offset += sizeof(struct ip6_hdr);
        relative_offset = sizeof(struct ip6_hdr);
        next_header = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        break;
      case 4: /* 4in4 and 4in6 tunneling */
        /** The real packet is now ipv4. **/
        version = 4;
        ip4 = (struct iphdr*)(pkt + application_offset);
#ifdef PFWL_ENABLE_L3_TRUNCATION_PROTECTION
        if (unlikely(application_offset + sizeof(struct iphdr) > length ||
                     application_offset + ((ip4->ihl) * 4) > length ||
                     application_offset + ntohs(ip4->tot_len) > length)) {
          if (unlikely(pkt != p_pkt)) free(pkt);
          dissection_info->status = PFWL_ERROR_L3_TRUNCATED_PACKET;
          return;
        }
#endif
        dissection_info->addr_src.ipv4 = ip4->saddr;
        dissection_info->addr_dst.ipv4 = ip4->daddr;
        next_header = ip4->protocol;
        tmp = (ip4->ihl) * 4;
        application_offset += tmp;
        relative_offset = tmp;
        break;
      default:
        stop = 1;
        dissection_info->offset_l4 = application_offset;
        break;
    }
  }

  dissection_info->protocol_l4 = next_header;
#ifdef PFWL_ENABLE_L4_TRUNCATION_PROTECTION
  if (unlikely(application_offset > length)) {
    if (unlikely(pkt != p_pkt)) free(pkt);
    dissection_info->status = PFWL_ERROR_L4_TRUNCATED_PACKET;
    return;
  }
#endif
  dissection_info->timestamp = current_time;
  dissection_info->pkt_refragmented = pkt;
  dissection_info->offset_l7 = application_offset;
  dissection_info->data_length_l7 = length - application_offset;
  dissection_info->ip_version = version;
  dissection_info->status = to_return;
  return;
}

void pfwl_parse_L3_L4(pfwl_state_t* state, const unsigned char* pkt, uint32_t length,
                      uint32_t current_time, pfwl_dissection_info_t* dissection_info) {
  /**
   * We can pass any thread id, indeed in this case we don't
   * need lock synchronization.
   **/
  return mc_pfwl_parse_L3_L4_header(state, pkt, length, current_time, 0, dissection_info);
}
