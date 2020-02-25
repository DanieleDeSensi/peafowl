/*
 * protocols_identifiers.h
 *
 * =========================================================================
 * Copyright (c) 2012-2019 Daniele De Sensi (d.desensi.software@gmail.com)
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

#ifndef PROTOCOLS_IDENTIFIERS_H_
#define PROTOCOLS_IDENTIFIERS_H_

#include <netinet/ip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 *  Inspectors must catch all the possible packet types during the message
 *exchange.
 *  E.g. inspect which detect only request or response are not valid inspectors.
 *	They must be able to detect flow that already started.
 *
 *	MUST never happen that two protocols match over the same packet. Is
 *preferable to have an inspector that 'take time' and
 *	returns PFWL_PROTOCOL_MORE_DATA_NEEDED (to check more packets) up to the
 *point in which it is not sure that the protocol matches.
 */

enum protocol_check_statuses {
  PFWL_PROTOCOL_MATCHES = 0,      /** If the protocol matches for sure. */
  PFWL_PROTOCOL_NO_MATCHES,       /** If the protocol doesn't matches for sure. */
  PFWL_PROTOCOL_MORE_DATA_NEEDED, /** The inspector needs more data to be sure
                                    that the protocol matches or to invoke the
                                    callback on the complete data. **/
  PFWL_PROTOCOL_ERROR
};

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define port_ssh 0x1600           /** 22 **/
#define port_smtp_1 0x1900        /** 25 **/
#define port_dns 0x3500           /** 53 **/
#define port_dhcp_1 0x4300        /** 67 **/
#define port_dhcp_2 0x4400        /** 68 **/
#define port_http 0x5000          /** 80 **/
#define port_pop3 0x6E00          /** 110 **/
#define port_ntp 0x7B00           /** 123 **/
#define port_bgp 0xB300           /** 179 **/
#define port_dhcpv6_1 0x2202      /** 546 **/
#define port_dhcpv6_2 0x2302      /** 547 **/
#define port_smtp_2 0x4B02        /** 587 **/
#define port_smtp_ssl 0xD101      /** 465 **/
#define port_sip 0xC413           /** 5060 **/
#define port_mdns 0xE914          /** 5353 **/
#define port_ssl 0xBB01           /** 443 **/
#define port_pop3_ssl 0xE303      /** 995 **/
#define port_imap 0x8F00          /** 143 **/
#define port_imap_ssl 0xE103      /** 993 **/
#define port_hangout_19302 0x664B /** 19302 **/
#define port_hangout_19303 0x674B /** 19303 **/
#define port_hangout_19304 0x684B /** 19304 **/
#define port_hangout_19305 0x694B /** 19305 **/
#define port_hangout_19306 0x6A4B /** 19306 **/
#define port_hangout_19307 0x6B4B /** 19307 **/
#define port_hangout_19308 0x6C4B /** 19308 **/
#define port_hangout_19309 0x4B6D /** 19309 **/
#define port_dropbox 0x5C44       /** 17500 **/
#define port_spotify 0x15E1       /** 57621 **/
#define port_bitcoin 0x8D20       /** 8333 **/
#define port_ssdp 0x6C07          /** 1900 **/
#define port_monero_rpc_1 0xA146  /** 18081 **/
#define port_monero_rpc_2 0xB16D  /** 28081 **/
#define port_monero_p2p_1 0xA046  /** 18080 **/
#define port_monero_p2p_2 0xB06D  /** 28080 **/
#define port_stun 0x960D          /** 3478 **/
#define port_stun_tls 0xE514      /** 5349 **/
#define port_mqtt 0x5B07          /** 1883 **/
#define port_mqtt_ssl 0xB322      /** 8883 **/
#define port_viber_1 0x311F       /** 7985 **/
#define port_viber_2 0x331F       /** 7987 **/
#define port_viber_3 0x7A14       /** 5242 **/
#define port_viber_4 0x7B14       /** 5243 **/
#define port_viber_5 0x9410       /** 4244 **/
#define port_kerberos 0x5800      /** 88 **/
#define port_tor 0x2923           /** 9001 **/
#define port_git 0xCA24           /** 9418 **/
#elif __BYTE_ORDER == __BIG_ENDIAN
#define port_ssh 0x0016           /* 22 **/
#define port_smtp_1 0x0019        /** 25 **/
#define port_dns 0x0035           /** 53 **/
#define port_dhcp_1 0x0043        /** 67 **/
#define port_dhcp_2 0x0044        /** 68 **/
#define port_http 0x0050          /** 80 **/
#define port_pop3 0x006E          /** 110 **/
#define port_pop3_ssl 0x03E3      /** 995 **/
#define port_imap 0x008F          /** 143 **/
#define port_imap_ssl 0x03E1      /** 993 **/
#define port_ntp 0x007B           /** 123 **/
#define port_bgp 0x00B3           /** 179 **/
#define port_dhcpv6_1 0x0222      /** 546 **/
#define port_dhcpv6_2 0x0223      /** 547 **/
#define port_smtp_2 0x024B        /** 587 **/
#define port_smtp_ssl 0x01D1      /** 465 **/
#define port_sip 0x13C4           /** 5060 **/
#define port_mdns 0x14E9          /** 5353 **/
#define port_ssl 0x01BB           /** 443 **/
#define port_hangout_19302 0x4B66 /** 19302 **/
#define port_hangout_19303 0x4B67 /** 19303 **/
#define port_hangout_19304 0x4B68 /** 19304 **/
#define port_hangout_19305 0x4B69 /** 19305 **/
#define port_hangout_19306 0x4B6A /** 19306 **/
#define port_hangout_19307 0x4B6B /** 19307 **/
#define port_hangout_19308 0x4B6C /** 19308 **/
#define port_hangout_19309 0x4B6D /** 19309 **/
#define port_dropbox 0x445C       /** 17500 **/
#define port_spotify 0xE115       /** 57621 **/
#define port_bitcoin 0x208D       /** 8333 **/
#define port_ssdp 0x076C          /** 1900 **/
#define port_monero_rpc_1 0x46A1  /** 18081 **/
#define port_monero_rpc_2 0x6DB1  /** 28081 **/
#define port_monero_p2p_1 0x46A0  /** 18080 **/
#define port_monero_p2p_2 0x6DB0  /** 28080 **/
#define port_stun 0x0D96          /** 3478 **/
#define port_stun_tls 0x14E5      /** 5349 **/
#define port_mqtt 0x075B          /** 1883 **/
#define port_mqtt_ssl 0x22B3      /** 8883 **/
#define port_viber_1 0x1F31       /** 7985 **/
#define port_viber_2 0x1F33       /** 7987 **/
#define port_viber_3 0x147A       /** 5242 **/
#define port_viber_4 0x147B       /** 5243 **/
#define port_viber_5 0x1094       /** 4244 **/
#define port_kerberos 0x0058      /** 88 **/
#define port_tor 0x2329           /** 9001 **/
#define port_git 0x24CA           /** 9418 **/
#else
#error "Please fix <bits/endian.h>"
#endif

#endif /* PROTOCOLS_IDENTIFIERS_H_ */
