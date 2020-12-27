/*
 * quic_extraction_nfq.c
 *
 * NFQ based demo application for inspecting quic traffic
 *
 * =========================================================================
 * Copyright (c) 2020 SoftAtHome (david.cluytens@gmail.com)
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <peafowl/peafowl.h>
#include <net/ethernet.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <linux/netfilter.h>		
#include <libnetfilter_queue/libnetfilter_queue.h>

pfwl_state_t* state = NULL;
uint32_t protocols[PFWL_PROTO_L7_NUM];

static u_int32_t print_pkt (struct nfq_data *tb)
{	
	int 				id 		= 0;
	int 				caplen;	
	struct nfqnl_msg_packet_hdr 	*ph		= NULL;
	unsigned char 			*data		= NULL;
	pfwl_dissection_info_t 		r;
	pfwl_status_t 			pfwl_status;
	pfwl_string_t 			version;
	pfwl_string_t 			sni;
	pfwl_string_t 			uaid;

	caplen = nfq_get_payload(tb, &data);
	ph = nfq_get_msg_packet_hdr(tb);
	id = ntohl(ph->packet_id);

	if (caplen >= 0) {
		memset(&r, 0, sizeof(pfwl_dissection_info_t));

		pfwl_status = pfwl_dissect_from_L3(state, data, caplen, time(NULL), &r);
		if(pfwl_status >= PFWL_STATUS_OK){
			if(r.l4.protocol == IPPROTO_TCP || r.l4.protocol == IPPROTO_UDP){
				if(r.l7.protocol < PFWL_PROTO_L7_NUM){
					++protocols[r.l7.protocol];
					int print_once 	= 1;
					if(print_once && !strcmp("QUIC5", pfwl_get_L7_protocol_name(r.l7.protocol))) {
						pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, &version);
						pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, &sni);
						pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, &uaid);

						printf("hw_protocol=0x%04x hook=%u id=%d ", ntohs(ph->hw_protocol), ph->hook, id);
						struct nfqnl_msg_packet_hw *hwph = nfq_get_packet_hw(tb);
						int hlen = ntohs(hwph->hw_addrlen);

						printf("hw_src_addr=");
						int i = 0;
						for (i = 0; i < hlen-1; i++)
							printf("%02x:", hwph->hw_addr[i]);
						printf("%02x ", hwph->hw_addr[hlen-1]);
						printf(" QUIC Version: %.*s SNI; %.*s UAID %.*s\n", 
								version.length, version.value, sni.length, sni.value, uaid.length, uaid.value);
						print_once = 0;
					}
				}

			}
		} else {
			printf("PFWL_STATUS %d: %s\n", pfwl_status, pfwl_get_status_msg(pfwl_status));
		}

	}
	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	state = pfwl_init();
	if (state == NULL) {
		fprintf(stderr, "error during initialisation of peafowl handler\n");
		exit(1);
	}
	pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_VERSION);
	pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_SNI);
	pfwl_field_add_L7(state, PFWL_FIELDS_L7_QUIC_UAID);
	memset(protocols, 0, sizeof(protocols));
	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);
	pfwl_terminate(state);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
