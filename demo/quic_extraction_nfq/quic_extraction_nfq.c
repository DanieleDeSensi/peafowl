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

void processPacketdata(const unsigned char *packet, int caplen) {
	int 			print_once 	= 1;
	uint32_t 		unknown 	= 0;
	pfwl_dissection_info_t 	r;
	pfwl_status_t 		pfwl_status;
	pfwl_string_t 		version;
	pfwl_string_t 		sni;
	pfwl_string_t 		uaid;

	memset(&r, 0, sizeof(pfwl_dissection_info_t));

	printf("Processing packet data ... length %d\n", caplen);
	pfwl_status = pfwl_dissect_from_L3(state, packet, caplen, time(NULL), &r);
	if(pfwl_status >= PFWL_STATUS_OK){
		printf("Protocol found %d\n", r.l4.protocol);
		if(r.l4.protocol == IPPROTO_TCP || r.l4.protocol == IPPROTO_UDP){
			if(r.l7.protocol < PFWL_PROTO_L7_NUM){
				++protocols[r.l7.protocol];
				if(print_once && !strcmp("QUIC", pfwl_get_L7_protocol_name(r.l7.protocol))) {
					pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_VERSION, &version);
					pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_SNI, &sni);
					pfwl_field_string_get(r.l7.protocol_fields, PFWL_FIELDS_L7_QUIC_UAID, &uaid);
					printf("QUIC Version: %.*s SNI; %.*s UAID %.*s\n", 
						version.length, version.value, sni.length, sni.value, uaid.length, uaid.value);
					print_once = 0;
				}
			}else{
				++unknown;
			}
		}else{
			++unknown;
		}
	} else {
		printf("PFWL_STATUS %d: %s\n", pfwl_status, pfwl_get_status_msg(pfwl_status));
	}

	if (unknown > 0) printf("Unknown packets: %"PRIu32"\n", unknown);
	for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
		if(protocols[i] > 0){
			printf("%s packets: %"PRIu32"\n", pfwl_get_L7_protocol_name(i), protocols[i]);
		}
	}
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0) {
		printf("payload_len=%d\n", ret);
		processPacketdata(data, ret);
	} else {
		fputc('\n', stdout);
	}

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
//	u_int32_t id;

        //struct nfqnl_msg_packet_hdr *ph;
	//ph = nfq_get_msg_packet_hdr(nfa);	
	//id = ntohl(ph->packet_id);
	printf("entering callback\n");
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
		printf("pkt received\n");
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
