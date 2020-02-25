/*
 * flows_summary.c
 *
 * From live or given a .pcap file, prints summary information about the contained flows.
 *
 * Created on: 05/01/2019
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
#include <pcap.h>
#include <net/ethernet.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <assert.h>

// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518

// error
#define DEVICE_ERROR(device, file)                          \
    fprintf(stderr, "error on #%s or #%s\n", device, file);	\


// Print the list of availlable devices
static void print_all_devices(pcap_if_t *all_devs, pcap_if_t *d)
{
    int i = 0;
    printf("\nList of available devices on your system:\n\n");
    for(d = all_devs; d; d = d->next) {
        printf("device %d = %s", ++i, d->name);
        if(d->description)
            printf("\t\t (%s)\n", d->description);
        else
            printf("\t\t No description available for this device\n");
    }
}

// PRINT
static void print_header(){
    printf("#Id\tThreadId\tAddressSrc\tAddressDst\tPortSrc\tPortDst\t"
           "ProtoL2\tProtoL3\tProtoL4\tProtosL7\t"
           "Packets(DirA|DirB)\tBytes(DirA|DirB)\tPacketsL7(DirA|DirB)\tBytesL7(DirA|DirB)\t"
           "TimestampFirst(DirA|DirB)\tTimestampLast(DirA|DirB)\n");
}

static const char* convert_address(pfwl_ip_addr_t address, pfwl_protocol_l3_t l3prot, char* buf, size_t buf_size){
    if(l3prot == PFWL_PROTO_L3_IPV4){
        struct in_addr a;
        a.s_addr = address.ipv4;
        return inet_ntop(AF_INET, (void*) &a, buf, buf_size);
    }else{
        return inet_ntop(AF_INET6, (void*) &(address.ipv6), buf, buf_size);
    }
}

static char protocols_tmp[2048];
static const char* convert_l7_protocols(pfwl_flow_info_t* flow_info){
    protocols_tmp[0] = 0;
    for(size_t i = 0; i < flow_info->protocols_l7_num; i++){
        strcat(protocols_tmp, pfwl_get_L7_protocol_name(flow_info->protocols_l7[i]));
        if(i != flow_info->protocols_l7_num - 1){
            strcat(protocols_tmp, ",");
        }
    }
    if(!protocols_tmp[0]){
        return "Unknown";
    }else{
        return protocols_tmp;
    }
}

// Function to summarize flows to print stats
static char tmp_srcaddr[64], tmp_dstaddr[64];
void summarizer(pfwl_flow_info_t* flow_info){
    printf("%"PRIu64"\t%"PRIu16"\t%s\t%s\t%"PRIu16"\t%"PRIu16"\t"
           "%s\t%s\t%s\t%s\t"
           "%.0f|%.0f\t%.0f|%.0f\t%.0f|%.0f\t%.0f|%.0f\t"
           "%.0f|%.0f\t%.0f|%.0f\n",
           flow_info->id,
           flow_info->thread_id,
           convert_address(flow_info->addr_src, flow_info->protocol_l3, tmp_srcaddr, sizeof(tmp_srcaddr)),
           convert_address(flow_info->addr_dst, flow_info->protocol_l3, tmp_dstaddr, sizeof(tmp_dstaddr)),
           ntohs(flow_info->port_src),
           ntohs(flow_info->port_dst),
           pfwl_get_L2_protocol_name(flow_info->protocol_l2),
           pfwl_get_L3_protocol_name(flow_info->protocol_l3),
           pfwl_get_L4_protocol_name(flow_info->protocol_l4),
           convert_l7_protocols(flow_info),
           flow_info->statistics[PFWL_STAT_PACKETS][PFWL_DIRECTION_OUTBOUND], flow_info->statistics[PFWL_STAT_PACKETS][PFWL_DIRECTION_INBOUND],
           flow_info->statistics[PFWL_STAT_BYTES][PFWL_DIRECTION_OUTBOUND], flow_info->statistics[PFWL_STAT_BYTES][PFWL_DIRECTION_INBOUND],
           flow_info->statistics[PFWL_STAT_L7_PACKETS][PFWL_DIRECTION_OUTBOUND], flow_info->statistics[PFWL_STAT_L7_PACKETS][PFWL_DIRECTION_INBOUND],
           flow_info->statistics[PFWL_STAT_L7_BYTES][PFWL_DIRECTION_OUTBOUND], flow_info->statistics[PFWL_STAT_L7_BYTES][PFWL_DIRECTION_INBOUND],
           flow_info->statistics[PFWL_STAT_TIMESTAMP_FIRST][PFWL_DIRECTION_OUTBOUND], flow_info->statistics[PFWL_STAT_TIMESTAMP_FIRST][PFWL_DIRECTION_INBOUND],
           flow_info->statistics[PFWL_STAT_TIMESTAMP_LAST][PFWL_DIRECTION_OUTBOUND], flow_info->statistics[PFWL_STAT_TIMESTAMP_LAST][PFWL_DIRECTION_INBOUND]
    );
}

int main(int argc, char** argv)
{
    if(argc < 2){
        fprintf(stderr, "Usage: -l: list of availlable device\n");
        fprintf(stderr, "       -i: open live capture \n");
        fprintf(stderr, "       -p: detect traffic from a give pcap file\n");
        return -1;
    }

    pcap_if_t *all_devs, *d = NULL;
    pcap_t *handle;
    char errbuff[PCAP_ERRBUF_SIZE];
    const u_char* packet;
    uint32_t protocols[PFWL_PROTO_L7_NUM];
    struct pcap_pkthdr header;
    memset(protocols, 0, sizeof(protocols));
    uint32_t unknown = 0;
    char *device = NULL, *file = NULL;

    int opt;
    while(opt = getopt(argc, argv, ":p:i:l"), opt != -1)
    {
        switch(opt) {

            // LIVE
          case 'i':
              device = optarg;
              break;
              // PCAP
          case 'p':
              file = optarg;
              break;
              // List the availlable network device
          case 'l': {
              if(pcap_findalldevs(&all_devs, errbuff) == -1) {
                  fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuff);
                  return EXIT_FAILURE;
              }
              print_all_devices(all_devs, d);
              return EXIT_SUCCESS;
          }
        }
    }

    if(device) {
        printf("Listening on device %s\n", device);
        // open device live
        handle = pcap_open_live(device, SNAP_LEN, 0, 0, errbuff);
        if(!handle) {
            fprintf(stderr, "Couldn't listen on device %s (%s)\n", device, errbuff);
            return EXIT_FAILURE;
        }
    }
    else if(file) {
        printf("Reading from pcap file\n");
        handle = pcap_open_offline(file, errbuff);
        if(handle == NULL){
            fprintf(stderr, "Couldn't open device %s (%s)\n", file, errbuff);
            return EXIT_FAILURE;
        }
    }
    else if(opt == -1) {
        fprintf(stderr, "Bad argument\n");
        return EXIT_FAILURE;
    }
    else {
        DEVICE_ERROR(device, errbuff);
        return EXIT_FAILURE;
    }

    pfwl_state_t* state = pfwl_init();
    //pfwl_set_expected_flows(state, 8, PFWL_FLOWS_STRATEGY_NONE);
    pfwl_set_flow_termination_callback(state, &summarizer);    
    print_header();
    pfwl_dissection_info_t r;
    pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(pcap_datalink(handle));
    while((packet = pcap_next(handle, &header)) != NULL){
        if(pfwl_dissect_from_L2(state, packet, header.caplen, header.ts.tv_sec, dlt, &r) >= PFWL_STATUS_OK){
            if(r.l4.protocol == IPPROTO_TCP || r.l4.protocol == IPPROTO_UDP){
                if(r.l7.protocol < PFWL_PROTO_L7_NUM){
                    ++protocols[r.l7.protocol];
                }else{
                    ++unknown;
                }
            }else{
                ++unknown;
            }
        }
    }
    pfwl_terminate(state);

    if (unknown > 0) printf("Unknown packets: %"PRIu32"\n", unknown);
    for(size_t i = 0; i < PFWL_PROTO_L7_NUM; i++){
        if(protocols[i] > 0){
            printf("%s packets: %"PRIu32"\n", pfwl_get_L7_protocol_name(i), protocols[i]);
        }
    }
    return 0;
}
