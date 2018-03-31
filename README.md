[![HitCount](http://hits.dwyl.io/DanieleDeSensi/Peafowl.svg)](http://hits.dwyl.io/DanieleDeSensi/Peafowl)
[![MIT Licence](https://badges.frapsoft.com/os/mit/mit.svg?v=103)](https://opensource.org/licenses/mit-license.php)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](paypal.me/DanieleDeSensi)
<noscript><a href="https://liberapay.com/~36438/donate"><img alt="Donate using Liberapay" src="https://liberapay.com/assets/widgets/donate.svg"></a></noscript>


Introduction
================================================================================================================
Peafowl is a flexible and extensible DPI framework which can be used to identify the application protocols
carried by IP (IPv4 and IPv6) packets and to extract and process data and metadata carried by those protocols.

For example, is possible to write applications that process any possible kind of data and metadata carried by an 
HTTP connection (e.g. Host, User-Agent, Content-Type, HTTP body, etc..). It's important to notice that the
application programmer needs only to focus on the way these information are processed, since their extraction
is completely and transparently performed by the framework. Accordingly, using Peafowl is possible to implement
different kinds of applications like:

+ URL filtering (for parental control or access control)
+ User-Agent or Content-Type filtering (e.g. block traffic for mobile users, block video traffic, etc...)
+ Security controls (e.g. block the traffic containing some malicious signatures or patterns)
+ Data leak prevention
+ Quality of Service and Traffic shaping (e.g. to give higher priority to VoIP traffic)

Peafowl is not tied to any specific technology for packet capture. Accordingly, you can capture the packets using 
pcap, sockets, PF_RING or whatever technology you prefer.

To correctly identify the protocol also when its data is split among multiple IP fragments and/or TCP segments 
and to avoid the possibility of evasion attacks, if required, the framework can perform IP defragmentation and 
TCP stream reassembly.

Peafowl also provide the possibility to exploit the parallelism of current multicore machines, splitting the
processing load among the available cores. This feature is particularly useful when some complex processing
is required on the content of the packets (e.g. complex pattern matching, audio/video processing, etc...).
This possibility have been implemented by using [FastFlow](http://calvados.di.unipi.it/dokuwiki/doku.php?id=ffnamespace:about),
a parallel programming framework for multicore platforms based upon non-blocking lock-free/fence-free 
synchronization mechanisms.


**If you use Peafowl for scientific purposes, please cite our paper:**

*"Deep Packet Inspection on Commodity Hardware using FastFlow"*, M. Danelutto, L. Deri, D. De Sensi, M. Torquati


Supported protocols
================================================================================================================
Peafowl can identify some of the most common protocols. To add more protocols refer to the corresponding
section in this document. 
The supported protocols are:

<table>
  <tr>
    <th>Protocol</th><th>Quality</th>
  </tr>
  <tr>
    <td>HTTP</td><td>5/5</td>
  </tr>
  <tr>
  	<td>SSL</td><td>5/5</td>
  </tr>
  <tr>
    <td>POP3</td><td>3/5</td>
  </tr>
  <tr>
    <td>SMTP</td><td>3/5</td>
  </tr>
  <tr>
    <td>BGP</td><td>5/5</td>
  </tr>
  <tr>
    <td>DHCP</td><td>5/5</td>
  </tr>
  <tr>
    <td>DHCPv6</td><td>5/5</td>
  </tr>
  <tr>
    <td>DNS</td><td>5/5</td>
  </tr>
  <tr>
    <td>MDNS</td><td>5/5</td>
  </tr>
  <tr>
    <td>NTP</td><td>5/5</td>
  </tr>
  <tr>
    <td>SIP</td><td>4/5</td>
  </tr>
  <tr>
    <td>RTP</td><td>4/5</td>
  </tr>
  <tr>
    <td>SKYPE</td><td>3/5</td>
  </tr>
</table>

At the moment, data and metadata extraction is supported for the following protocols:

<table>
  <tr>
    <th>Protocol</th><th>Kind of data that the framework can provide to the application</th>
  </tr>
  <tr>
    <td>HTTP</td><td>Any kind of HTTP header, HTTP body</td>
  </tr>
<table>


Usage
================================================================================================================
Fetch the framework typing:

```
$ git clone git://github.com/DanieleDeSensi/Peafowl.git
$ cd Peafowl
```

Compile it with:

```
$ make
```

After that, install it with

```
$ make install
```

Sequential version
------------------------------------------------------------------------------------------------------------
At this point, your application can use Peafowl by including the ["src/api.h"](src/api.h) header and by 
linking lib/libdpi.a.

The API is based on 3 main calls:

+ ```dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS)```:
used to initialize the state of the framework. It requires the size of the tables that the framework will use
and the maximum number of flows that the framework should manage. When this number of flows is reached, the 
framework will add no other flows to the table. This call returns an handle to the framework, which will
be required as parameter for most of the framework calls;

+ ```dpi_stateful_identify_application_protocol(state, packet, length, timestamp)```:
 used to identify a specific packet. It requires the handle to the framework, a pointer to the beginning of
 IP header, its length starting from the IP header, and a timestamp in seconds. It returns a struct containing
 the protocol of the packet and an indication of the status of the processing (e.g. success/failure and reason
 of the failure).
 
+ ```dpi_terminate(state)```: used to terminate the framework. 

For other API calls (e.g. to enable/disable protocol inspectors or to enable/disable TCP stream reassembly and IP 
defragmentation please refer to the documentation in ["src/api.h"](src/api.h)).

Multicore version
------------------------------------------------------------------------------------------------------------------ 
You can take advantage of the multicore version by including the ["src/mc_api.h"](src/mc_api.h) header and by 
linking lib/libmcdpi.a. Since the user manual for the multicore version of Peafowl is not yet available,
you can look at [this](demo/protocol_identification_mc/protocol_identification.cpp) simple demo file.
If you  need more informations about how to use it, contact me at d.desensi.software@gmail.com or read the [Thesis](Thesis.pdf). 

Demo application
---------------------------------------------------------------------------------------------------------------------
In the following example we can see a demo application which reads packets from a .pcap file and tries to 
identify their protocol. This source file can also be found in [demo_identification.c](demo/demo_identification.c) 
This application can be easily modified to read packet from the network instead from a file.

```C
/*
 *  demo_identification.c
 *
 *  Given a .pcap file, it identifies the protocol of all the packets contained in it.
 *
 *  Created on: 12/11/2012
 *  Author: Daniele De Sensi
 */

#include "../api.h"
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

#define SIZE_IPv4_FLOW_TABLE 32767
#define SIZE_IPv6_FLOW_TABLE 32767
#define MAX_IPv4_ACTIVE_FLOWS 500000
#define MAX_IPv6_ACTIVE_FLOWS 500000

int main(int argc, char** argv){
	if(argc!=2){
		fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
		return -1;
	}
	char* pcap_filename=argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	dpi_framework_state_t* state=dpi_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, 
	                                             MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
	u_int64_t bytes_contained=0;

	pcap_t *handle=pcap_open_offline(pcap_filename, errbuf);

	if(handle==NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
		return (2);
	}

	int datalink_type=pcap_datalink(handle);
	uint ip_offset=0;
	if(datalink_type==DLT_EN10MB){
		printf("Datalink type: Ethernet\n");
		ip_offset=sizeof(struct ether_header);
	}else if(datalink_type==DLT_RAW){
		printf("Datalink type: RAW\n");
		ip_offset=0;
	}else{
		fprintf(stderr, "Datalink type not supported\n");
		exit(-1);
	}

	const u_char* packet;
	struct pcap_pkthdr header;

	dpi_identification_result_t r;
	u_int32_t http_matches=0;
	u_int32_t dns_matches=0;
	u_int32_t bgp_matches=0;
	u_int32_t smtp_matches=0;
	u_int32_t pop3_matches=0;
	u_int32_t mdns_matches=0;
	u_int32_t ntp_matches=0;
	u_int32_t dhcp_matches=0;
	u_int32_t dhcpv6_matches=0;
	u_int32_t unknown=0;


	while((packet=pcap_next(handle, &header))!=NULL){
		if(header.len<ip_offset) continue;

		r=dpi_stateful_identify_application_protocol(state, packet+ip_offset, 
		                                             header.len-ip_offset, time(NULL));

		if(r.protocol.l4prot==IPPROTO_TCP){
			switch(r.protocol.l7prot){
				case DPI_PROTOCOL_TCP_BGP:
					++bgp_matches;
					break;
				case DPI_PROTOCOL_TCP_HTTP:
					++http_matches;
					break;
				case DPI_PROTOCOL_TCP_SMTP:
					++smtp_matches;
					break;
				case DPI_PROTOCOL_TCP_POP3:
					++pop3_matches;
					break;
				default:
					++unknown;
					break;
			}
		}else if(r.protocol.l4prot==IPPROTO_UDP){
		  switch(r.protocol.l7prot){
				case DPI_PROTOCOL_UDP_DHCP:
					++dhcp_matches;
					break;
				case DPI_PROTOCOL_UDP_DHCPv6:
					++dhcpv6_matches;
					break;
				case DPI_PROTOCOL_UDP_DNS:
					++dns_matches;
					break;
				case DPI_PROTOCOL_UDP_MDNS:
					++mdns_matches;
					break;
				case DPI_PROTOCOL_UDP_NTP:
			        ++ntp_matches;
					break;
				default:
					++unknown;
					break;
			}
		}else{
			++unknown;
		}

	}

	dpi_terminate(state);


	printf("Unknown packets: %"PRIu32"\n", unknown);
	printf("HTTP packets: %"PRIu32"\n", http_matches);
	printf("BGP packets: %"PRIu32"\n", bgp_matches);
	printf("POP3 packets: %"PRIu32"\n", pop3_matches);
	printf("SMTP packets: %"PRIu32"\n", smtp_matches);
	printf("NTP packets: %"PRIu32"\n", ntp_matches);
	printf("DNS packets: %"PRIu32"\n", dns_matches);
	printf("MDNS packets: %"PRIu32"\n", mdns_matches);
	printf("DHCP packets: %"PRIu32"\n", dhcp_matches);
	printf("DHCPv6 packets: %"PRIu32"\n", dhcpv6_matches);

	return 0;
}
```

Other demos
---------------------------------------------------------------------------------------------------------------------
More demo applications can be found in [demo](demo) folder:

+ [protocol_identification_identification.c](demo/protocol_identification/protocol_identification.c): Given a .pcap file, 
  it identifies the protocol of all the packets contained in it.
+ [jpeg_dump.c](demo/dump_jpeg/dump_jpeg.c): Dumps on the disk all the jpeg images carried by HTTP packets captured from a .pcap 
  file or from the network.
+ ```http_pattern_matching```: Searches in all the HTTP bodies a set of patterns (e.g. viruses signatures, an [example](demo/http_pattern_matching/signatures.example) 
  of a signatures set is provided). The TCP stream is analyzed in the correct order and the pattern is correctly identified also when splitted 
  over multiple TCP segmentes. 
  It is possible to use this demo to read data [sequentially](demo/http_pattern_matching/http_pm_seq.cpp) from a .pcap file, 
  to read data using [multiple cores](demo/http_pattern_matching/http_pm_mc.cpp) from a .pcap file, or to read data from the 
  [network](demo/http_pattern_matching/http_pm_mc_pfring.cpp) by using [PF_RING.](http://www.ntop.org/products/pf_ring/) (PF_RING needs to be installed).

Experimental results
================================================================================================================
Extensive tests have been done from the point of view of the performance. We will show here only some of the results
we obtained (other results and comparison with similar tools can be found in [Thesis.pdf](Thesis.pdf)).

Protocol identification
---------------------------------------------------------------------------------------------------------------------
First of all, we computed the bandwidth (in millions of packets per second) of the multicore version of the framework 
over different datasets, obtaining the following results:

![Multicore protocol identification: bandwidth](results/bandwidth_protocol_identification.png)

HTTP pattern matching
---------------------------------------------------------------------------------------------------------------------
In this test, we computed the bandwidth (in millions of packets per second) of the HTTP pattern matching application
varying the number of worker threads used by the framework. We executed this test both on data read from the network
with PF_RING and on data read by preloading a .pcap file in main memory and the reading data from the memory, 
obtaining very similar results.

![HTTP pattern matching application: bandwidth](results/bandwidth_app.png)

How it works
================================================================================================================
To identify the application protocol, packets are classified in bidirectional sets of packets all sharing the 
same:

+ Source IP and Destination IP addressess
+ Source and Destination Ports
+ Layer4 protocol (TCP or UDP)

These sets are called "flows" and for each of them the framework stores some data into an hash table. These
informations are mantained for all the duration the TCP connection or until the flow is active. If we receive
no packets for a flow for a given amount of time (30 seconds by default), the corresponding data will be removed
from the table.

The framework also performs IP defragmentation and TCP stream reassembly, in such a way that the protocol is 
correctly identified also when its data is split among multiple fragments or segments. Moreover, this is useful
to avoid evasion attacks that use IP fragmentation and TCP segmentation.

The framework can be used in two different modes: Stateful and Stateless.
+ Stateful: is suited for applications which don't have a  concept of 'flow'. In this case the user simply pass to
the framework a stream of packets without concerning about how to store the flow. All the flow management and storing
will be done by the framework.

+ Stateless: is suited for applications which already have a concept of 'flow'. In this case the framework demand 
the storage of the flow data to the application. The user application should be modified in order to store with 
their own flow informations also the informations needed by the framework to identify the protocols.

A more detailed description can be found in the thesis which lead to the development of this framework: [Thesis.pdf](Thesis.pdf)

Advanced usage
================================================================================================================
Details on how to add new protocols and on different configuration parameters can be found in [README_ADVANCED.md](README_ADVANCED.md)

Contributions
================================================================================================================
Peafowl has been mainly developed by Daniele De Sensi (d.desensi.software@gmail.com).

I would like to thank Prof. Marco Danelutto, Dr. Luca Deri and Dr. Massimo Torquati for their essential help and
valuable advices.
