[![Build Status](https://travis-ci.org/DanieleDeSensi/peafowl.svg?branch=master)](https://travis-ci.org/DanieleDeSensi/peafowl) 
[![release](https://img.shields.io/github/release/danieledesensi/peafowl.svg)](https://github.com/danieledesensi/peafowl/releases/latest)
[![CodeFactor](https://www.codefactor.io/repository/github/danieledesensi/peafowl/badge)](https://www.codefactor.io/repository/github/danieledesensi/peafowl/)
[![HitCount](http://hits.dwyl.io/DanieleDeSensi/Peafowl.svg)](http://hits.dwyl.io/DanieleDeSensi/Peafowl)
[![MIT Licence](https://badges.frapsoft.com/os/mit/mit.svg?v=103)](https://opensource.org/licenses/mit-license.php)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](http://paypal.me/DanieleDeSensi)
<noscript><a href="https://liberapay.com/~36438/donate"><img height="22" alt="Donate using Liberapay" src="https://liberapay.com/assets/widgets/donate.svg"></a></noscript>


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
    <td>IMAP</td><td>5/5</td>
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
    <td>SIP</td><td>5/5</td>
  </tr>
  <tr>
    <td>RTP</td><td>4/5</td>
  </tr>
  <tr>
    <td>Skype</td><td>3/5</td>
  </tr>
  <tr>
    <td>Hangout</td><td>3/5</td>
  </tr>
  <tr>
    <td>WhatsApp</td><td>4/5</td>
  </tr>
  <tr>
    <td>Telegram</td><td>?</td>
  </tr>
  <tr>
    <td>Dropbox</td><td>3/5</td>
  </tr>
  <tr>
    <td>Spotify</td><td>5/5</td>
  </tr>
  <tr>
    <td>SSH</td><td>5/5</td>
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
  <tr>
    <td>SSL</td><td>Certificate</td>
  </tr>
  <tr>
    <td>SIP</td><td>Request URI</td>
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
$ mkdir build
$ cd build
$ cmake ../
$ make
```

After that, install it with

```
$ make install
```

Sequential version
------------------------------------------------------------------------------------------------------------
At this point, your application can use Peafowl by including the ["src/peafowl.h"](src/peafowl.h) header and by 
linking lib/libdpi.a.

The API is based on 3 main calls:

+ ```pfwl_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS)```:
used to initialize the state of the framework. It requires the size of the tables that the framework will use
and the maximum number of flows that the framework should manage. When this number of flows is reached, the 
framework will add no other flows to the table. This call returns an handle to the framework, which will
be required as parameter for most of the framework calls;

+ ```pfwl_get_protocol(state, packet, length, timestamp)```:
 used to identify a specific packet. It requires the handle to the framework, a pointer to the beginning of
 IP header, its length starting from the IP header, and a timestamp in seconds. It returns a struct containing
 the protocol of the packet and an indication of the status of the processing (e.g. success/failure and reason
 of the failure).
 
+ ```pfwl_terminate(state)```: used to terminate the framework. 

For other API calls (e.g. to enable/disable protocol inspectors or to enable/disable TCP stream reassembly and IP 
defragmentation please refer to the documentation in ["src/peafowl.h"](src/peafowl.h)).

Multicore version
------------------------------------------------------------------------------------------------------------------ 
You can take advantage of the multicore version by including the ["src/peafowl_mc.h"](src/peafowl_mc.h) header and by 
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

#include <peafowl.h>
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

    pfwl_library_state_t* state=pfwl_init_stateful(SIZE_IPv4_FLOW_TABLE, SIZE_IPv6_FLOW_TABLE, MAX_IPv4_ACTIVE_FLOWS, MAX_IPv6_ACTIVE_FLOWS);
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
    }else if(datalink_type==DLT_LINUX_SLL){
        printf("Datalink type: Linux Cooked\n");
        ip_offset=16;
    }else{
        fprintf(stderr, "Datalink type not supported\n");
        exit(-1);
    }



    const u_char* packet;
    struct pcap_pkthdr header;

    pfwl_identification_result_t r;
    u_int32_t protocols[PFWL_NUM_PROTOCOLS];
    memset(protocols, 0, sizeof(protocols));
    u_int32_t unknown=0;

    uint virtual_offset = 0;

    while((packet=pcap_next(handle, &header))!=NULL){
        if(datalink_type == DLT_EN10MB){
            if(header.caplen < ip_offset){
                continue;
            }
            uint16_t ether_type = ((struct ether_header*) packet)->ether_type;
            if(ether_type == htons(0x8100)){ // VLAN
                virtual_offset = 4;
            }
            if(ether_type != htons(ETHERTYPE_IP) &&
               ether_type != htons(ETHERTYPE_IPV6)){
                continue;
            }
        }

        r=pfwl_get_protocol(state, packet+ip_offset+virtual_offset, header.caplen-ip_offset-virtual_offset, time(NULL));


        if(r.protocol.l4prot == IPPROTO_TCP ||
           r.protocol.l4prot == IPPROTO_UDP){
            if(r.protocol.l7prot < PFWL_NUM_PROTOCOLS){
                ++protocols[r.protocol.l7prot];
            }else{
                ++unknown;
            }
        }else{
            ++unknown;
        }

    }

    pfwl_terminate(state);

    if (unknown > 0) printf("Unknown packets: %"PRIu32"\n", unknown);
    for(size_t i = 0; i < PFWL_NUM_PROTOCOLS; i++){
        if(protocols[i] > 0){
            printf("%s packets: %"PRIu32"\n", pfwl_get_protocol_string(i), protocols[i]);
        }
    }
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

This file contains information for advanced users who want to modify the default configuration of the framework
or who want to add new protocols to the framework. 

Adding new protocols
================================================================================================================
If you want to add the support for new protocols, you can do it by following some simple steps.
For example, if you want to add the support for the Telnet protocol:

1) Define the protocol and give to it the next available numeric identifier (file ```include/peafowl/inspectors/protocols_identifiers.h```).

```C
/** Protocols. **/
enum protocols{
    PFWL_PROTOCOL_HTTP=0,
  PFWL_PROTOCOL_BGP,
  PFWL_PROTOCOL_SMTP,
  PFWL_PROTOCOL_POP3,
  PFWL_PROTOCOL_TELNET, // <--- Insert this line right before 'PFWL_NUM_PROTOCOLS' to assign an identifier to the new protocol
  PFWL_NUM_PROTOCOLS
};
```

2) Create a new inspector, by implementing a C function with the following signature and semantic:

```C
uint8_t check_telnet(pfwl_library_state_t* state,    // The state of the library
                      pfwl_pkt_infos_t* pkt,          // The parsed information about the current packet
                      const unsigned char* app_data, // A pointer to the beginning of the 
                                                     // application (layer 7) data
                      uint32_t data_length,         // The lenght of the application data
                      pfwl_tracking_informations_t* t // Information about the current state of the 
                                                     // connection to which the packet belongs to
                      );
```
The function declaration must be put in ```include/peafowl/inspectors/inspectors.h```, while its definition can be put 
in a new source file in inspectors folder (e.g. ```src/inspectors/telnet.c```).

This function, after analyzing "app_data" and using the knowledge about the current state of the flow
can return one of four different values:

+ PFWL_PROTOCOL_MATCHES: If the protocol matches for sure
+ PFWL_PROTOCOL_NO_MATCHES: If the protocol doesn't matches for sure
+ PFWL_PROTOCOL_MORE_DATA_NEEDED: If the inspector needs more data to be sure that the protocol matches 
+ PFWL_PROTOCOL_ERROR: If an error occurred

You can look at one of the existing inspectors to see some examples. An inspector will parse both TCP
and UDP packets, so it may be a good idea, as a first thing, to return PFWL_PROTOCOL_NO_MATCHES when 
the inspectors is called on UDP packets for a protocol which only works over TCP (e.g. HTTP).

If the inspector needs to store information about the application flow, add an appropriate structure in the 
flow data description (```include/peafowl/flow_table.h```, ```struct pfwl_tracking_informations```). 

```C
typedef struct pfwl_tracking_informations{
    [...]
    /************************************/
    /* Protocol inspectors support data */
    /************************************/
    [...]
    /***********************************/
    /** Telnet Tracking informations. **/
    /***********************************/
    void* telnet_state;
}pfwl_tracking_informations_t;
```

These data can be then used by the inspector by accessing the parameter ```t```.

3) In file ```src/peafowl.c```, create a descriptor for the new protocol, by adding a descriptor struct to the ```protocols_descriptors``` array. The descriptor has the following fields:
* name: A string representation for the protocol (e.g. ```"TELNET"```).
* dissector: The function to detect the if the packet is carrying data for the given protocol. (Described in point 2)
* get_extracted_fields: A function to get the fields extracted by the dissector (Will be described when talking about data extraction)
* extracted_fields_num: The number of fields extracted by the dissector (Will be described when talking about data extraction)

4) If the protocol usually run on one or more predefined ports, specify the association between the ports and 
the protocol identifier (```src/peafowl.c```).

```C
static const pfwl_l7_prot_id const
  pfwl_well_known_ports_association_tcp[PFWL_MAX_UINT_16+1] =
    {[0 ... PFWL_MAX_UINT_16] = PFWL_PROTOCOL_UNKNOWN
    ,[port_http] = PFWL_PROTOCOL_HTTP
    ,[port_bgp] = PFWL_PROTOCOL_BGP
    ,[port_smtp_1] = PFWL_PROTOCOL_SMTP
    ,[port_smtp_2] = PFWL_PROTOCOL_SMTP
    ,[port_pop3] = PFWL_PROTOCOL_POP3
    ,[port_telnet] = PFWL_PROTOCOL_TELNET};
```

In this way, when the framework receives a protocol on the telnet port, it will first check if the carried
protocol is telnet and, if this is not the case, it will check the other protocols.
In a similar way, if the protocol runs over UDP instead of TCP, you have to add it to 
```pfwl_well_known_ports_association_udp``` array.

```port_telnet``` must be specified in network byte order. See the definitions in ```include/peafowl/inspectors/protocols_identifiers.h``` for some examples.

5) Add unit tests for the protocol. Suppose you are adding the support for the ```TELNET``` protocol. 
First, you need to add a ```testTelnet.cpp``` file under ```./test/```. This file will be automatically compiled and
executed when the tests are run. In this file you should put the code for checking that the protocol ```TELNET```
is correctly identified. You can check correctness in the way you prefer.

However, the suggested (and simplest) way is the following:
- Place a .pcap file containing some packets for the protocol under the ```./test/pcaps```
folder. Suppose this file is called ```TELNET.pcap```. If the protocol is a TCP-based protocol,
check that the .pcap contains the SYN packets which open the TCP connection.
- Peafowl relies on [googletest](https://github.com/google/googletest). In the ```testTelnet.cpp``` file
you can check the correctness of the identification by running the following code:

```C
#include "common.h"

TEST(TELNETTest, Generic) {
    std::vector<uint> protocols;
    getProtocols("./pcaps/TELNET.pcap", protocols);
    EXPECT_EQ(protocols[PFWL_PROTOCOL_TELNET], (uint) 42);
}

```

Where ```42``` is the number of ```TELNET``` packets you expect to be identified by the protocol inspector.
Of course, you can check the correctness of the protocol in any other way.

6) Recompile the framework with testing option enabled and run the tests to check that the unit tests succeed:

```
$ cd build
$ rm -rf *
$ cmake -DENABLE_TESTS=ON ../
$ make
$ make test
```

If you implemented the support for some other protocols please let me know so I can add them to the framework.

Adding data extraction capabilities to existing protocol inspectors
----------------------------------------------------------------------------------------------------------------
As we said before, beside protocol identification, is possible to seamlessly provide data and metadata carried
by the protocols to the application that uses the framework. In this way, the application specifies which data it
needs and which callback the framework has to invoke when this data is found. To add this capability to existing 
inspector you need to follow some simple steps. For example, to add it to POP3 you need to:

1) Define in the ```include/peafowl/inspectors/fields.h``` header an enumeration with the identifiers of the fields you want to extract,
for example

```C
typedef enum{
  PFWL_FIELDS_POP3_SRC_ADDR = 0, // Source mail address
  PFWL_FIELDS_POP3_DST_ADDR,     // Destination mail address
  PFWL_FIELDS_POP3_NUM,          // This is not a field, must be the last to indicate the number of possible fields
}pfwl_fields_pop3;
```

2) Add to the ```extracted_fields``` union in the ```pfwl_tracking_informations_t``` struct in the ```include/peafowl/flow_table.h``` header the array of fields, e.g.:
```C
pfwl_field_t pop3[PFWL_FIELDS_POP3_NUM];
```

3) Define in ```include/peafowl/inspectors/fields.h``` a function to get the pointer to the fields given a ```pfwl_tracking_informations_t```
struct. For the POP3 case, the function would have a signature such as:

```C
pfwl_field_t* get_extracted_fields_pop3(pfwl_tracking_informations_t*);

```

Its implementation (which can be place in the ```.c``` file containing the implementation of the dissector), would look like:
```C
pfwl_field_t* get_extracted_fields_pop3(pfwl_tracking_informations_t* t){
  return t->extracted_fields.pop3;
}

```

4) Update the ```protocols_descriptors``` array in ```src/peafowl.c``` file, by setting the ```get_extracted_fields``` and ```extracted_fields_num``` fields.
The modified entry would look like:
```C
    [PFWL_PROTOCOL_POP3]     = {"POP3"    , check_pop3    , get_extracted_fields_pop3, PFWL_FIELDS_POP3_NUM},

```

5) In the protocol dissector, set the fields once you find them in the packet. 
You need to set both the content of the field and its length. To avoid copying and allocating new data, you can directly set the pointer to the packet payload. 
Indeed, Peafowl guarantees that the fields are valid only until the next packet for the same flow is received. 
Moreover, you could inspect and process some parts of the packet only if the user required that field.

E.g. suppose you want to set a field corresponding to the source mail address:

```C
if(pfwl_protocol_field_required(state, PFWL_PROTOCOL_POP3, PFWL_FIELDS_POP3_SRC_ADDR)){
    pfwl_field_t* src_address = &(t->extracted_fields.pop3[PFWL_FIELDS_POP3_SRC_ADDR]);
    src_address->s = app_data[....];
    src_address->len = ....;
}
```

6) Now inside your application you can check the fields that have been extracted. A field has been extracted only if its lenght is greater than zero.
For example:

```C
if(r.protocol.l7prot == PFWL_PROTOCOL_POP3 &&
   r.protocol_fields[PFWL_FIELDS_POP3_SRC_ADDR].len){
    // Address is stored inside r.protocol_fields[PFWL_FIELDS_POP3_SRC_ADDR].s; 
}
```

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

Export to Prometheus DB
================================================================================================================
Dependencies:
- libcurl: e.g. apt-get install libcurl4-openssl-dev

Configuration
================================================================================================================
Default parameters are suited for many cases. Different configuration parameters can be modified in "config.h" 
file. The most important are the following:

+ PFWL_CACHE_LINE_SIZE: Size of L1 cache line
+ PFWL_FLOW_TABLE_USE_MEMORY_POOL: If 1 a certain amount of memory is preallocated for the hash table. That
  amount of memory can be specified using macros PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4 and
  PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6 respectively for IPv4 and IPv6 hash tables.
+ PFWL_USE_MTF: If 1, when a packet is received, the information about its flow are moved on the top
  of the corresponding collision list. Experiments shown that this can be very useful in most cases.
+ PFWL_NUMA_AWARE: Experimental macro for NUMA machine support
+ PFWL_NUMA_AWARE_FLOW_TABLE_NODE: Experimental macro for NUMA machine support
+ PFWL_DEFAULT_MAX_TRIALS_PER_FLOW: Maximum number of attempts before declaring the protocol of the flow as 
  "Unknown". 0 means infinite.
+ PFWL_ENABLE_L3_TRUNCATION_PROTECTION and PFWL_ENABLE_L4_TRUNCATION_PROTECTION: To protect from the cases in which 
  the packet is truncated for some reasons
+ PFWL_FLOW_TABLE_HASH_VERSION: Hash function used for the hash table where the flows are stored. Can be one of:
  PFWL_SIMPLE_HASH, PFWL_FNV_HASH, PFWL_MURMUR3_HASH, PFWL_BKDR_HASH. Experiments shown that PFWL_SIMPLE_HASH is a 
  good choice for most cases.
+ PFWL_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE: Size of the table containing IPv4 fragments when IPv4 fragmentation
  is enabled.
+ PFWL_IPv4_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT: Maximum amount of memory that can be allocated to any 
  source for fragmentation purposes.
+ PFWL_IPv4_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT: Maximum amount of memory (global) that can be allocated 
  for fragmentation purposes.
+ PFWL_IPv4_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT: Maximum amount of time (seconds) which can elapse from
  when the first fragment for a datagram is received to the moment when it is completely rebuilt. If after
  this amount of time there is still some missing fragment, the fragments saved by the framework will be removed.
+ PFWL_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE: As for IPv4
+ PFWL_IPv6_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT: As for IPv4
+ PFWL_IPv6_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT: As for IPv4
+ PFWL_IPv6_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT: As for IPv4

Contributions
================================================================================================================
Peafowl has been mainly developed by Daniele De Sensi (d.desensi.software@gmail.com).

I would like to thank Prof. Marco Danelutto, Dr. Luca Deri and Dr. Massimo Torquati for their essential help and
valuable advices.

The following people contributed to Peafowl:
- Daniele De Sensi (d.desensi.software@gmail.com): Main developer
- Michele Campus (michelecampus5@gmail.com): DNS dissector
- Lorenzo Mangani (lorenzo.mangani@gmail.com): SIP, RTP and Skype dissectors
- max197616 (https://github.com/max197616): SSL dissector
- QXIP B.V. sponsored the development of some parts of Peafowl (e.g. SIP dissector, Prometheus DB export, and others)

