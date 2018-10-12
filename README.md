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
is completely and transparently performed by the framework. Accordingly, by using Peafowl is possible to implement
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

At the moment, data and metadata extraction is supported for the following protocols (for a full list of fields please refer to the [Peafowl](include/peafowl/peafowl.h) header:

<table>
  <tr>
    <th>Protocol</th><th>Kind of data that the framework can provide to the application</th>
  </tr>
  <tr>
    <td>HTTP</td><td>Any kind of HTTP header, HTTP body, HTTP version, etc...</td>
  </tr>
  <tr>
    <td>SSL</td><td>Certificate</td>
  </tr>
  <tr>
    <td>SIP</td><td>Request URI, Contact URI, Call ID, Method, etc...</td>
  </tr>
  <tr>
    <td>DNS</td><td>Server name, authority name</td>
  </tr>
<table>

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

A more detailed (but outdated) description can be found in the thesis which lead to the development of this framework: [Thesis.pdf](Thesis.pdf)

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
At this point, your application can use Peafowl by including the [<peafowl/peafowl.h>](include/peafowl/peafowl.h)
header and by adding ```-lpeafowl``` to the linker options.

The Peafowl API is based on 4 main calls:

+ ```pfwl_init()```: used to initialize the state of the framework. This call returns an handle to the framework, 
which will be required as parameter for most of the framework calls;

+ ```pfwl_dissect_from_L2(state, packet, length, timestamp, datalink_type, dissection_info)```: used to identify a specific packet. 
The parameters are:
    * The handle to the framework
    * The packet, as a pointer to the beginning of L2 header 
    * The packet length
    * A timestamp (in seconds) 
    * The datalink type (it depends on how you capture the packets)

This call will fill the ```dissection_info``` struct with the information about protocols detected at different levels
and about the data and metadata carried by the different layers.
Moreover, the struct also contains the number of packets and bytes sent in each direction up to now (for the flow to
which this packet belongs).
The call returns a status which provides additional information on the processing (or an error).

+ ```pfwl_field_add_L7(state, field)```: To require the extraction of a specific L7 (application level) protocol field.
 
+ ```pfwl_terminate(state)```: used to terminate the framework. 

For other API calls (e.g. to extract specific L7 fields from the packets), please refer to the documentation in ["src/peafowl.h"](src/peafowl.h).
Documentation can also generated by doing:

```
$ mkdir build
$ cd build
$ cmake ../ -DENABLE_DOCS=ON
$ make docs
```

Then you will find the documentation in the ```docs``` folder.

Multicore version
------------------------------------------------------------------------------------------------------------------ 
A multicore version of Peafowl was available on pre 1.0.0 version of Peafowl. It is not available at the moment
but will be back in Peafowl v1.1.0

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
 *  Author: Daniele De Sensi (d.desensi.software@gmail.com)
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

int main(int argc, char** argv){
  if(argc != 2){
    fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
    return -1;
  }
  char* pcap_filename = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];  
  const u_char* packet;
  uint32_t protocols[PFWL_PROTO_L7_NUM];
  struct pcap_pkthdr header;
  memset(protocols, 0, sizeof(protocols));
  uint32_t unknown = 0;

  pcap_t *handle = pcap_open_offline(pcap_filename, errbuf);
  if(handle == NULL){
    fprintf(stderr, "Couldn't open device %s: %s\n", pcap_filename, errbuf);
    return (2);
  }

  pfwl_state_t* state = pfwl_init();
  pfwl_dissection_info_t r;
  pfwl_protocol_l2_t dlt = pfwl_convert_pcap_dlt(pcap_datalink(handle));
  while((packet = pcap_next(handle, &header))!=NULL){
    if(pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), dlt, &r) >= PFWL_STATUS_OK){
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
```

Other demos
---------------------------------------------------------------------------------------------------------------------
More demo applications can be found in [demo](demo) folder:

+ [protocol_identification_identification.c](demo/protocol_identification/protocol_identification.c): Given a .pcap file, 
  it identifies the protocol of all the packets contained in it.
+ [jpeg_dump.c](demo/dump_jpeg/dump_jpeg.c): Dumps on the disk all the jpeg images carried by HTTP packets captured from a .pcap 
  file or from the network.
+ [sip_extraction.c](demo/sip_extraction/sip_extraction.c): Extracts Request URI field from SIP packets.
+ [dns_extraction.c](demo/dns_extraction/dns_extraction.c): Extracts name server, authority server and IP address of name server from DNS packets.
+ [http_pm_seq.cpp](demo/http_pattern_matching/http_pm_seq.cpp): Searches in all the HTTP bodies a set of patterns (e.g. viruses signatures, an [example](demo/http_pattern_matching/signatures.example) of a signatures set is provided). The TCP stream is analyzed in the correct order and the pattern is correctly identified also when splitted 
  over multiple TCP segmentes. 

Adding new protocols
================================================================================================================
If you want to add the support for new protocols, you can do it by following some simple steps.
For example, if you want to add the support for the Telnet protocol:

1) Define the protocol and give to it the next available numeric identifier (file ```include/peafowl/peafowl.h```).

```C
/** Protocols. **/
enum protocols{
  PFWL_PROTO_L7_HTTP = 0,
  PFWL_PROTO_L7_BGP,
  PFWL_PROTO_L7_SMTP,
  PFWL_PROTO_L7_POP3,
  PFWL_PROTO_L7_TELNET, // <--- Insert this line right before 'PFWL_NUM_PROTOCOLS' to assign an identifier to the new protocol
  PFWL_PROTO_L7_NUM
};
```

2) Create a new inspector, by implementing a C function with the following signature and semantic:

```C
uint8_t check_telnet(pfwl_state_t* state,                         ///< The state of the library.
                   const unsigned char* app_data,                 ///< A pointer to the beginning of the 
                                                                  ///< application (layer 7) data.     
                   uint32_t data_length,                          ///< The lenght of the application data.
                   pfwl_dissection_info_t* dissection_info,       ///< Dissection data collected up to L4.
                   pfwl_flow_info_private_t* flow_info_private);  ///< Information about the flow the packet belongs to
```
The function declaration must be put in ```include/peafowl/inspectors/inspectors.h```, while its definition can be put 
in a new source file in inspectors folder (e.g. ```src/inspectors/telnet.c```).

This function, after analyzing "app_data" and using the knowledge about the current state of the flow
can return one of four different values:

+ PFWL_PROTOCOL_MATCHES: If the protocol matches for sure
+ PFWL_PROTOCOL_NO_MATCHES: If the protocol doesn't matches for sure
+ PFWL_PROTOCOL_MORE_DATA_NEEDED: If the inspector needs more data to be sure that the protocol matches 
+ PFWL_PROTOCOL_ERROR: If an error occurred

You can look at one of the existing inspectors to see some examples. 

If the inspector needs to store information about the application flow, add an appropriate structure in the 
```pfwl_flow_info_private_t``` structure (in file ```include/peafowl/flow_table.h```). This data will be 
flow-specific and will be preserved between different packets for the same flow. 

```C
typedef struct pfwl_flow_info_private{
    [...]
    /************************************/
    /* Protocol inspectors support data */
    /************************************/
    [...]
    /***********************************/
    /** Telnet Tracking informations. **/
    /***********************************/
    void* telnet_state;
}pfwl_flow_info_private_t;
```

These data can be then used by the inspector by accessing the parameter ```flow_info_private```.

3) In file ```src/parsing_l7.c```, create a descriptor for the new protocol, by adding a descriptor struct to the ```protocols_descriptors``` array. The descriptor has the following fields:
* name: A string representation for the protocol (e.g. ```"TELNET"```).
* dissector: The function to detect the if the packet is carrying data for the given protocol. (Described in point 2)
* transport: PFWL_L7_TRANSPORT_TCP if the protocol can only be carried by TCP packets, PFWL_L7_TRANSPORT_UDP if the protocol can only be carried by UDP packets, PFWL_L7_TRANSPORT_TCP_OR_UDP if the protocol can be carried by both TCP and UDP packets.

4) If the protocol usually run on one or more predefined ports, specify the association between the ports and 
the protocol identifier (```src/parsing_l7.c```).
ATTENTION: The ports must be specified in Network Byte Order! Check ```include/peafowl/inspectors/protocols_identifiers.h``` for some example.

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

In this way, when the framework receives a protocol on the telnet port, it will first check if the carried protocol is Telnet and, if this is not the case, it will check the other protocols. In a similar way, if the protocol runs over UDP instead of TCP, you have to add it to ```pfwl_well_known_ports_association_udp``` array.

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
================================================================================================================
As we said before, beside protocol identification, is possible to seamlessly provide data and metadata carried
by the protocols to the application that uses the framework. To add this capability to existing 
inspector you need to follow some simple steps. For example, let us assume that POP3 dissector is available
in Peafowl but no field extraction capabilities are provided yet. To extract POP3 fields the following
steps should be followed:

1) Add to the ```pfwl_field_id_t``` enum in the ```include/peafowl/peafowl.h``` header, the fields identifier for fields you want to extract,
for example

```C
typedef enum{
  [...]
  PFWL_FIELDS_L7_POP3_FIRST,        ///< Dummy value to indicate first POP3 field
  PFWL_FIELDS_L7_POP3_SRC_ADDR,     ///< Source mail address [STRING]
  PFWL_FIELDS_L7_POP3_DST_ADDR,     ///< Destination mail address [STRING]
  PFWL_FIELDS_L7_POP3_LAST,         ///< Dummy value to indicate last POP3 field. Must be the last field specified for SSL.
  [...]
}pfwl_field_id_t;
```

The reason why the two dummy values ```PFWL_FIELDS_L7_POP3_FIRST``` and ```PFWL_FIELDS_L7_POP3_LAST``` will be clear in a moment.

2) In file ```src/peafowl.c``` modify the ```pfwl_get_protocol_from_field``` for mapping the fields to the protocol they belong to.
For example, it would be sufficient to add:

```C
[...]
else if(field > PFWL_FIELDS_L7_POP3_FIRST && field < PFWL_FIELDS_L7_POP3_LAST){
  return PFWL_PROTO_L7_POP3;
}
[...]
```

3) In the protocol dissector, set the fields once you find them in the packet. Different types of fields are supported, and some helper
functions (e.g. ```pfwl_field_string_set(...)```) are provided to simplify setting the fields.
Peafowl guarantees that the fields are valid only until the next packet for the same flow is received. Accordingly, to avoid data copying,
for STRING fields you can just set a pointer to the position in the original packet. Instead of copying the data.
Moreover, you could inspect and process some parts of the packet only if the user required that field.

E.g. suppose you want to set a field corresponding to the source mail address:

```C
if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_POP3_SRC_ADDR)){
  pfwl_field_string_set(dissection_info, PFWL_FIELDS_L7_POP3_SRC_ADDR, [pointer to the address start in the packet], [length of the address])
}
```

4) Now, inside the application that is using Peafowl, it is possible to check the fields that have been extracted. Helper function are provided. 
For example:

```C
if(pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), dlt, &dissection_info) >= PFWL_STATUS_OK){
  if(dissection_info.l7.protocol == PFWL_PROTOCOL_POP3){
    pfwl_string_t src_addr;
    if(!pfwl_field_string_get(&dissection_info.l7.protocol_fields, PFWL_FIELDS_L7_POP3_SRC_ADDR, &src_addr)){
      // Use src_addr string
    }
  }
}
```

Configuration
================================================================================================================
Different configuration parameters can be modified in "config.h" file. The most important are the following:

+ PFWL_HTTP_MAX_HEADERS: The maximum number of headers that can be extracted for a single HTTP packet [default = 256].
+ PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE: Default value for the average bucket size of the flow table.
+ PFWL_DEFAULT_EXPECTED_FLOWS: Default value for the expected flows
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

The following people contributed to Peafowl:
- Daniele De Sensi (d.desensi.software@gmail.com): Main developer
- Michele Campus (michelecampus5@gmail.com): DNS dissector, L2 parsing
- Lorenzo Mangani (lorenzo.mangani@gmail.com): SIP, RTP and Skype dissectors
- QXIP B.V. sponsored the development of some parts of Peafowl (e.g. SIP dissector and others)
- max197616 (https://github.com/max197616): SSL dissector

I would like to thank Prof. Marco Danelutto, Dr. Luca Deri and Dr. Massimo Torquati for their essential help and
valuable advices.

Disclaimer
================================================================================================================
The authors of Peafowl are strongly against any form of censorship.
Please make sure that you respect the privacy of users and you have proper authorization to listen, 
capture and inspect network traffic.  