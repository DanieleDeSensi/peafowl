[![Build Status](https://travis-ci.org/DanieleDeSensi/peafowl.svg?branch=master)](https://travis-ci.org/DanieleDeSensi/peafowl) 
[![release](https://img.shields.io/github/release/danieledesensi/peafowl.svg)](https://github.com/danieledesensi/peafowl/releases/latest)
[![Documentation Status](https://readthedocs.org/projects/peafowl/badge/?version=latest)](https://peafowl.readthedocs.io/en/latest/?badge=latest)
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

For a detailed description of the framework, of its usage, and on how to extend it, please refer to the [documentation](https://peafowl.readthedocs.io/en/latest/).

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

Basic Usage
------------------------------------------------------------------------------------------------------------
At this point, your application can use Peafowl by including the [<peafowl/peafowl.h>](include/peafowl/peafowl.h)
header and by adding ```-lpeafowl``` to the linker options.

The Peafowl API is based on 3 main calls:

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
 
+ ```pfwl_terminate(state)```: used to terminate the framework. 

Moreover, the following two calls can be used to extract and process specific protocol fields:

+ ```pfwl_field_add_L7(state, field)```: To require the extraction of a specific L7 (application level) protocol field (e.g. HTTP URL, DNS Server Name, etc...). Such field can be then accessed packet by packet by using ```pfwl_field_*_get``` calls on the ```dissection_info``` struct returned by the ```pfwl_dissect_from_L2``` call.

+ ```pfwl_field_*_tags_add_L7(state, field, value, matchingType, tag)```: To require the library to associate 'tags' to packets according to their content. 
The parameters are:
    * The handle to the framework
    * The identifier of the field
    * The value to match
    * The matching type (prefix match, suffix match or exact match)
    * The tag to associate to the packet when the match is found
For example, by calling ```pfwl_field_string_tags_add_L7(state, PFWL_FIELDS_L7_HTTP_BODY, "<?xml", PFWL_FIELD_MATCHING_PREFIX, "TAG_XML")```, every time the body of an HTTP packets starts with the ```<?xml``` string, the ```TAG_XML``` tag will be associated with that packet. The user can find the tags associated to each packet in the ```dissection_info``` struct returned by the ```pfwl_dissect_from_L2``` call. Tags matching rules can also be loaded from files by using the ```pfwl_field_tags_load_L7``` call.

For a more detailed description of the framework please refer to the [documentation](https://peafowl.readthedocs.io/en/latest/).


Contributions
================================================================================================================
Peafowl has been mainly developed by Daniele De Sensi (d.desensi.software@gmail.com).

The following people contributed to Peafowl:
- Daniele De Sensi (d.desensi.software@gmail.com): Main developer
- Michele Campus (michelecampus5@gmail.com): DNS, RTP and RTCP dissectors, L2 parsing
- Lorenzo Mangani (lorenzo.mangani@gmail.com): SIP, RTP and Skype dissectors
- max197616 (https://github.com/max197616): SSL dissector
- QXIP B.V. (http://qxip.net/) sponsored the development of some Peafowl features (e.g. SIP, RTP, RTCP dissectors and others)
- CounterFlowAI (https://www.counterflow.ai/) sponsored the development of some Peafowl features (e.g. TCP statistics)

I would like to thank Prof. Marco Danelutto, Dr. Luca Deri and Dr. Massimo Torquati for their essential help and
valuable advices.

Disclaimer
================================================================================================================
The authors of Peafowl are strongly against any form of censorship.
Please make sure that you respect the privacy of users and you have proper authorization to listen, 
capture and inspect network traffic.  
