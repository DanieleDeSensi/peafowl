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
    DPI_PROTOCOL_HTTP=0,
	DPI_PROTOCOL_BGP,
	DPI_PROTOCOL_SMTP,
	DPI_PROTOCOL_POP3,
	DPI_PROTOCOL_TELNET, // <--- Insert this line right before 'DPI_NUM_PROTOCOLS' to assign an identifier to the new protocol
	DPI_NUM_PROTOCOLS
};
```

2) Create a new inspector, by implementing a C function with the following signature and semantic:

```C
uint8_t check_telnet(dpi_library_state_t* state,    // The state of the library
                      dpi_pkt_infos_t* pkt,          // The parsed information about the current packet
                      const unsigned char* app_data, // A pointer to the beginning of the 
                                                     // application (layer 7) data
                      uint32_t data_length,         // The lenght of the application data
                      dpi_tracking_informations_t* t // Information about the current state of the 
                                                     // connection to which the packet belongs to
                      );
```
The function declaration must be put in ```include/peafowl/inspectors/inspectors.h```, while its definition can be put 
in a new source file in inspectors folder (e.g. ```src/inspectors/telnet.c```).

This function, after analyzing "app_data" and using the knowledge about the current state of the flow
can return one of four different values:

+ DPI_PROTOCOL_MATCHES: If the protocol matches for sure
+ DPI_PROTOCOL_NO_MATCHES: If the protocol doesn't matches for sure
+ DPI_PROTOCOL_MORE_DATA_NEEDED: If the inspector needs more data to be sure that the protocol matches 
+ DPI_PROTOCOL_ERROR: If an error occurred

You can look at one of the existing inspectors to see some examples. An inspector will parse both TCP
and UDP packets, so it may be a good idea, as a first thing, to return DPI_PROTOCOL_NO_MATCHES when 
the inspectors is called on UDP packets for a protocol which only works over TCP (e.g. HTTP).

If the inspector needs to store information about the application flow, add an appropriate structure in the 
flow data description (```include/peafowl/flow_table.h```, ```struct dpi_tracking_informations```). 

```C
typedef struct dpi_tracking_informations{
    [...]
    /************************************/
    /* Protocol inspectors support data */
    /************************************/
    [...]
    /***********************************/
    /** Telnet Tracking informations. **/
    /***********************************/
    void* telnet_state;
}dpi_tracking_informations_t;
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
static const dpi_l7_prot_id const
	dpi_well_known_ports_association_tcp[DPI_MAX_UINT_16+1] =
		{[0 ... DPI_MAX_UINT_16] = DPI_PROTOCOL_UNKNOWN
		,[port_http] = DPI_PROTOCOL_HTTP
		,[port_bgp] = DPI_PROTOCOL_BGP
		,[port_smtp_1] = DPI_PROTOCOL_SMTP
		,[port_smtp_2] = DPI_PROTOCOL_SMTP
		,[port_pop3] = DPI_PROTOCOL_POP3
		,[port_telnet] = DPI_PROTOCOL_TELNET};
```

In this way, when the framework receives a protocol on the telnet port, it will first check if the carried
protocol is telnet and, if this is not the case, it will check the other protocols.
In a similar way, if the protocol runs over UDP instead of TCP, you have to add it to 
```dpi_well_known_ports_association_udp``` array.

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
    EXPECT_EQ(protocols[DPI_PROTOCOL_TELNET], (uint) 42);
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
  DPI_FIELDS_POP3_SRC_ADDR = 0, // Source mail address
  DPI_FIELDS_POP3_DST_ADDR,     // Destination mail address
  DPI_FIELDS_POP3_NUM,          // This is not a field, must be the last to indicate the number of possible fields
}pfwl_fields_pop3;
```

2) Add to the ```extracted_fields``` union in the ```dpi_tracking_informations_t``` struct in the ```include/peafowl/flow_table.h``` header the array of fields, e.g.:
```C
pfwl_field_t pop3[DPI_FIELDS_POP3_NUM];
```

3) Define in ```include/peafowl/inspectors/fields.h``` a function to get the pointer to the fields given a ```dpi_tracking_informations_t```
struct. For the POP3 case, the function would have a signature such as:

```C
pfwl_field_t* get_extracted_fields_pop3(dpi_tracking_informations_t*);

```

Its implementation (which can be place in the ```.c``` file containing the implementation of the dissector), would look like:
```C
pfwl_field_t* get_extracted_fields_pop3(dpi_tracking_informations_t* t){
  return t->extracted_fields.pop3;
}

```

4) Update the ```protocols_descriptors``` array in ```src/peafowl.c``` file, by setting the ```get_extracted_fields``` and ```extracted_fields_num``` fields.
The modified entry would look like:
```C
    [DPI_PROTOCOL_POP3]     = {"POP3"    , check_pop3    , get_extracted_fields_pop3, DPI_FIELDS_POP3_NUM},

```

5) In the protocol dissector, set the fields once you find them in the packet. 
You need to set both the content of the field and its length. To avoid copying and allocating new data, you can directly set the pointer to the packet payload. 
Indeed, Peafowl guarantees that the fields are valid only until the next packet for the same flow is received. 
Moreover, you could inspect and process some parts of the packet only if the user required that field.

E.g. suppose you want to set a field corresponding to the source mail address:

```C
if(pfwl_protocol_field_required(state, DPI_PROTOCOL_POP3, DPI_FIELDS_POP3_SRC_ADDR)){
    pfwl_field_t* src_address = &(t->extracted_fields.pop3[DPI_FIELDS_POP3_SRC_ADDR]);
    src_address->s = app_data[....];
    src_address->len = ....;
}
```

6) Now inside your application you can check the fields that have been extracted. A field has been extracted only if its lenght is greater than zero.
For example:

```C
if(r.protocol.l7prot == DPI_PROTOCOL_POP3 &&
   r.protocol_fields[DPI_FIELDS_POP3_SRC_ADDR].len){
    // Address is stored inside r.protocol_fields[DPI_FIELDS_POP3_SRC_ADDR].s; 
}
```


Configuration
================================================================================================================
Default parameters are suited for many cases. Different configuration parameters can be modified in "config.h" 
file. The most important are the following:

+ DPI_CACHE_LINE_SIZE: Size of L1 cache line
+ DPI_FLOW_TABLE_USE_MEMORY_POOL: If 1 a certain amount of memory is preallocated for the hash table. That
  amount of memory can be specified using macros DPI_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4 and
  DPI_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6 respectively for IPv4 and IPv6 hash tables.
+ DPI_USE_MTF: If 1, when a packet is received, the information about its flow are moved on the top
  of the corresponding collision list. Experiments shown that this can be very useful in most cases.
+ DPI_NUMA_AWARE: Experimental macro for NUMA machine support
+ DPI_NUMA_AWARE_FLOW_TABLE_NODE: Experimental macro for NUMA machine support
+ DPI_DEFAULT_MAX_TRIALS_PER_FLOW: Maximum number of attempts before declaring the protocol of the flow as 
  "Unknown". 0 means infinite.
+ DPI_ENABLE_L3_TRUNCATION_PROTECTION and DPI_ENABLE_L4_TRUNCATION_PROTECTION: To protect from the cases in which 
  the packet is truncated for some reasons
+ DPI_FLOW_TABLE_HASH_VERSION: Hash function used for the hash table where the flows are stored. Can be one of:
  DPI_SIMPLE_HASH, DPI_FNV_HASH, DPI_MURMUR3_HASH, DPI_BKDR_HASH. Experiments shown that DPI_SIMPLE_HASH is a 
  good choice for most cases.
+ DPI_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE: Size of the table containing IPv4 fragments when IPv4 fragmentation
  is enabled.
+ DPI_IPv4_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT: Maximum amount of memory that can be allocated to any 
  source for fragmentation purposes.
+ DPI_IPv4_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT: Maximum amount of memory (global) that can be allocated 
  for fragmentation purposes.
+ DPI_IPv4_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT: Maximum amount of time (seconds) which can elapse from
  when the first fragment for a datagram is received to the moment when it is completely rebuilt. If after
  this amount of time there is still some missing fragment, the fragments saved by the framework will be removed.
+ DPI_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE: As for IPv4
+ DPI_IPv6_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT: As for IPv4
+ DPI_IPv6_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT: As for IPv4
+ DPI_IPv6_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT: As for IPv4
