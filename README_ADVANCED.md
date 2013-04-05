This file contains information for advanced users who want to modify the default configuration of the framework
or who want to add new protocols to the framework. 

Adding new protocols
================================================================================================================
If you want to add the support for new protocols, you can do it by following some simple steps.
For example, if you want to add the support for the Telnet protocol:

1) Define the protocol and give to it the next available numeric identifier (file inspectors/protocols_identifiers.h).

```C
/** Protocols over TCP. **/
enum tcp_protocols{
 DPI_PROTOCOL_TCP_HTTP=0,
	DPI_PROTOCOL_TCP_BGP,
	DPI_PROTOCOL_TCP_SMTP,
	DPI_PROTOCOL_TCP_POP3,
	DPI_PROTOCOL_TCP_TELNET, // <--- Insert this line to assign an identifier to the new protocol
	DPI_NUM_TCP_PROTOCOLS
};
```
In a similar way, if the protocol runs over UDP instead of TCP, you have to add it to "enum udp_protocols".

2) Create a new inspector, by implementing a C function with the following signature and semantic:

```C
u_int8_t check_telnet(dpi_library_state_t* state,    // The state of the library
                      dpi_pkt_infos_t* pkt,          // The parsed information about the current packet
                      const unsigned char* app_data, // A pointer to the beginning of the 
                                                     // application (layer 7) data
                      u_int32_t data_length,         // The lenght of the application data
                      dpi_tracking_informations_t* t // Information about the current state of the 
                                                     // connection to which the packet belongs to
                      );
```
The function declaration must be put in inspectors/inspectors.h, while its definition can be put 
in a new source file in inspectors folder (e.g. inspectors/telnet.c) and then added to the 
inspectors/Makefile targets

```Makefile
TARGET = dhcp.o dhcpv6.o bgp.o dns.o http_parser_joyent.o http.o smtp.o pop3.o mdns.o ntp.o telnet.o
```

This function, after analyzing "app_data" and using the knowledge about the current state of the flow
can return one of four different values:

+ DPI_PROTOCOL_MATCHES: If the protocol matches for sure
+ DPI_PROTOCOL_NO_MATCHES: If the protocol doesn't matches for sure
+ DPI_PROTOCOL_MORE_DATA_NEEDED: If the inspector needs more data to be sure that the protocol matches 
+ DPI_PROTOCOL_ERROR: If an error occurred

3) If the inspector needs to store information about the application flow, add an appropriate structure in the 
flow data description (api.h, struct dpi_tracking_informations). These data can be then used by the inspector
by accessing the last parameter of the call described in point 2).

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

4) Add the inspector to the set of inspectors which will be called by the framework. This can be done by 
inserting a pointer to the corresponding function into an appropriate array (api.c).

```C
static const dpi_inspector_callback const
	tcp_inspectors[DPI_NUM_TCP_PROTOCOLS]=
		{[DPI_PROTOCOL_TCP_BGP]=check_bgp
		,[DPI_PROTOCOL_TCP_HTTP]=check_http
		,[DPI_PROTOCOL_TCP_SMTP]=check_smtp
		,[DPI_PROTOCOL_TCP_POP3]=check_pop3
		,[DPI_PROTOCOL_TCP_TELNET]=check_telnet};
```

In a similar way, if the protocol runs over UDP instead of TCP, you have to add it to "tcp_inspectors" array.

5) If the protocol usually run on one or more predefined ports, specify the association between the ports and 
the protocol identifier (api.c).

```C
static const dpi_l7_prot_id const
	dpi_well_known_ports_association_tcp[DPI_MAX_UINT_16+1]=
		{[0 ... DPI_MAX_UINT_16]=DPI_PROTOCOL_UNKNOWN
		,[port_http]=DPI_PROTOCOL_TCP_HTTP
		,[port_bgp]=DPI_PROTOCOL_TCP_BGP
		,[port_smtp_1]=DPI_PROTOCOL_TCP_SMTP
		,[port_smtp_2]=DPI_PROTOCOL_TCP_SMTP
		,[port_pop3]=DPI_PROTOCOL_TCP_POP3
		,[port_telnet]=DPI_PROTOCOL_TCP_TELNET};
```

In this way, when the framework receives a protocol on the telnet port, it will first check if the carried
protocol is telnet and, if this is not the case, it will check the other protocols.
In a similar way, if the protocol runs over UDP instead of TCP, you have to add it to 
"dpi_well_known_ports_association_udp" array.

6) Recompile the framework.

If you implemented the support for some other protocols please let me know so I can add them to the framework.

Adding data extraction capabilities to existing protocol inspectors
----------------------------------------------------------------------------------------------------------------
As we said before, beside protocol identification, is possible to seamlessly provide data and metadata carried
by the protocols to the application that uses the framework. In this way, the application specifies which data it
needs and which callback the framework has to invoke when this data is found. To add this capability to existing 
inspector you need to follow some simple steps. For example, to add it to POP3 you need to:

1) Create a struct that will be used by the application to indicate to the framework both the information about 
the data to extract and the function to use to process them, and define it in api.h. 
E.g.:

```C
typedef struct dpi_pop3_callbacks{
	/** Flags to specify which part of the POP3 message is needed by the application. **/
	u_int8_t user:1; //Set to 1 if the application wants to process the "USER" message of POP3 connections
	u_int8_t pass:1; //Set to 1 if the application wants to process the "PASS" message of POP3 connections
	u_int8_t list:1; //Set to 1 if the application wants to process the "LIST" message of POP3 connections
	u_int8_t retr:1; //Set to 1 if the application wants to process the "RETR" message of POP3 connections
	[...]
	/**
	 * The callbacks that will be invoked when the specified messages are found.
	 **/
	pop3_user_callback user_cb; //Invoked by the framework when a POP3 "USER" message is found
	pop3_pass_callback pass_cb; //Invoked by the framework when a POP3 "PASS" message is found
	pop3_list_callback list_cb; //Invoked by the framework when a POP3 "LIST" message is found
	pop3_retr_callback retr_cb; //Invoked by the framework when a POP3 "RETR" message is found
	[...]
}dpi_pop3_callbacks_t;
```

2) Define the signature of the callbacks used in the struct described in point 1). For example,

```C
typedef void(pop3_user_callback)(
	char* user;   // Content of the "USER" message
	uint length;  // Length of the "USER" message
	);
```

3) Define in api.h two functions to enable/disable these callbacks:
```C
u_int8_t dpi_pop3_enable_callbacks(dpi_library_state_t* state, dpi_pop3_callbacks_t* callbacks, void* user_data);

u_int8_t dpi_pop3_disable_callbacks(dpi_library_state_t* state);
```

These two functions must then be implemented in inspectors/pop3.c and they should simply copy the content
of "callbacks" into a sub-structure of "state".

4) To implement the extraction of these information you have to define the following function and add it to 
inspectors/pop3.c

```C
u_int8_t invoke_callbacks_pop3(dpi_library_state_t* state, dpi_pkt_infos_t* pkt, const unsigned char* app_data, 
                               u_int32_t data_length, dpi_tracking_informations_t* tracking);
```

The parameters are the same we described before for the creation of a new protocol inspector.
Accessing a sub-structure of "state" (filled with the functions described in 3) when the data extraction
capability is enabled), this function will have the knowledge of which data the application needs and how it
want them to be processed.

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
