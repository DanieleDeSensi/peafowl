Adding New Protocols
====================
If you want to add the support for new protocols, you can do it by following some simple steps. Protocols must be added in the **C** implementation. They will then be automatically available to the **C++** and **Python** interfaces as well. 

For example, if you want to add the support for the Telnet protocol:

1. Define the protocol and give to it the next available numeric identifier (file ```include/peafowl/peafowl.h```).

  .. code-block:: c
  
     /** Protocols. **/
     typedef enum{
       PFWL_PROTO_L7_HTTP = 0,
       PFWL_PROTO_L7_BGP,
       PFWL_PROTO_L7_SMTP,
       PFWL_PROTO_L7_POP3,
       PFWL_PROTO_L7_TELNET, // <--- Insert this line right before 'PFWL_PROTO_L7_NUM' to assign an identifier to the new protocol
       PFWL_PROTO_L7_NUM
     }pfwl_protocol_l7_t;

2. Create a new inspector, by implementing a C function with the following signature and semantic:

  .. code-block:: c
  
     uint8_t check_telnet(pfwl_state_t* state,                         ///< The state of the library.
                        const unsigned char* app_data,                 ///< A pointer to the beginning of the 
                                                                       ///< application (layer 7) data.     
                        uint32_t data_length,                          ///< The lenght of the application data.
                        pfwl_dissection_info_t* dissection_info,       ///< Dissection data collected up to L4.
                        pfwl_flow_info_private_t* flow_info_private);  ///< Information about the flow the packet belongs to
  

  The function declaration must be put in ``include/peafowl/inspectors/inspectors.h``, while its definition can be put in a new source file in inspectors folder (e.g. ``src/inspectors/telnet.c``).

  This function, after analyzing "app_data" and using the knowledge about the current state of the flow can return one of four different values:
  
    - PFWL_PROTOCOL_MATCHES: If the protocol matches for sure
    - PFWL_PROTOCOL_NO_MATCHES: If the protocol doesn't matches for sure
    - PFWL_PROTOCOL_MORE_DATA_NEEDED: If the inspector needs more data to be sure that the protocol matches 
    - PFWL_PROTOCOL_ERROR: If an error occurred
  
  You can look at one of the existing inspectors to see some examples. 

  If the inspector needs to store information about the application flow, add an appropriate structure in the  ``pfwl_flow_info_private_t`` structure (in file ``include/peafowl/flow_table.h``). This data will be  flow-specific and will be preserved between different packets for the same flow. 

  .. code-block:: c
  
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
  
  
  These data can be then used by the inspector by accessing the parameter ``flow_info_private``.

3. In file ``src/parsing_l7.c``, create a descriptor for the new protocol, by adding a descriptor struct to the ``protocols_descriptors`` array. The descriptor has the following fields:

  - name: A string representation for the protocol (e.g. ``"TELNET"``).
  - dissector: The function to detect the if the packet is carrying data for the given protocol. (Described in point 2)
  - transport: PFWL_L7_TRANSPORT_TCP if the protocol can only be carried by TCP packets, PFWL_L7_TRANSPORT_UDP if the protocol can only be carried by UDP packets, PFWL_L7_TRANSPORT_TCP_OR_UDP if the protocol can be carried by both TCP and UDP packets.
  - dependencies_fields: Array of fields (of other protocols) needed to identify this protocol. Last value in the array must always be PFWL_FIELDS_L7_NUM

4. If the protocol usually run on one or more predefined ports, specify the association between the ports and the protocol identifier (``src/parsing_l7.c``).

  ATTENTION: The ports must be specified in Network Byte Order! Check ``include/peafowl/inspectors/protocols_identifiers.h`` for some example.
  
  .. code-block:: c
  
     static const pfwl_protocol_l7 const
       pfwl_known_ports_tcp[PFWL_MAX_UINT_16+1] =
         {[0 ... PFWL_MAX_UINT_16] = PFWL_PROTOCOL_UNKNOWN
         ,[port_http] = PFWL_PROTOCOL_HTTP
         ,[port_bgp] = PFWL_PROTOCOL_BGP
         ,[port_smtp_1] = PFWL_PROTOCOL_SMTP
         ,[port_smtp_2] = PFWL_PROTOCOL_SMTP
         ,[port_pop3] = PFWL_PROTOCOL_POP3
         ,[port_telnet] = PFWL_PROTOCOL_TELNET};
  
  
  In this way, when the framework receives a protocol on the telnet port, it will first check if the carried protocol is Telnet and, if this is not the case, it will check the other protocols. In a similar way, if the protocol runs over UDP instead of TCP, you have to add it to ``pfwl_known_ports_udp`` array.

5. Add unit tests for the protocol. Suppose you are adding the support for the ``TELNET`` protocol. First, you need to add a ``testTelnet.cpp`` file under ``./test/``. This file will be automatically compiled and executed when the tests are run. In this file you should put the code for checking that the protocol ``TELNET`` is correctly identified. You can check correctness in the way you prefer.

  However, the suggested (and simplest) way is the following:
  
  - Place a .pcap file containing some packets for the protocol under the ``./test/pcaps`` folder. Suppose this file is called ``TELNET.pcap``. If the protocol is a TCP-based protocol, check that the .pcap contains the SYN packets which open the TCP connection.
  - Peafowl relies on [googletest](https://github.com/google/googletest). In the ``testTelnet.cpp`` file you can check the correctness of the identification by running the following code:

  .. code-block:: c
  
     #include "common.h"
     
     TEST(TELNETTest, Generic) {
         std::vector<uint> protocols;
         getProtocols("./pcaps/TELNET.pcap", protocols);
         EXPECT_EQ(protocols[PFWL_PROTOCOL_TELNET], (uint) 42);
     }
  
  
  Where ``42`` is the number of ``TELNET`` packets you expect to be identified by the protocol inspector. Of course, you can check the correctness of the protocol in any other way.

6. Recompile the framework with testing option enabled and run the tests to check that the unit tests succeed:

  .. code-block:: shell
  
     $ cd build
     $ rm -rf *
     $ cmake -DENABLE_TESTS=ON ../
     $ make
     $ make test
  
  
If you implemented the support for some other protocols please consider opening a Pull Request.