Adding New Fields
=================
As described before, besides protocol identification, it is possible to seamlessly provide data and metadata carried by the protocols to the application that uses the framework. To add this capability to existing  inspector you need to follow some simple steps. 

For example, let us assume that POP3 dissector is available in Peafowl but no field extraction capabilities are provided yet. To extract POP3 fields the following steps must be followed:

1. Add to the ``field_L7_descriptors`` array in the ``src/parsing_l7.c`` source file, the descriptors for the fields you want to extract, for example:

  .. code-block:: c
  
     typedef enum{
       [...]
       {PFWL_PROTO_L7_POP3 , "SRC_ADDR", PFWL_FIELD_TYPE_STRING, "POP3 source address"},
       {PFWL_PROTO_L7_POP3 , "DST_ADDR", PFWL_FIELD_TYPE_STRING, "POP3 destination address"},
       [...]
     }pfwl_field_id_t;
  
  The elements specified are defined as follows:
    - The first element is the protocol for which we want to extract the field
    - The second element is the short name of the field. Enum values called ``PFWL_FIELDS_L7_POP3_SRC_ADDR`` and ``PFWL_FIELDS_L7_POP3_DST_ADDR`` will be automatically generated when compiling the code, and could be used by the user inside the application.
    - The third element is the type of field. In this case both addresses are strings.
    - The fourth and last field is a textual description of the field (just used for documentation purposes).

2. In the protocol dissector, set the fields once you find them in the packet. Different types of fields are supported, and some helper functions (e.g. ``pfwl_field_string_set(...)``) are provided to simplify setting the fields. Peafowl guarantees that the fields are valid only until the next packet for the same flow is received. Accordingly, to avoid data copying, for STRING fields you can just set a pointer to the position in the original packet. Instead of copying the data. Moreover, you could inspect and process some parts of the packet only if the user required that field.

  E.g. suppose you want to set a field corresponding to the source mail address:
  
  .. code-block:: c
  
     if(pfwl_protocol_field_required(state, PFWL_FIELDS_L7_POP3_SRC_ADDR)){
       pfwl_field_string_set(dissection_info, PFWL_FIELDS_L7_POP3_SRC_ADDR, [pointer to the address start in the packet], [length of the address])
     }


3. Now, inside the application that is using Peafowl, it is possible to check the fields that have been extracted. Helper function are provided.  

  For example:
  
  .. code-block:: c
     
     if(pfwl_dissect_from_L2(state, packet, header.caplen, time(NULL), dlt, &dissection_info) >= PFWL_STATUS_OK){
       if(dissection_info.l7.protocol == PFWL_PROTOCOL_POP3){
         pfwl_string_t src_addr;
         if(!pfwl_field_string_get(&dissection_info.l7.protocol_fields, PFWL_FIELDS_L7_POP3_SRC_ADDR, &src_addr)){
           // Use src_addr string
         }
       }
     }
  
If you implemented the extraction of some other fields please consider opening a Pull Request.