Fields Extraction
=================

Besides identifying the application protocol carried by the packets, Peafowl can also extract some data and metadata carried by the application protocol (e.g. HTTP URL, DNS Server Name, etc...). We call each of these piece of information *fields* (i.e., HTTP URL is a *field*).

To avoid performance overhead caused by extracting fields which would not be needed by the user, the user needs first to specify which fields must be extracted by Peafowl. Then, the user can check, packet-by-packet if the field was present. If the field is present, the user can then check its value. 

.. warning::
   Please note that the fields will be overwritten when the next packet is read, i.e. if you need to preserve the value of a field for a longer time, you need to make a copy of the field.

For example, to extract the HTTP URL field:

.. tabs::

   .. tab:: C
       
      .. code-block:: c
         
         // Create peafowl handler, etc...
         // Tell Peafowl to extract HTTP URL
         pfwl_field_add_L7(handle, PFWL_FIELDS_L7_HTTP_URL);
         ...
         // Start dissecting the packets
         ...
         // Check if the field is present and print it.
         pfwl_string_t field;
         if(!pfwl_field_string_get(info.l7.protocol_fields, PFWL_FIELDS_L7_HTTP_URL, &field)){
            printf("HTTP URL found: %.*s\n", (int) field.length, field.value);
         }
      .. warning::
         Please note that, to avoid copying data from the packet into another buffer, string fields are not '\0' terminated and you must explicitely consider their length.

   .. tab:: C++
       
      .. code-block:: cpp
         
         // Create peafowl handler, etc...
         // Tell Peafowl to extract HTTP URL
         handle.fieldAddL7(PFWL_FIELDS_L7_HTTP_URL);
         ...
         // Start dissecting the packets
         ...
         // Check if the field is present and print it.
         peafowl::Field field = info.getField(PFWL_FIELDS_L7_HTTP_URL);
         if(field.isPresent()){
           std::cout << "HTTP URL found: " << field.getString() << std::endl;
         }

   .. tab:: Python

      .. code-block:: python

         # Create peafowl handler, etc...
         # Tell Peafowl to extract HTTP URL
         handle.fieldAddL7(pfwl.Field.HTTP_URL)
         ...
         # Start dissecting the packets
         ...
         # Check if the field is present and print it.
         field = info.getField(pfwl.Field.HTTP_URL)
         if field.isPresent():
           print("HTTP URL found: " + field.getString())
         
For a more detailed description of the aforementioned calls and for other API calls, please refer to the `API Reference`_ documentation.

Some full working examples can be found in the `demo folder <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/>`_:

* C API:

  * `DNS Extraction <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/dns_extraction/dns_extraction.c>`_ : Extracts name server, authority server and IP address of name server from DNS packets
  * `HTTP JPEG Dump <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/dump_jpeg/dump_jpeg.c>`_ : Dumps on the disk all the jpeg images carried by HTTP packets captured from a .pcap file or from the network.
