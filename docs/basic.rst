Basic Usage
===========

After installing Peafowl, it can be used by your application by specifying the appropriate compilation flags for C and C++ or by loading the ``pypeafowl`` module for Python:

.. tabs::

   .. tab:: C

      Include the ``peafowl/peafowl.h`` header and add ``-lpeafowl`` flag to the linker options.
   
   .. tab:: C++

      Include the ``peafowl/peafowl.hpp`` header and add ``-lpeafowl`` flag to the linker options.

   .. tab:: Python

      .. code-block:: python

         import pypeafowl as pfwl


The first thing to do in your program, is creating an handle to the Peafowl library:

.. tabs::

   .. tab:: C
       
      .. code-block:: c
         
         pfwl_state_t* handle = pfwl_init();

   .. tab:: C++
       
      .. code-block:: cpp
         
         peafowl::Peafowl* handle = new peafowl::Peafowl();

   .. tab:: Python

      .. code-block:: python

         handle = pfwl.Peafowl()

This call initializes the framework and returns an handle, which will be used for most of the framework calls.
After creating the handle, you can start analyzing the network packets. As anticipated, Peafowl does not rely on
any specific packet capture library, and only requires you to provide a pointer to the packet, which you can read
with whatever mechanism you prefer (e.g. libpcap, etc..). To dissect the packet:

.. tabs::

   .. tab:: C
       
      .. code-block:: c
         
         pfwl_flow_info_t* info;
         pfwl_status_t status = pfwl_dissect_from_L3(handle, pkt, length, ts, info);

      The parameters are:
        * The handle to the framework
        * The packet, as a pointer to the beginning of Layer 3 (IP) header 
        * The packet length
        * A timestamp. By default it must specified with seconds resolution. However, this may be changed with appropriate calls (see `API Reference`_ for details).
        * The last parameter will be filled by Peafowl with the information about protocols detected at different layers and about the data and metadata carried by the different layers.
      
      The call returns a status which provides additional information on the processing (or an error).

      For example, to print the application protocol:

      .. code-block:: c

         if(status >= PFWL_STATUS_OK){
           printf("%s\n", pfwl_get_L7_protocol_name(info.l7.protocol));
         }
   
   .. tab:: C++
       
      .. code-block:: cpp
         
         peafowl::DissectionInfo info = handle->dissectFromL3(pkt, ts);
      
      The parameters are:
        * The packet, as a pointer to the beginning of Layer 3 (IP) header 
        * A timestamp. By default it must specified with seconds resolution. However, this may be changed with appropriate calls (see `API Reference`_ for details).

      This call returns a struct containing the status of the processing and information about protocols detected at different layers
      and about the data and metadata carried by the different layers.

      For example, to print the application protocol:

      .. code-block:: cpp

         if(!info.getStatus().isError()){
           std::cout << info.getL7().getProtocol().getName() << std::endl;
         }

   .. tab:: Python

      .. code-block:: python

         info = handle.dissectFromL3(pkt, ts)
      
      The parameters are:
        * The packet, as a pointer to the beginning of Layer 3 (IP) header 
        * A timestamp. By default it must specified with seconds resolution. However, this may be changed with appropriate calls (see `API Reference`_ for details).

      This call returns a struct containing the status of the processing and information about protocols detected at different layers
      and about the data and metadata carried by the different layers.

      For example, to print the application protocol:

      .. code-block:: python

         if not info.getStatus().isError():
           print(info.getL7().getProtocol().getName())

Similar calls are available for analyzing the packet starting from the beginning of Layer 2 or Layer 4 header. For more information
please refer to the `API Reference`_.

Eventually, when Peafowl is no more needed, you should deallocate the resources used by Peafowl:

.. tabs::

   .. tab:: C
       
      .. code-block:: c
         
         pfwl_terminate(handle);

   .. tab:: C++
       
      .. code-block:: cpp
         
         delete handle;

   .. tab:: Python

      .. code-block:: python

         del handle

For a more detailed description of the aforementioned calls and for other API calls, please refer to the `API Reference`_ documentation.

Some full working examples can be found in the `demo folder <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/>`_:

* `C API <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/protocol_identification/protocol_identification.c>`_
* `Python API <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/protocol_identification/protocol_identification.py>`_
