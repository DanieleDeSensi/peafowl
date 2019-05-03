Flows
=====

To identify the application protocol, packets are classified in bidirectional sets of packets called *flows*. All the packets in a *flow* share the same:

+ Source IP and Destination IP addressess
+ Source and Destination Ports
+ Layer 4 protocol (TCP, UDP, etc...)

Flows are stored by Peafowl to correctly identify the protocol by correlating information of subsequent packets. When a connection is terminated (i.e. FINs arrived for TCP flows), or when no packets are received for a given  amount of time (30 seconds by default), the *flow* is considered as terminated and it is removed from the Peafowl  internal storage.

There are cases where the user may be interested not only in the information about the packet, but also  on information about the flow (e.g. how many packets/bytes have been sent on that *flow*). Such information can be accessed after the packet has been processed. For example, to know how many packets have been received on that flow up to that moment:

.. tabs::

   .. tab:: C
       
      .. code-block:: c

         double* packetsStat = info->flow_info->statistics[PFWL_STAT_PACKETS];
         long num_packets = packetsStat[PFWL_DIRECTION_OUTBOUND] + 
                            packetsStat[PFWL_DIRECTION_INBOUND];

   .. tab:: C++
       
      .. code-block:: cpp
         
         long numPackets = info.getStatistic(PFWL_STAT_PACKETS, PFWL_DIRECTION_OUTBOUND) +  
                           info.getStatistic(PFWL_STAT_PACKETS, PFWL_DIRECTION_INBOUND)

   .. tab:: Python

      .. code-block:: python

         numPackets = info.getStatistic(pfwl.Statistic.PACKETS, pfwl.Direction.OUTBOUND) + 
                      info.getStatistic(pfwl.Statistic.PACKETS, pfwl.Direction.INBOUND)

Since the *flows* are bidirectional, we consider as *outbound* the packets flowing from source to destination host (as specified in the *info* structure) and as *inbound* the packets flowing from destination to source host.

In some cases, instead of accessing such statistic packet-by-packet, it may be more helpful to access them only once, when the flow terminates and it is removed from the Peafowl storage. It is possible to do that  by specifying a callback function, which will be called by Peafowl when a flow terminates. This can be done in the following way:


.. tabs::

   .. tab:: C
       
      .. code-block:: c

         void cb(pfwl_flow_info_t* flow_info){
           // You can here access to the information about the 
           // flow before it is removed from the storage.
         }

         ...

         int main(int argc, char** argv){
           ...
           // Create peafowl handler, etc...
           pfwl_set_flow_termination_callback(handle, &cb);
           ...
           // Start dissecting the packets
           ...
         }

   .. tab:: C++
       
      .. code-block:: cpp
         
         class FlowManager: public peafowl::FlowManager{
         public:
           void onTermination(const peafowl::FlowInfo& info){
             // You can here access to the information about the 
             // flow before it is removed from the storage.
           }
         };

         ...

         int main(int argc, char** argv){
           ...
           // Create peafowl handler, etc...
           FlowManager fm;
           handle->setFlowManager(&fm);
           ...
           // Start dissecting the packets
           ...
         }


   .. tab:: Python

      .. code-block:: python
         
         class FlowManagerPy(pfwl.FlowManager):
             def onTermination(self, f):
               # You can here access to the information about the 
               # flow before it is removed from the storage.

         ...

         def main():
           ...
           # Create peafowl handler, etc...
           fm = FlowManagerPy()
           p.setFlowManager(fm)
           ...
           # Start dissecting the packets
           ...
         
         if __name__ == "__main__":
             main()

For a more detailed description of the aforementioned calls and for other API calls, please refer to the `API Reference`_ documentation.

Some full working examples can be found in the `demo folder <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/>`_:

* `C API <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/flows_summary/flows_summary.c>`_
* `C++ API <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/flows_summary/flows_summary.cpp>`_
* `Python API <https://github.com/DanieleDeSensi/peafowl/blob/master/demo/flows_summary/flows_summary.py>`_