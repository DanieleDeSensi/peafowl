Low-level Configuration
=======================
Peafowl can be tuned by modifying some low-level configuration parameters, by modifying 
some ``#define`` in the ``include/config.h`` file before compiling and installing the library. 
The most important are the following:

+ ``PFWL_HTTP_MAX_HEADERS``: The maximum number of headers that can be extracted for a single HTTP packet [default = 256].
+ ``PFWL_DEFAULT_FLOW_TABLE_AVG_BUCKET_SIZE``: Default value for the average bucket size of the flow table.
+ ``PFWL_DEFAULT_EXPECTED_FLOWS``: Default value for the expected flows
+ ``PFWL_CACHE_LINE_SIZE``: Size of L1 cache line
+ ``PFWL_FLOW_TABLE_USE_MEMORY_POOL``: If 1 a certain amount of memory is preallocated for the hash table. That amount of memory can be specified using macros `` PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v4`` and ``PFWL_FLOW_TABLE_MEMORY_POOL_DEFAULT_SIZE_v6`` respectively for IPv4 and IPv6 hash tables.
+ ``PFWL_USE_MTF``: If 1, when a packet is received, the information about its flow are moved on the top of the corresponding collision list. Experiments shown that this can be very useful in most cases.
+ ``PFWL_NUMA_AWARE``: Experimental macro for NUMA machine support
+ ``PFWL_NUMA_AWARE_FLOW_TABLE_NODE``: Experimental macro for NUMA machine support
+ ``PFWL_DEFAULT_MAX_TRIALS_PER_FLOW``: Maximum number of attempts before declaring the protocol of the flow as  "Unknown". 0 means infinite.
+ ``PFWL_ENABLE_L3_TRUNCATION_PROTECTION`` and ``PFWL_ENABLE_L4_TRUNCATION_PROTECTION``: To protect from the cases in which  the packet is truncated for some reasons
+ ``PFWL_FLOW_TABLE_HASH_VERSION``: Hash function used for the hash table where the flows are stored. Can be one of: PFWL_SIMPLE_HASH, PFWL_FNV_HASH, PFWL_MURMUR3_HASH, PFWL_BKDR_HASH. Experiments shown that PFWL_SIMPLE_HASH is a  good choice for most cases.
+ ``PFWL_IPv4_FRAGMENTATION_DEFAULT_TABLE_SIZE``: Size of the table containing IPv4 fragments when IPv4 fragmentation is enabled.
+ ``PFWL_IPv4_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT``: Maximum amount of memory that can be allocated to any  source for fragmentation purposes.
+ ``PFWL_IPv4_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT``: Maximum amount of memory (global) that can be allocated  for fragmentation purposes.
+ ``PFWL_IPv4_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT``: Maximum amount of time (seconds) which can elapse from when the first fragment for a datagram is received to the moment when it is completely rebuilt. If after this amount of time there is still some missing fragment, the fragments saved by the framework will be removed.
+ ``PFWL_IPv6_FRAGMENTATION_DEFAULT_TABLE_SIZE``: As for IPv4
+ ``PFWL_IPv6_FRAGMENTATION_DEFAULT_PER_HOST_MEMORY_LIMIT``: As for IPv4
+ ``PFWL_IPv6_FRAGMENTATION_DEFAULT_TOTAL_MEMORY_LIMIT``: As for IPv4
+ ``PFWL_IPv6_FRAGMENTATION_DEFAULT_REASSEMBLY_TIMEOUT``: As for IPv4
