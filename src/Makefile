CC                   = gcc
CXX                  = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = -O3 -finline-functions -fno-exceptions 
CXXFLAGS             = -Wall -g 
CFLAGS               =
CONFIGURATIONFLAGS   = 
LDFLAGS              = 
INCS                 = -I ./ -I ./fastflow/
LIBS                 = 
INCLUDES             =
SEQTARGET            = utils.o ipv4_reassembly.o ipv6_reassembly.o reassembly.o tcp_stream_management.o hash_functions.o flow_table.o api.o 
PARTARGET            = worker.o mc_api.o energy_utils.o

.PHONY: clean cleanall install uninstall test seqlib parlib
.SUFFIXES: .cpp .o

tcp_stream_management.o: tcp_stream_management.c
	$(CC) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c tcp_stream_management.c -o tcp_stream_management.o
utils.o: utils.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c utils.cpp -o utils.o
reassembly.o: reassembly.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c reassembly.cpp -o reassembly.o
ipv4_reassembly.o: ipv4_reassembly.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c ipv4_reassembly.cpp -o ipv4_reassembly.o
ipv6_reassembly.o: ipv6_reassembly.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c ipv6_reassembly.cpp -o ipv6_reassembly.o
hash_functions.o: hash_functions.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c hash_functions.cpp -o hash_functions.o
flow_table.o: flow_table.c
	$(CC) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c flow_table.c -o flow_table.o
api.o: api.c
	make -C ./inspectors
	$(CC) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c api.c -o api.o
worker.o: worker.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c worker.cpp  -o worker.o 
mc_api.o: mc_api.cpp 
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c mc_api.cpp -o mc_api.o 
energy_utils.o: energy_utils.c
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c energy_utils.c -o energy_utils.o
clean: 
	make -C ./inspectors clean
	-rm -fr *.o *~ *.a
cleanall:
	make -C ./inspectors cleanall
	-rm -fr *.o *~ *.a
	-rm -fr $(SEQTARGET) $(PARTARGET)
seq: $(SEQTARGET)
seqlib:
	ar rs libdpi.a $(SEQTARGET) inspectors/*.o
	mv libdpi.a ../lib/libdpi.a	
par: $(SEQTARGET) $(PARTARGET)
parlib:
	make seqlib
	ar rs libmcdpi.a $(SEQTARGET) $(PARTARGET) inspectors/*.o
	mv libmcdpi.a ../lib/libmcdpi.a
