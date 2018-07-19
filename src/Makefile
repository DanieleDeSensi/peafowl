SEQTARGET            = utils.o ipv4_reassembly.o ipv6_reassembly.o reassembly.o tcp_stream_management.o hash_functions.o flow_table.o api.o 
PARTARGET            = worker.o mc_api.o

.PHONY: all clean cleanall install uninstall test seqlib parlib
.SUFFIXES: .cpp .o

all: 
	make clean
	make CONFIGURATIONFLAGS=-DDPI_THREAD_SAFETY_ENABLED=0 seq
	make seqlib
	rm *.o
	make CONFIGURATIONFLAGS=-DDPI_THREAD_SAFETY_ENABLED=1 par
	make parlib
tcp_stream_management.o: tcp_stream_management.c
	$(CC) $(INCS) $(CCFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c tcp_stream_management.c -o tcp_stream_management.o
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
	$(CC) $(INCS) $(CCFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c flow_table.c -o flow_table.o
api.o: api.c
	make -C ./inspectors
	$(CC) $(INCS) $(CCFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c api.c -o api.o
worker.o: worker.cpp
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c worker.cpp  -o worker.o 
mc_api.o: mc_api.cpp 
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $(CONFIGURATIONFLAGS) -c mc_api.cpp -o mc_api.o 
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
	$(CXX) $(SEQTARGET) inspectors/*.o -lm -shared -o ../lib/libdpi.so
par: $(SEQTARGET) $(PARTARGET)
parlib:
	make seqlib
	ar rs libmcdpi.a $(SEQTARGET) $(PARTARGET) inspectors/*.o
	mv libmcdpi.a ../lib/libmcdpi.a
	$(CXX) $(SEQTARGET) $(PARTARGET) inspectors/*.o -lm -shared -o ../lib/libmcdpi.so
