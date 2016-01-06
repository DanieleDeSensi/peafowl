#GNU makefile
CXX = g++
CXXFLAGS = -O3 -Wall -W -Xlinker -zmuldefs -std=c++0x -DENABLE_RECONFIGURATION 
INCS = -I../../src/ -I../../src/fastflow/ -I../../src/fastflow/ff -I../../demo/http_pattern_matching/pattern_matching_lib -I /home/desensi/libs/libpcap-1.3.0/ -I../../src/external/adaptivefastflow/src/external/Mammut -I../../src/external/adaptivefastflow/ -I /usr/include/libxml2
LIBS = -lpcap -L../../lib/ -L../../demo/http_pattern_matching/pattern_matching_lib/ -lpatternmatching -lmcdpireconf -L../../src/external/adaptivefastflow/src -lgrape -pthread -lrt -lm -lmlpack -llapack -lblas -lgsl -lgslcblas 


.PHONY: all clean cleanall

all: dynamic_reconfiguration.cpp
	make -C ../../demo/http_pattern_matching/pattern_matching_lib lib
	$(CXX) $(INCS) $(CXXFLAGS) $? -o dynamic_reconfiguration $(LIBS) -lpthread
clean:
	-rm -fr *.o *~ 
cleanall:
	make clean
	-rm -fr dynamic_reconfiguration_reconf dynamic_reconfiguration_noreconf


