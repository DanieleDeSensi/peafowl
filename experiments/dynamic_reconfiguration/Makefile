#GNU makefile
CXX = g++
CXXFLAGS = -g -O -Wall -W -ansi -Xlinker -zmuldefs -std=c++0x 
INCS = -I../../src/ -I../../src/fastflow/ -I../../src/fastflow/ff -I../../demo/http_pattern_matching/pattern_matching_lib -I /home/desensi/libs/libpcap-1.3.0/
LIBS = -lpcap -L../../lib/ -L../../demo/http_pattern_matching/pattern_matching_lib/ -lpatternmatching 


.PHONY: all reconf noreconf common clean cleanall

all: noreconf

reconf: export INCS += -I../../src/external/adaptivefastflow/src/external/Mammut -I../../src/external/adaptivefastflow/ -I /usr/include/libxml2
reconf: export CXXFLAGS += -DENABLE_RECONFIGURATION
reconf: export LIBS += -lmcdpireconf -L../../src/external/adaptivefastflow/src -lgrape -pthread -lrt -lm -lmlpack -llapack -lblas -lgsl -lgslcblas
reconf: common
	mv dynamic_reconfiguration dynamic_reconfiguration_reconf

noreconf: export LIBS += -lmcdpi
noreconf: common
	mv dynamic_reconfiguration dynamic_reconfiguration_noreconf

common: dynamic_reconfiguration.cpp
	make -C ../../demo/http_pattern_matching/pattern_matching_lib lib
	$(CXX) $(INCS) $(CXXFLAGS) $? -o dynamic_reconfiguration $(LIBS) -lpthread
clean:
	-rm -fr *.o *~ 
cleanall:
	make clean
	-rm -fr dynamic_reconfiguration_reconf dynamic_reconfiguration_noreconf


