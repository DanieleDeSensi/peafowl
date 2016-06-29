#GNU makefile
CXX = g++
CXXFLAGS =  -Wall -std=c++0x -DENABLE_RECONFIGURATION  -DARMA_DONT_USE_WRAPPER -DARMA_USE_BLAS -DARMA_USE_LAPACK -DARMA_USE_HDF5 -O0 -g # -O3
INCS = -I../../src/external/nornir/src/external/fastflow -I../../src/ -I../../demo/http_pattern_matching/pattern_matching_lib -I /home/desensi/libs/libpcap-1.3.0/ -I../../src/external/nornir/src/external/Mammut -I../../src/external/nornir/ -I /usr/include/libxml2
LIBS = -L/disc1/homes/desensi/lib64/ -lpcap -L../../lib/ -L../../demo/http_pattern_matching/pattern_matching_lib/ -lpatternmatching -lmcdpireconf -L../../src/external/nornir/src -lnornir -pthread -lrt -lm -lmlpack -llapack -lblas -lgsl -lgslcblas -larmadillo -lhdf5


.PHONY: all clean cleanall

all: dynamic_reconfiguration.cpp
	make -C ../../demo/http_pattern_matching/pattern_matching_lib lib
	$(CXX) $(INCS) $(CXXFLAGS) $? -o dynamic_reconfiguration $(LIBS) -lpthread
clean:
	-rm -fr *.o *~ 
cleanall:
	make clean
	-rm -fr dynamic_reconfiguration


