#GNU makefile
CXX = g++
CXXFLAGS = --std=c++11 -O3 -g -Wall -W -Xlinker -zmuldefs
INCLUDES = -I../../src/ -I../../src/external/fastflow/
LIBS = -lpcap -L../../lib/ -L./pattern_matching_lib/ -lpatternmatching 


.PHONY: all clean cleanall

all: 
	make -C ./pattern_matching_lib lib
	make http_pm_seq 
	make http_pm_mc
#	make http_pm_mc_pfring 
http_pm_seq: http_pm_seq.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $? -o $@ $(LIBS) -ldpi
http_pm_mc: http_pm_mc.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $? -o $@ $(LIBS) -lmcdpi -lpthread
http_pm_mc_pfring: http_pm_mc_pfring.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) $? -o $@ $(LIBS) -lmcdpi -lpthread -lpfring -lpcap
clean:
	make -C ./pattern_matching_lib clean
cleanall:
	make clean
	make -C ./pattern_matching_lib cleanall
	-rm -fr http_pm_seq http_pm_mc http_pm_mc_pfring


