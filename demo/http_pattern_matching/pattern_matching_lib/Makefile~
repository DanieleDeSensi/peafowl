#GNU makefile

CXX = g++
CXXFLAGS = -O -g -Wall -W -ansi 
INCLUDES = -I../../../src/ -I../../../src/fastflow/
LDFLAGS = -lpcap -L../../../lib/ -Xlinker -zmuldefs 

DOXYGEN = doxygen

SOURCES = buffer.cc ../http_pm_mc_pfring.cc signatures.cc timer.cc trie.cc
TARGETS = http_pm_mc_pfring #http_pm_seq http_pm_mc

.PHONY: all clean doxygen realclean

all: $(TARGETS)

http_pm_seq: buffer.o http_pm_seq.o signatures.o timer.o trie.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $+ -o $@
	mv http_pm_seq  ../
http_pm_mc: buffer.o http_pm_mc.o signatures.o timer.o trie.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -lmpdpi -lpthread $+ -o $@
	mv http_pm_mc  ../
http_pm_mc_pfring: buffer.o http_pm_mc_pfring.o signatures.o timer.o trie.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -lmpdpi -lpthread -lpfring $+ -o $@
	mv http_pm_mc_pfring  ../
doxygen:
	$(DOXYGEN)

clean:
	rm -f $(SOURCES:.cc=.o) $(SOURCES:.cc=.d) core *.core

realclean: clean
	rm -f $(TARGETS)
	rm -rf doxygen

http_pm_seq.o : ../http_pm_seq.cc
	$(CXX) $(INCLUDES) $(CXXFLAGS) -c ../http_pm_seq.cc -o http_pm_seq.o

http_pm_mc.o : ../http_pm_mc.cc
	$(CXX) $(INCLUDES) $(CXXFLAGS) -c ../http_pm_mc.cc -o http_pm_mc.o

http_pm_mc_pfring.o : ../http_pm_mc_pfring.cc
	$(CXX) $(INCLUDES) $(CXXFLAGS) -c ../http_pm_mc_pfring.cc -o http_pm_mc_pfring.o

%o : %.cc
	$(CXX) $(INCLUDES) $(CXXFLAGS) -c $< -o $@
