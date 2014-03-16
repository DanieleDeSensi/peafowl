#GNU makefile
CXX = g++
CXXFLAGS = -O -g -Wall -W -ansi -Xlinker -zmuldefs -std=c++0x
INCLUDES = -I../../src/ -I../../src/fastflow/ -I../../demo/http_pattern_matching/pattern_matching_lib
LIBS = -lpcap -L../../lib/ -L../../demo/http_pattern_matching/pattern_matching_lib/ -lpatternmatching 


.PHONY: all clean cleanall

all:
	make -C ../../demo/http_pattern_matching/pattern_matching_lib lib
	make energy_consumption
energy_consumption: energy_consumption.c
	$(CXX) $(INCLUDES) $(CXXFLAGS) $? -o $@ $(LIBS) -lmcdpi -lpthread
clean:
	-rm -fr *.o *~ $(TARGET)
cleanall:
	make clean
	-rm -fr energy_consumption


