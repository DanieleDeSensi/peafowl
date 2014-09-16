#GNU makefile
CXX = g++
CXXFLAGS = -O -g -Wall -W -ansi -Xlinker -zmuldefs -std=c++0x
INCLUDES = -I../../src/ -I../../src/fastflow/ -I../../src/fastflow/ff -I../../demo/http_pattern_matching/pattern_matching_lib -I /home/desensi/libs/libpcap-1.3.0/
LIBS = -L /home/desensi/libs/libpcap-1.3.0/ -lpcap -L../../lib/ -L../../demo/http_pattern_matching/pattern_matching_lib/ -lpatternmatching

.PHONY: all clean cleanall

all:
	make -C ../../demo/http_pattern_matching/pattern_matching_lib lib
	make sender
	make receiver
sender: sender.cpp
	$(CXX) $(INCLUDES) $(CXXFLAGS) $? -o $@ $(LIBS) -lpcap -lpthread
receiver: receiver.c
	$(CXX) $(INCLUDES) $(CXXFLAGS) $? -o $@ $(LIBS) -lmcdpi -lpthread
clean:
	-rm -fr *.o *~ $(TARGET)
cleanall:
	make clean
	-rm -fr sender receiver


