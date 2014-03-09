#GNU makefile
CXX = g++
CXXFLAGS = -O -g -Wall -W -ansi -Xlinker -zmuldefs
INCLUDES = -I../../src/ -I../../src/fastflow/ -I../http_pattern_matching/pattern_matching_lib
LIBS = -lpcap -L../../lib/ -L../http_pattern_matching/pattern_matching_lib/ -lpatternmatching 


.PHONY: all clean cleanall

all: 
	make -C ../http_pattern_matching/pattern_matching_lib lib
	make dynamic_reconfiguration
dynamic_reconfiguration: dynamic_reconfiguration.c
	$(CXX) $(INCLUDES) $(CXXFLAGS) $? -o $@ $(LIBS) -lmcdpi -lpthread
clean:
	-rm -fr *.o *~ $(TARGET)
cleanall:
	make clean
	-rm -fr dynamic_reconfiguration


