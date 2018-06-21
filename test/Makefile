.PHONY: all clean cleanall
TARGET=$(patsubst %.cpp, %, $(wildcard *.cpp))
LDLIBS+=-pthread -lpcap

all: $(TARGET)
	
%: %.cpp ../lib/libdpi.a
	$(CXX) $(CXXFLAGS) $(OPTIMIZE_FLAGS) -g -o $@ $< ./googletest/googletest/make/gtest_main.a ../lib/libdpi.a $(INCS) -I./googletest/googletest/include $(LDFLAGS) $(LDLIBS) $(PEAFOWL_COVERAGE_LIBS)
clean: 
	-rm -fr *.o *~
cleanall:
	-rm -fr *.o *~ 
	-rm -fr $(TARGET)
