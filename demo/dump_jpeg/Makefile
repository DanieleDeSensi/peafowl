CC                   = gcc 
CXX                  = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = -O3 -finline-functions
CXXFLAGS             = --std=c++11 -Wall -g
CFLAGS               =
LDFLAGS              = 
INCS                 = -I ../../src/
LIBS                 = -lpcap -L../../lib/ -ldpi -lpthread
INCLUDES             =
TARGET               = dump_jpeg

.PHONY: all clean cleanall
.SUFFIXES: .cpp .o

all: $(TARGET)

%: %.c 
	$(CC) $(CXXFLAGS) $(INCS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
%: %.cpp 
	$(CXX) $(CXXFLAGS) $(INCS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
clean: 
	-rm -fr *.o *~ dumps/*.jpeg $(TARGET)
cleanall:
	make clean
	-rm -fr $(TARGET)

