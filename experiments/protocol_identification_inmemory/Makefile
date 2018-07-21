CC                   = gcc 
CXX                  = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = --std=c++11 -O3 -finline-functions
CXXFLAGS             = -Wall -g
CFLAGS               =
LDFLAGS              = 
INCS                 = -I ../../src/ -I../../src/external/fastflow 
LIBS                 = -lpcap -L../../lib/ -lmcdpi -lpthread 
INCLUDES             =
TARGET               = protocol_identification

.PHONY: all clean cleanall
.SUFFIXES: .cpp .o

all: $(TARGET)

%: %.c 
	$(CC) $(CXXFLAGS) $(INCS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
%: %.cpp 
	$(CXX) $(CXXFLAGS) $(INCS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
clean: 
	-rm -fr *.o *~ $(TARGET)
cleanall:
	make clean
	-rm -fr $(TARGET)

