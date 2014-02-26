CC                   = gcc 
CXX                  = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = -O3 -finline-functions
CXXFLAGS             = -Wall -g
CFLAGS               =
LDFLAGS              = 
INCS                 = -I ../../src/
LIBS                 = -lpcap -L../../lib/ -ldpi -lpthread -lm
INCLUDES             =
TARGET               = protocol_identification

.PHONY: all clean cleanall
.SUFFIXES: .cpp .o

all: $(TARGET)

%: %.c 
	$(CC) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
%: %.cpp 
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
clean: 
	-rm -fr *.o *~ $(TARGET)
cleanall:
	make clean
	-rm -fr $(TARGET)

