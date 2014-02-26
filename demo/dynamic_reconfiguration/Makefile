CC                   = gcc 
CXX 		     = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       =  -O6 -finline-functions
CXXFLAGS             = -Wall -g -Xlinker -zmuldefs
CFLAGS               =
LDFLAGS              = 
INCS                 = -I ../../src/
LIBS                 = -lpcap -L../../lib -lmcdpi -lpthread 
INCLUDES             =
TARGET               = dynamic_reconfiguration

.PHONY: all clean cleanall
.SUFFIXES: .cpp .o

all: $(TARGET) 

%: %.cpp 
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
%: %.c 
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
clean: 
	-rm -fr *.o *~ $(TARGET)
cleanall:
	make clean
	-rm -fr $(TARGET)
