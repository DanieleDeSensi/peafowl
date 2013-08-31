CC                   = gcc 
CXX                  = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = -O3 -finline-functions
CXXFLAGS             = -Wall -g
CFLAGS               =
LDFLAGS              = 
INCS                 = -I ../src/
LIBS                 = -lpcap -L../lib/ -ldpi -lpthread -lm
INCLUDES             =
TARGET               = demo_identification demo_jpeg

.PHONY: all clean cleanall install uninstall test
.SUFFIXES: .cpp .o

all: $(TARGET)
 

%: %.c 
	$(CC) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
%: %.cpp 
	$(CXX) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) $? -o $@ $(LIBS)
clean: 
	-rm -fr *.o *~ demo_jpeg_dump/*.jpeg $(TARGET)
cleanall:
	make clean
	-rm -fr $(TARGET)

