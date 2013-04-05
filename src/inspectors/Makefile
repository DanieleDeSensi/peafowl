CC                   = gcc 
CXX                  = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = -O3
CXXFLAGS             = -Wall -g 
CFLAGS               =
LDFLAGS              = 
INCS                 = 
LIBS                 = 
INCLUDES             =
TARGET               = dhcp.o dhcpv6.o bgp.o dns.o http_parser_joyent.o http.o smtp.o pop3.o mdns.o ntp.o

.PHONY: all clean cleanall install uninstall
.SUFFIXES: .cpp .o

all: $(TARGET)
 
%.o: %.c 
	$(CC) $(INCS) $(CXXFLAGS) $(OPTIMIZE_FLAGS) -c $? -o $@
clean: 
	-rm -fr *.o *~ 
cleanall: clean
	-rm -fr $(TARGET)
