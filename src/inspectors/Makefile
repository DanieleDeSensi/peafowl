TARGET               = dhcp.o dhcpv6.o bgp.o dns.o http_parser_joyent.o http.o sip.o smtp.o pop3.o mdns.o rtp.o ntp.o skype.o ssl.o

.PHONY: all clean cleanall install uninstall
.SUFFIXES: .cpp .o

all: $(TARGET)
 
%.o: %.c 
	$(CC) $(INCS) $(CCFLAGS) $(OPTIMIZE_FLAGS) -c $? -o $@
clean: 
	-rm -fr *.o *~ 
cleanall: clean
	-rm -fr $(TARGET)
