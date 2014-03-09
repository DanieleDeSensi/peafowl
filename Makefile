CC                   = gcc
CXX                  = g++ 
LINK_OPT             = 
VERSION              = 
OPTIMIZE_FLAGS       = -O3 -finline-functions
CXXFLAGS             = -Wall -g 
CFLAGS               =
LDFLAGS              = 
INCS                 = -I ./ 
LIBS                 = 
INCLUDES             =
TARGET               =

.PHONY: clean cleanall install uninstall
.SUFFIXES: .cpp .o

all:
	make -C ./src all 
install:
	cp ./lib/libdpi.a /usr/lib/libpeafowldpi.a
	cp ./lib/libmcdpi.a /usr/lib/libpeafowldpimc.a
	cp ./src/api.h /usr/include/peafowldpi.h
	cp ./src/mc_api.h /usr/include/peafowldpimc.h
uninstall:
	rm /usr/lib/libpeafowldpi.a
	rm /usr/lib/libpeafowldpimc.a
	rm /usr/include/peafowldpi.h
	rm /usr/include/peafowldpimc.h
clean: 
	make -C ./src clean
cleanall:
	make -C ./src cleanall
	rm -rf ./lib/lib*

