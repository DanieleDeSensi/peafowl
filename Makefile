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
	make seq 
	make par
seq:
	make clean
	make -C ./src CONFIGURATIONFLAGS=-DDPI_THREAD_SAFETY_ENABLED=0 seq
	make -C ./src seqlib
par:
	make clean
	make -C ./src CONFIGURATIONFLAGS=-DDPI_THREAD_SAFETY_ENABLED=1 par
	make -C ./src parlib
install:
	cp ./lib/lib* /usr/lib/
uninstall:
	rm /usr/lib/libdpi.a
	rm /usr/lib/libmcdpi.a	
clean: 
	make -C ./src clean
	make -C ./demo clean
cleanall:
	make -C ./src cleanall
	make -C ./demo cleanall
	rm -rf ./lib/lib*

