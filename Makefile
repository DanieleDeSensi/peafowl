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

.PHONY: clean cleanall install uninstall test seq par
.SUFFIXES: .cpp .o

all:
	make seq 
seq:
	make -C ./src CONFIGURATIONFLAGS=-DDPI_THREAD_SAFETY_ENABLED=0
	make -C ./src lib
	make -C ./test
	make -C ./test test
	make -C ./demo
par:
	make -C ./src CONFIGURATIONFLAGS=-DDPI_THREAD_SAFETY_ENABLED=1
	make -C ./src lib
	make -C ./test
	make -C ./test test
	make -C ./demo
install:
	cp ./lib/lib* /usr/lib/
uninstall:
	rm /usr/lib/libdpi.a
	rm /usr/lib/libmpdpi.a	
clean: 
	make -C ./src clean
	make -C ./test clean
	make -C ./demo clean
	rm -rf ./lib/lib*
cleanall:
	make -C ./src cleanall
	make -C ./test cleanall
	make -C ./demo cleanall
	rm -rf ./lib/lib*