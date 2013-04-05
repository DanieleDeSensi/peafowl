CC                   = gcc
CXX 		         = g++ 
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

.PHONY: clean cleanall install uninstall test
.SUFFIXES: .cpp .o

all: 
	make -C ./src
	make -C ./src lib
	make -C ./test
	make -C ./test test
	make -C ./demo
clean: 
	make -C ./src clean
	make -C ./test clean
	make -C ./demo clean
cleanall:
	make -C ./src cleanall
	make -C ./test cleanall
	make -C ./demo cleanall
