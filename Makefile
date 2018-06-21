export CC                   = gcc
export CXX                  = g++
export OPTIMIZE_FLAGS       = -finline-functions -O3 -fPIC
export CXXFLAGS             = --std=c++11 -Wall -DFF_BOUNDED_BUFFER -DNO_DEFAULT_MAPPING #-DDPI_DEBUG_TCP_REORDERING #-DBLOCKING_MODE
export INCS                 = -I $(realpath .) 
MAMMUT               = $(realpath ./src/external/nornir/src/external/Mammut)
ADPFF                = $(realpath ./src/external/nornir)
LIBXML               = /usr/include/libxml2/

.PHONY: all reconf noreconf clean cleanall install uninstall
.SUFFIXES: .cpp .o

all: noreconf

reconf: export INCS += -I$(MAMMUT) -I$(ADPFF) -I$(LIBXML) -I$(ADPFF)/src/external/fastflow # For reconf I use the nornir fastflow
reconf: export CXXFLAGS += -DENABLE_RECONFIGURATION 
reconf: 
	python submodules_init.py
	git submodule foreach git pull -q origin master
	make -C ./src/external/nornir
	make -C ./src all
	mv ./lib/libmcdpi.a ./lib/libmcdpireconf.a
noreconf: export INCS += -I $(realpath ./src/external/fastflow) # For noreconf I use the normal fastflow
noreconf:
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

