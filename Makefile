export CC                   = gcc
export CXX                  = g++ 
export OPTIMIZE_FLAGS       = -O3 -finline-functions
export CXXFLAGS             = --std=c++11 -Wall -g -DFF_BOUNDED_BUFFER -DTRACE_FASTFLOW -DNO_DEFAULT_MAPPING #-DBLOCKING_MODE
export INCS                 = -I $(realpath .) -I $(realpath ./src/external/fastflow)
MAMMUT               = $(realpath ./src/external/adaptivefastflow/src/external/Mammut)
ADPFF                = $(realpath ./src/external/adaptivefastflow)
LIBXML               = /usr/include/libxml2/

.PHONY: all reconf noreconf clean cleanall install uninstall
.SUFFIXES: .cpp .o

all: noreconf

reconf: export INCS += -I$(MAMMUT) -I$(ADPFF) -I$(LIBXML)
reconf: export CXXFLAGS += -DENABLE_RECONFIGURATION
reconf: 
	git submodule update --init --recursive
	git submodule foreach git pull -q origin master
	make -C ./src/external/adaptivefastflow
	make -C ./src all
	mv ./lib/libmcdpi.a ./lib/libmcdpireconf.a
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

