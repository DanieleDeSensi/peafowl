export CC                   = /usr/local/gnu/packages/gcc-4.8.1/bin/gcc
export CXX                  = /usr/local/gnu/packages/gcc-4.8.1/bin/g++
export OPTIMIZE_FLAGS       = -finline-functions -O3
export CXXFLAGS             = --std=c++11 -Wall -g -DFF_BOUNDED_BUFFER -DTRACE_FASTFLOW -DNO_DEFAULT_MAPPING #-DBLOCKING_MODE
export INCS                 = -I $(realpath .) 
MAMMUT               = $(realpath ./src/external/adaptivefastflow/src/external/Mammut)
ADPFF                = $(realpath ./src/external/adaptivefastflow)
LIBXML               = /usr/include/libxml2/

.PHONY: all reconf noreconf clean cleanall install uninstall
.SUFFIXES: .cpp .o

all: noreconf

reconf: export INCS += -I$(MAMMUT) -I$(ADPFF) -I$(LIBXML) -I$(ADPFF)/src/external/fastflow # For reconf I use the adpff fastflow
reconf: export CXXFLAGS += -DENABLE_RECONFIGURATION -DFF_TASK_CALLBACK
reconf: 
	python submodules_init.py
	git submodule foreach git pull -q origin master
	make -C ./src/external/adaptivefastflow
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

