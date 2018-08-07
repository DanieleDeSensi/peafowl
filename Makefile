export CC                   = gcc
export CXX                  = g++
export OPTIMIZE_FLAGS       = -finline-functions -O3 -fPIC
export CCFLAGS             = $(PEAFOWL_COVERAGE_FLAGS) -Wall -DFF_BOUNDED_BUFFER -DNO_DEFAULT_MAPPING #-DDPI_DEBUG_TCP_REORDERING #-DBLOCKING_MODE
export CXXFLAGS             = $(CCFLAGS) --std=c++11
export INCS                 = -I $(realpath .) 
MAMMUT               = $(realpath ./src/external/nornir/src/external/Mammut)
ADPFF                = $(realpath ./src/external/nornir)
LIBXML               = /usr/include/libxml2/

.PHONY: all reconf noreconf clean cleanall install uninstall cppcheck develcheck gcov test testquick demo
.SUFFIXES: .cpp .o

all: noreconf

demo:
	$(MAKE) -C demo
cppcheck:
	cppcheck --xml --xml-version=2 --enable=warning,performance,style --error-exitcode=1 --suppressions-list=./test/cppcheck/suppressions-list.txt -UNN_EXPORT . -isrc/external -idemo/http_pattern_matching/pattern_matching_lib -itest 2> cppcheck-report.xml || (cat cppcheck-report.xml; exit 2) 
gcov:
	./test/gcov/gcov.sh
test:
	$(MAKE) cleanall
	$(MAKE) "PEAFOWL_COVERAGE_FLAGS=-fprofile-arcs -ftest-coverage --coverage"
	$(MAKE) testquick
testquick:
	cd test && ./installdep.sh 
	cd ..
	$(MAKE) "PEAFOWL_COVERAGE_LIBS=-fprofile-arcs -ftest-coverage -lgcov" -C test && cd test && ./runtests.sh
	cd ..
develcheck:
	$(MAKE) cppcheck && $(MAKE) test && $(MAKE) gcov && $(MAKE) cleanall && $(MAKE) && $(MAKE) demo
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
	make -C ./demo cleanall
	rm -rf ./lib/lib*

