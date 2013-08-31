#GNU makefile

.PHONY: all clean cleanall

all: 
	make -C ./pattern_matching_lib
	mv http_pm_seq .
	mv http_pm_mc .
	mv http_pm_mc_pfring .
clean:
	make -C ./pattern_matching_lib clean
cleanall:
	make -C ./pattern_matching_lib realclean

