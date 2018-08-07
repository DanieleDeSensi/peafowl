.PHONY: all clean cleanall

all:
	make -i -C ./http_pattern_matching
	make -i -C ./dump_jpeg
	make -i -C ./protocol_identification
	make -i -C ./protocol_identification_mc
	make -i -C ./sip_extraction
clean: 
	make -C ./http_pattern_matching clean
	make -C ./dump_jpeg clean
	make -C ./protocol_identification clean
	make -C ./protocol_identification_mc clean
	make -C ./sip_extraction clean
cleanall:
	make -C ./http_pattern_matching cleanall
	make -C ./dump_jpeg cleanall
	make -C ./protocol_identification cleanall
	make -C ./protocol_identification_mc cleanall
	make -C ./sip_extraction cleanall
