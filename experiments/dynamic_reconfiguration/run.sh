#!/bin/bash
STRATEGIES=('cores_conservative' 'power_conservative' 'gov_ondemand' 'gov_conservative' 'gov_performance')

rm -rf reconfigurations_count.txt

strategy_id=0
for strategy in "${STRATEGIES[@]}"
do
	./dynamic_reconfiguration signatures.example ../../../test_pcap_ok.pcap 1 $strategy_id
	RECONFIGURATIONS=$(cat stats.txt | cut -f 2 | uniq | wc -l)
	echo ${strategy} $RECONFIGURATIONS >> reconfigurations_count.txt
	mv stats.txt stats_${strategy}.txt
	((strategy_id++))	
done


gnuplot plot.gnuplot