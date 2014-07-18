#!/bin/bash
STRATEGIES=('cores_conservative' 'power_conservative' 'gov_ondemand' 'gov_conservative' 'gov_performance')

strategy_id=0
for strategy in "${STRATEGIES[@]}"
do
	./dynamic_reconfiguration signatures.example ../../../test_pcap_ok.pcap 1 $strategy_id
	mv stats.txt stats_${strategy}.txt
	((strategy_id++))	
done


gnuplot plot.gnuplot