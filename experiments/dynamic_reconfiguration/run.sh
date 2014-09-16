#!/bin/bash
STRATEGIES=('cores_conservative' 'power_conservative' 'gov_ondemand' 'gov_conservative' 'gov_performance')
rm -rf reconfigurations_count.txt
rm -rf workers_per_second.txt
rm -rf watts_per_second.txt

strategy_id=0
for strategy in "${STRATEGIES[@]}"
do
	./dynamic_reconfiguration signatures.example ../../../test_pcap_ok.pcap 1 $strategy_id
	RECONFIGURATIONS=$(cat stats.txt | tail -n +13 | cut -f 2 | cut -d ',' -f 1 | uniq -c | wc -l)
	echo ${strategy} $RECONFIGURATIONS >> reconfigurations_count.txt
	WORKERS_PER_SECOND=$(cat stats.txt  | tail -n +13 | cut -f 2 | cut -d ',' -f 1 | uniq -c | awk '{ print $1 * $2 }' | awk '{s+=$1} END {print s/3715}')
	echo ${strategy} $WORKERS_PER_SECOND >> workers_per_second.txt
	WATTS_PER_SECOND=$(cat stats.txt  | tail -n +13 |  cut -f 5 | awk '{s+=$1} END {print s/3715}')
	echo ${strategy} $WATTS_PER_SECOND >> watts_per_second.txt
        RHO=$(cat stats.txt  | tail -n +13 |  cut -f 10 | awk '{s+=$1} END {print s/3715}')
        echo ${strategy} $RHO >> avg_rho.txt
	mv stats.txt stats_${strategy}.txt
	((strategy_id++))	
done
