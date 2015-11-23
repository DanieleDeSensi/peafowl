#!/bin/bash

SIG=signatures.1781
HOST='pianosa'
BLOCKING=('nonblocking' 'blocking')
STRATEGIES=('corescons' 'reconf' 'ondemand' 'conservative' 'performance')

for b in "${BLOCKING[@]}"
do
    rm -rf ${HOST}_${BLOCKING}_reconfigurations_count.txt
    rm -rf ${HOST}_${BLOCKING}_workers_per_second.txt
    rm -rf ${HOST}_${BLOCKING}_watts_per_second.txt
    rm -rf ${HOST}_${BLOCKING}_avg_rho.txt
    strategy_id=1 # We avoid the coresconf strategy
    for strategy in "${STRATEGIES[@]}"
    do
	./dynamic_reconfiguration ${SIG} ../../../test_pcap_ok.pcap 1 $strategy_id
	RECONFIGURATIONS=$(cat stats.txt | tail -n +13 | cut -f 2 | cut -d ',' -f 1 | uniq -c | wc -l)
	echo ${strategy} $RECONFIGURATIONS >> ${HOST}_${BLOCKING}_reconfigurations_count.txt
	WORKERS_PER_SECOND=$(cat stats.txt  | tail -n +13 | cut -f 2 | cut -d ',' -f 1 | uniq -c | awk '{ print $1 * $2 }' | awk '{s+=$1} END {print s/3715}')
	echo ${strategy} $WORKERS_PER_SECOND >> ${HOST}_${BLOCKING}_workers_per_second.txt
	WATTS_PER_SECOND=$(cat stats.txt  | tail -n +13 |  cut -f 5 | awk '{s+=$1} END {print s/3715}')
	echo ${strategy} $WATTS_PER_SECOND >> ${HOST}_${BLOCKING}_watts_per_second.txt
        RHO=$(cat stats.txt  | tail -n +13 |  cut -f 10 | awk '{s+=$1} END {print s/3715}')
        echo ${strategy} $RHO >> ${HOST}_${BLOCKING}_avg_rho.txt
	mv stats.txt ${HOST}_${BLOCKING}_${strategy}_${SIG}.txt
	((strategy_id++))	
    done
done
