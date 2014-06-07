#!/bin/sh

if [ -f fr_socket.txt ]
then
	rm fr_socket.txt
fi

if [ -f fr_cores.txt ]
then
	rm fr_cores.txt
fi

if [ -f fr_dram.txt ]
then
	rm fr_dram.txt
fi

ITERATIONSPCAP=10
NCORES=$(cat /proc/cpuinfo | egrep "core id|physical id" | tr -d "\n" | sed s/physical/\\nphysical/g | grep -v ^$ | sort | uniq | wc -l)

for (( c=1; c<=$NCORES-2; c++ ))
do

for FREQ in $(cpufreq-info | grep 'frequenze disponibili' | sort -u | cut -d ':' -f 2 | tr ',' '\n' | tr -d ' ' | sort)
#for FREQ in $(cpufreq-info | grep 'available frequency' | sort -u | cut -d ':' -f 2 | tr ',' '\n' | tr -d ' ' | sort)
do

#Set the frequency of cpus
for (( i=0; i<$NCORES; i++ ))
do
        cpufreq-set -g userspace -c $i
        cpufreq-set -f $FREQ -c $i
done
	OUT=$(./energy_consumption signatures.example ../../../test_pcap_ok.pcap $ITERATIONSPCAP $c)
	BANDWIDTH=$(echo "$OUT" | grep '++++Bandwidth' | cut -d ':' -f 2 | tr -d ' ')
	SOCKETW=$(echo "$OUT" | grep '++++Socket' | cut -d ':' -f 2 | tr -d ' ')
        CORESW=$(echo "$OUT" | grep '++++Cores' | cut -d ':' -f 2 | tr -d ' ')
        DRAMW=$(echo "$OUT" | grep '++++DRAM' | cut -d ':' -f 2 | tr -d ' ')

	echo $c,$FREQ $BANDWIDTH $SOCKETW >> fr_socket.txt
        echo $c,$FREQ $BANDWIDTH $CORESW >> fr_cores.txt
        echo $c,$FREQ $BANDWIDTH $DRAMW >> fr_dram.txt
done

done
