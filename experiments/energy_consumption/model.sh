#!/bin/bash

rm -fr modelbw.txt
rm -fr modelpw.txt

NCORES=$(cat /proc/cpuinfo | egrep "core id|physical id" | tr -d "\n" | sed s/physical/\\nphysical/g | grep -v ^$ | sort | uniq | wc -l)
LASTRES=0
BASERATE=491550.93882
K=0

for (( c=1; c<=$NCORES-2; c++ ))
do
i=0
for FREQ in $(cpufreq-info | grep 'frequenze disponibili' | sort -u | cut -d ':' -f 2 | tr ',' '\n' | tr -d ' ' | sort | cut -d 'G' -f 1)
#for FREQ in $(cpufreq-info | grep 'available frequency' | sort -u | cut -d ':' -f 2 | tr ',' '\n' | tr -d ' ' | sort | cut -d 'G' -f 1)
do
        ((K=K+1))
	BW=`echo "scale=5;(($c*$FREQ)/(9*1.8))*$BASERATE" | bc`
	((i=i+1))
	PW=$(echo "" | awk -v c=$c -v f=$FREQ -v v=$VOLT -v be=$BASEENERGY 'END {print ((c+2)*f**1.3)}')
	echo $K $c","$FREQ $PW >> modelpw.txt
	echo $c","$FREQ $BW >> model_bw.txt
done

done
