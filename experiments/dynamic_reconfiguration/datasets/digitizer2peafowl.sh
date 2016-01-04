#/bin/bash
# $1: The .csv output (space separated) obtained by the digitizer.
#     The digitizer output should have 2 fields, the first one is the timestamp and can be ignored,
#     the second one is the rate (in packets per seconds).
# Prints the same csv in Peafowl format. 
# ATTENTIONS: We assume we have one sample every 5 minutes
cat $1 | cut -f 2 -d ' ' | awk '{printf "%.0f 300\n", $1}'
