#!/bin/sh
cat out.txt | grep 'of cores:' | cut -d ':' -f 2 | awk '{printf "%d\t%s\n", NR, $0}' | tr '|' ' ' > cores.txt
cat out.txt | grep 'DRAM' | cut -d ':' -f 2 | awk '{printf "%d\t%s\n", NR, $0}' | tr '|' ' ' > dram.txt
cat out.txt | grep 'entire socket' | cut -d ':' -f 2 | awk '{printf "%d\t%s\n", NR, $0}' | tr '|' ' ' > socket.txt
