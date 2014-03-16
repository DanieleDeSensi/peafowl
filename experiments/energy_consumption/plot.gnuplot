set terminal png size 1600,600
set output "frequencies.png"
set style data linespoints 
set title "Energy statistics (Workers + Emitter + Collector)"
set xlabel "Workers|Cpufreq"
set ylabel "Pkts/Sec"
set y2label "Watts"
set xtics rotate 45
set ytics nomirror
set y2tics nomirror
set key left top
plot "fr_socket.txt" using 2:xticlabels(1) title "Bandwidth" axes x1y1 pt 5, "fr_socket.txt" using 3:xticlabels(1) title "Sockets Watts" axes x1y2 pt 7, "fr_dram.txt" using 3:xticlabels(1) title "DRAM Watts" axes x1y2 pt 9

set terminal png size 1600,600
set output "bw_x_watt.png"
set style data linespoints
set title "Energy statistics (Workers + Emitter + Collector)"
set xlabel "Workers|Cpufreq"
set ylabel "Bandwidth Per Watt"
set xtics rotate 45
set key left top
plot "fr_socket.txt" using ($2/$3):xticlabels(1) title "Bandwidth x Watt" pt 5
