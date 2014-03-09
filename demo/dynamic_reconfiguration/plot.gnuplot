set terminal png
set output "sockets.png"
set style data linespoints
set title "Sockets Watts x Workers"
set xlabel "Workers"
set ylabel "Socket Watts"
plot "socket.txt" using 1:2 title "Socket #1", "socket.txt" using 1:3 title "Socket #2", "socket.txt" using 1:($2+$3) title "Sum of two sockets"

set terminal png
set output "cores.png"
set style data linespoints
set title "Cores Watts x Workers"
set xlabel "Workers"
set ylabel "Cores Watts"
plot "cores.txt" using 1:2 title "Cores on Socket #1", "cores.txt" using 1:3 title "Cores on Socket #2", "cores.txt" using 1:($2+$3) title "Sum of cores of two sockets"

set terminal png
set output "dram.png"
set style data linespoints
set title "DRAM Watts x Workers"
set xlabel "Workers"
set ylabel "DRAM Watts"
plot "dram.txt" using 1:2 title "DRAM of Socket #1", "dram.txt" using 1:3 title "DRAM of Socket #2", "dram.txt" using 1:($2+$3) title "Sum of DRAM of two sockets"

set terminal png
set output "total.png"
set style data linespoints
set title "Watts x Workers"
set xlabel "Workers"
set ylabel "Watts"
plot "socket.txt" using 1:($2+$3) title "Sockets", "cores.txt" using 1:($2+$3) title "Cores", "dram.txt" using 1:($2+$3) title "DRAM"