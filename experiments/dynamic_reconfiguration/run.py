import subprocess
import os

pcap="../../../pcaps/test_pcap_ok.pcap"
sig="signatures.1781"
host="pianosa"
modes=['nonblocking', 'blocking']
strategiesnonblocking={1 : "reconf", 2 : "ondemand", 3 : "conservative", 4 : "performance"}
strategiesblocking={2 : "ondemand", 3 : "conservative", 4 : "performance", 5: "powersave"}
strategies={}
outlog = open("out.log", 'w')
errlog = open("err.log", 'w')

def set_governor(strategyname):
    subprocess.Popen("cpufreq-set -c 0 -r -g " + strategyname, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    subprocess.Popen("cpufreq-set -c 8 -r -g " + strategyname, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    
for m in modes:
    if m == 'nonblocking':
        strategies = strategiesnonblocking
    else:
        strategies = strategiesblocking

    for s in strategies:
        outlog.write("==== Executing mode " + m + ", strategy " + str(s) + "\n")
        errlog.write("==== Executing mode " + m + ", strategy " + str(s) + "\n")
        strategy = s
        if m == 'blocking':
            set_governor(strategies[s])
            strategy = 0

        p = subprocess.Popen("./dynamic_reconfiguration_" + m + " " + sig + " " + " " + pcap + " 1 " + str(strategy), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        out, err = p.communicate()
        outlog.write(out)
        errlog.write(err)
        
        os.rename("stats.txt",  host + "_" + m + "_" + str(strategies[s]) + "_" + sig + ".csv")

outlog.close()
errlog.close()

