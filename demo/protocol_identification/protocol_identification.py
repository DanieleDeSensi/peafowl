from scapy.all import *
import pypeafowl as pfwl
import sys

protocolsCount = {}

def pkt_callback(p):
  def pfwl_processing(pkt):
    rawPkt = str(raw(pkt[IP]))
    ts = int(pkt.time)
    # Dissect the packet starting from L3 header
    info = p.dissectFromL3(rawPkt, ts)
    name = info.getL7().getProtocol().getName()
    if name in protocolsCount:
        protocolsCount[name] += 1
    else:
        protocolsCount[name] = 1
  return pfwl_processing

if(len(sys.argv) < 2):
    print "Usage: ./" + sys.argv[0] + " pcapFileName"
    exit(-1)

pcapName = sys.argv[1]
# Creates an handle to the library
p = pfwl.Peafowl()
# Ask scapy to sniff the packets. For each packet, pkt_callback will be called
sniff(offline = pcapName, prn = pkt_callback(p), store = 0)
# Print the detected protocols count
for key, value in protocolsCount.iteritems():
    print key + " " + str(value)


