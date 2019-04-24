from scapy.all import *
import pypeafowl as pfwl
import sys
import socket


def get_protocols_names(protocols):
    str = ""
    for p in protocols:
        str += p.getName() + ","
    if len(protocols):
        str = str[:-1] # Remove last comma
    return str

def print_header():
    print("#Id\tThreadId\tAddressSrc\tAddressDst\tPortSrc\tPortDst\t"
         "ProtoL2\tProtoL3\tProtoL4\tProtosL7\t"
         "Packets(DirA|DirB)\tBytes(DirA|DirB)\tPacketsL7(DirA|DirB)\tBytesL7(DirA|DirB)\t"
         "TimestampFirst(DirA|DirB)\tTimestampLast(DirA|DirB)\n")

# To process a flow after its termination, you must define a class
# extending pfwl.FlowManager and implement the 'onTermination' function.
# We show in the following an example where we print flow information and
# statistics after its termination.
class FlowManagerPy(pfwl.FlowManager):
    def onTermination(self, f):
        print("{:d}\t{:d}\t{:s}\t{:s}\t{:d}\t{:d}\t"
         "{:s}\t{:s}\t{:s}\t{:s}\t"
         "{:.0f}|{:.0f}\t{:.0f}|{:.0f}\t{:.0f}|{:.0f}\t{:.0f}|{:.0f}\t"
         "{:.0f}|{:.0f}\t{:.0f}|{:.0f}".format(
         f.getId(),
         f.getThreadId(),
         f.getAddressSrc().toString(),
         f.getAddressDst().toString(),
         socket.ntohs(f.getPortSrc()),
         socket.ntohs(f.getPortDst()),
         f.getProtocolL2().getName(),
         f.getProtocolL3().getName(),
         f.getProtocolL4().getName(),
         get_protocols_names(f.getProtocolsL7()),
         f.getStatistic(pfwl.Statistic.PACKETS, pfwl.Direction.OUTBOUND), f.getStatistic(pfwl.Statistic.PACKETS, pfwl.Direction.INBOUND),
         f.getStatistic(pfwl.Statistic.BYTES, pfwl.Direction.OUTBOUND), f.getStatistic(pfwl.Statistic.BYTES, pfwl.Direction.INBOUND),
         f.getStatistic(pfwl.Statistic.L7_PACKETS, pfwl.Direction.OUTBOUND), f.getStatistic(pfwl.Statistic.L7_PACKETS, pfwl.Direction.INBOUND),
         f.getStatistic(pfwl.Statistic.L7_BYTES, pfwl.Direction.OUTBOUND), f.getStatistic(pfwl.Statistic.L7_BYTES, pfwl.Direction.INBOUND),
         f.getStatistic(pfwl.Statistic.TIMESTAMP_FIRST, pfwl.Direction.OUTBOUND), f.getStatistic(pfwl.Statistic.TIMESTAMP_FIRST, pfwl.Direction.INBOUND),
         f.getStatistic(pfwl.Statistic.TIMESTAMP_LAST, pfwl.Direction.OUTBOUND), f.getStatistic(pfwl.Statistic.TIMESTAMP_LAST, pfwl.Direction.INBOUND)
         ))


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

def main():
    if(len(sys.argv) < 2):
        print "Usage: ./" + sys.argv[0] + " pcapFileName"
        exit(-1)

    pcapName = sys.argv[1]
    # Creates an handle to the library
    p = pfwl.Peafowl()
    # Adds the function to be called every time a flow terminates
    fm = FlowManagerPy()
    p.setFlowManager(fm)
    print_header()
    # Ask scapy to sniff the packets. For each packet, pkt_callback will be called
    sniff(offline = pcapName, prn = pkt_callback(p), store = 0)
    # Print the detected protocols count
    del p
    for key, value in protocolsCount.iteritems():
        print key + " " + str(value)

if __name__ == "__main__":
    main()