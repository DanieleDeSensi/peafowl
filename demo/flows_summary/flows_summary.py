# flows_summary.py
#
# Given a .pcap file, prints summary information about the contained flows.
#
# Created on: 05/01/2019
# =========================================================================
# Copyright (c) 2016-2019 Daniele De Sensi (d.desensi.software@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# =========================================================================

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