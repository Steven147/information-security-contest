from scapy.all import *
from BasicPacket import BasicPacketInfo
from BasicFlow import BasicFlow
from FlowGenerator import FlowGenerator
from PcapReader import *

def main():
    ret = pcapReader('aimchat.pcap')
    flowgen = FlowGenerator(True,120000000, 5000000)
    valid = 0
    discard = 0
    for i in range(0,len(ret)):
        if (ret[i] != None):
            flowgen.addPacket(ret[i])
            valid+=1
        else:
            discard+=1

if __name__ == '__main__':
    main()