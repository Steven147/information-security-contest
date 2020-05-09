from scapy.all import *
from FlowCheck.BasicPacket import BasicPacketInfo
from decimal import Decimal

def pcapReader(url):
    package = []
    packet = sniff(offline=url,count=10000)
    count = 1
    for i in packet:
        timestamp = i.time*1000000 #change to mircosecond
        temp = None
        if IP in i:
            if UDP in i:
                temp = BasicPacketInfo(count,i[IP].src,i[IP].dst,i[UDP].sport,i[UDP].dport,17,len(i[UDP].payload),timestamp)
                hdlen = 8
                temp.setheaderLen(hdlen)
            elif TCP in i:
                temp = BasicPacketInfo(count,i[IP].src,i[IP].dst,i[TCP].sport,i[TCP].dport,6,len(i[TCP].payload),timestamp)
                TCPset(temp,i[TCP])
                hdlen = i.dataofs*4
                temp.setheaderLen(hdlen)
        #elif IPv6 in i:
        #    if UDP in i:
        #        #IPv6 Proto ??
        #        temp = BasicPacketInfo(count,i[IPv6].src,i[IPv6].dst,i[UDP].sport,i[UDP].dport,i[IPv6].proto,len(i[UDP].payload),i[IPv6].time)
        #    elif TCP in i:
        #        temp = BasicPacketInfo(count,i[IPv6].src,i[IPv6].dst,i[TCP].sport,i[TCP].dport,i[IPv6].proto,len(i[TCP].payload),i[IPv6].time)
        #        TCPset(temp,i[TCP])
        if temp:
            package.append(temp)
            count += 1
    return package

def TCPset(packet,tcp):
    seq = format(int(tcp.flags),'08b')
    packet.setflagCWR(bool(int(seq[0])))
    packet.setflagECE(bool(int(seq[1])))
    packet.setflagURG(bool(int(seq[2])))
    packet.setflagACK(bool(int(seq[3])))
    packet.setflagPSH(bool(int(seq[4])))
    packet.setflagRST(bool(int(seq[5])))
    packet.setflagSYN(bool(int(seq[6])))
    packet.setflagFIN(bool(int(seq[7])))
    packet.setTCPWindow(tcp.window)