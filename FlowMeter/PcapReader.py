from scapy.all import *
from BasicPacket import BasicPacketInfo
from decimal import Decimal

class EDecimal(Decimal):
    """Extended Decimal
    This implements arithmetic and comparison with float for
    backward compatibility
    """

    def __add__(self, other, **kwargs):
        return EDecimal(Decimal.__add__(self, Decimal(other), **kwargs))

    def __radd__(self, other, **kwargs):
        return EDecimal(Decimal.__add__(self, Decimal(other), **kwargs))

    def __sub__(self, other, **kwargs):
        return EDecimal(Decimal.__sub__(self, Decimal(other), **kwargs))

    def __rsub__(self, other, **kwargs):
        return EDecimal(Decimal.__rsub__(self, Decimal(other), **kwargs))

    def __mul__(self, other, **kwargs):
        return EDecimal(Decimal.__mul__(self, Decimal(other), **kwargs))

    def __rmul__(self, other, **kwargs):
        return EDecimal(Decimal.__mul__(self, Decimal(other), **kwargs))

    def __truediv__(self, other, **kwargs):
        return EDecimal(Decimal.__truediv__(self, Decimal(other), **kwargs))

    def __floordiv__(self, other, **kwargs):
        return EDecimal(Decimal.__floordiv__(self, Decimal(other), **kwargs))

    def __div__(self, other, **kwargs):
        return EDecimal(Decimal.__div__(self, Decimal(other), **kwargs))

    def __rdiv__(self, other, **kwargs):
        return EDecimal(Decimal.__rdiv__(self, Decimal(other), **kwargs))

    def __mod__(self, other, **kwargs):
        return EDecimal(Decimal.__mod__(self, Decimal(other), **kwargs))

    def __rmod__(self, other, **kwargs):
        return EDecimal(Decimal.__rmod__(self, Decimal(other), **kwargs))

    def __divmod__(self, other, **kwargs):
        return EDecimal(Decimal.__divmod__(self, Decimal(other), **kwargs))

    def __rdivmod__(self, other, **kwargs):
        return EDecimal(Decimal.__rdivmod__(self, Decimal(other), **kwargs))

    def __pow__(self, other, **kwargs):
        return EDecimal(Decimal.__pow__(self, Decimal(other), **kwargs))

    def __rpow__(self, other, **kwargs):
        return EDecimal(Decimal.__rpow__(self, Decimal(other), **kwargs))

    def __eq__(self, other, **kwargs):
        return super(EDecimal, self).__eq__(other) or float(self) == other

def pcapReader(url):
    package = []
    packet = sniff(offline=url,count=10000)
    count = 1
    for i in packet:
        timestamp = i.time
        temp = None
        if IP in i:
            if UDP in i:
                temp = BasicPacketInfo(count,i[IP].src,i[IP].dst,i[UDP].sport,i[UDP].dport,i[IP].proto,len(i[UDP].payload),timestamp)
                temp.setheaderLen(i.ihl)
            elif TCP in i:
                temp = BasicPacketInfo(count,i[IP].src,i[IP].dst,i[TCP].sport,i[TCP].dport,i[IP].proto,len(i[TCP].payload),timestamp)
                TCPset(temp,i[TCP])
                temp.setheaderLen(i.ihl)
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