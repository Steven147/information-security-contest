from PyQt5.QtCore import *
from BasicPacket import BasicPacketInfo
from scapy.all import *
import ptvsd

class Signal(QObject):
    doneSignal = pyqtSignal(BasicPacketInfo)
    startSignal = pyqtSignal(bool)

class packetsniff(QRunnable):
    def __init__(self):
        super(packetsniff,self).__init__()
        self.signals = Signal()
        self.status = True

    def run(self):
        ptvsd.debug_this_thread()
        #initial value
        count = 0
        while self.status:
            packet = sniff(count=1)
            packet = packet[0]
            temp = None
            timestamp = packet.time
            if IP in packet:
                if UDP in packet:
                    temp = BasicPacketInfo(count,packet[IP].src,packet[IP].dst,packet[UDP].sport,packet[UDP].dport,packet[IP].proto,len(packet[UDP].payload),timestamp)
                    temp.setheaderLen(packet.ihl*4+8)
                elif TCP in packet:
                    temp = BasicPacketInfo(count,packet[IP].src,packet[IP].dst,packet[TCP].sport,packet[TCP].dport,packet[IP].proto,len(packet[TCP].payload),timestamp)
                    TCPset(temp,packet[TCP])
                    temp.setheaderLen((packet.ihl+packet.dataofs)*4)
            if temp:
                self.signals.doneSignal.emit(temp)
                count +=1
    def stop(self):
        self.status = False

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