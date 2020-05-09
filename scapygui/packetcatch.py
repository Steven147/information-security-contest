from PyQt5.QtCore import *
from FlowMeter.BasicPacket import BasicPacketInfo
from scapy.all import *
#import ptvsd

class Signal(QObject):
    doneSignal = pyqtSignal(scapy.layers.l2.Ether)
    startSignal = pyqtSignal(bool)

class packetsniff(QRunnable):
    def __init__(self):
        super(packetsniff,self).__init__()
        self.signals = Signal()
        self.status = True

    def run(self):
        #ptvsd.debug_this_thread()
        #initial value
        count = 0
        while self.status:
            packet = sniff(count=1)
            packet = packet[0]
            if IP in packet:
                if UDP in packet:
                    self.signals.doneSignal.emit(packet)
                elif TCP in packet:
                    self.signals.doneSignal.emit(packet)
                elif ICMP in packet:
                    self.signals.doneSignal.emit(packet)
    def stop(self):
        self.status = False