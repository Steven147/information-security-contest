from scapy.all import *

class BasicPacketInfo():
    def __init__(self,no,src,dst,sport,dport,ptc,payload,timestamp):
        super()
        self.no = no
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.ptc = ptc
        self.payloadBytes = payload
        self.timeStamp = timestamp
        #----- Initialize -------#
        self.flowID = None
        self.flagFIN = False
        self.flagPSH = False
        self.flagURG = False
        self.flagECE = False
        self.flagSYN = False
        self.flagACK = False
        self.flagCWR = False
        self.flagRST = False
        self.TCPWindow = 0
        self.hdlen = 0
        self.payloadPacket = 0
        self.generateflowID()

    def generateflowID(self):
        forward = True
        src = self.src.split('.')
        dst = self.dst.split('.')
        for i in range(0,len(src)):
            if (int(src[i]) != int(dst[i])):
                if (int(src[i]) > int(dst[i])):
                    forward = False
                i = len(src)
        if forward:
            self.flowID = self.src + '-' + str(self.sport) + '-' + self.dst + '-' + str(self.dport) + '-' + str(self.ptc)
        else:
            self.flowID = self.dst + '-' +str(self.dport) + '-' + self.src + '-' + str(self.sport) + '-' + str(self.ptc)
    def fwdFlowID(self):
        self.flowID = self.src + '-' + str(self.sport) + '-' + self.dst + '-' + str(self.dport) + '-' + str(self.ptc)
        return self.flowID
        #return (self.src + '-' + str(self.sport) + '-' + self.dst + '-' + str(self.dport) + '-' + str(self.ptc))
    def bwdFlowID(self):
        self.flowID = self.dst + '-' +str(self.dport) + '-' + self.src + '-' + str(self.sport) + '-' + str(self.ptc)
        return self.flowID
        #return (self.dst + '-' +str(self.dport) + '-' + self.src + '-' + str(self.sport) + '-' + str(self.ptc))
        
    def setflagFIN(self,value):
        self.flagFIN = value
    def setflagPSH(self,value):
        self.flagPSH = value
    def setflagURG(self,value):
        self.flagURG = value
    def setflagECE(self,value):
        self.flagECE = value
    def setflagSYN(self,value):
        self.flagSYN = value
    def setflagACK(self,value):
        self.flagACK = value
    def setflagCWR(self,value):
        self.flagCWR = value
    def setflagRST(self,value):
        self.flagRST = value

    def setTCPWindow(self,value):
        self.TCPWindow = value
    def setheaderLen(self,value):
        self.hdlen = value
    def setpayloadPacket(self,value):
        self.payloadPacket = value
