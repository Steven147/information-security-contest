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
    def setprotocol(self,value):
    	self.ptc = value

    def setTCPWindow(self,value):
        self.TCPWindow = value
    def setheaderLen(self,value):
        self.hdlen = value

    def check(self):
        return ("No:"+ str(self.no) + '\n' +
                "Source: "+ str(self.src) + '\n' +
                "Destination: "+ str(self.dst) + '\n' +
                "Source Port: "+ str(self.sport) + '\n' +
                "Destination Port: "+ str(self.dport) + '\n' +
                "Protocol: "+ str(self.ptc) + '\n' +
                "Payload Bytes: "+ str(self.payloadBytes) + '\n' +
                "Timestemp(in microsecond): "+ str(self.timeStamp) + '\n' +
                "Flag FIN:" + str(self.flagFIN) + '\n' +
                "Flag PSH:" + str(self.flagPSH)+ '\n' +
                "Flag URG:" + str(self.flagURG) + '\n' +
                "Flag ECE:" + str(self.flagECE) + '\n' +
                "Flag SYN:" + str(self.flagSYN) + '\n' +
                "Flag ACK:" + str(self.flagACK) + '\n' +
                "Flag CWR:" + str(self.flagCWR) + '\n' +
                "Flag RST:" + str(self.flagRST) + '\n' +
                "TCP Window:" + str(self.TCPWindow) + '\n' +
                "Header Length:" + str(self.hdlen) + '\n'
                )