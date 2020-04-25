from BasicPacket import BasicPacketInfo
import time
import numpy as np

class BasicFlow:
    def __init__(self,status,arg):
        self.forward = []
        self.backward = []
        self.forwardBytes = 0
        self.backwardBytes = 0
        self.fHeaderBytes = 0
        self.bHeaderBytes = 0
        self.isBidirectional = False
        #FIN SYN RST PSH ACK URG CWR ECE
        self.flagCounts = [0,0,0,0,0,0,0,0]
        self.fPSH_cnt = 0
        self.bPSH_cnt = 0
        self.fURG_cnt = 0
        self.bURG_cnt = 0
        self.Act_data_pkt_forward = 0
        self.min_seg_size_forward = 0
        self.Init_Win_bytes_forward = 0
        self.Init_Win_bytes_backward = 0
        self.src = None
        self.dst = None
        self.sport = None
        self.dport = None
        self.proto = None
        self.flowStartTime = 0
        self.startActiveTime = 0
        self.endActiveTime = 0
        self.flowID = None
        self.flowLastSeen = None
        self.forwardLastSeen = None
        self.backwardLastSeen = None
        self.stat = {"fwdPktStats":[],"bwdPktStats":[],"flowIAT":[],"forwardIAT":[],
                     "backwardIAT":[],"flowLengthStats":[],"flowActive":[],"flowIdle":[]}
        # -----------------------------------------
        self.sfLastPacketTS = -1
        self.sfCount = 0
        self.sfAcHelper = -1
        # ------------------------------------------
        self.fbulkDuration = 0
        self.fbulkPacketCount = 0
        self.fbulkSizeTotal = 0
        self.fbulkStateCount = 0
        self.fbulkPacketCountHelper = 0
        self.fbulkStartHelper = 0
        self.fbulkSizeHelper = 0
        self.flastBulkTS = 0
        self.bbulkDuration = 0
        self.bbulkPacketCount = 0
        self.bbulkSizeTotal = 0
        self.bbulkStateCount = 0
        self.bbulkPacketCountHelper = 0
        self.bbulkStartHelper = 0
        self.bbulkSizeHelper = 0
        self.blastBulkTS = 0
        if status == 1:
            self.isBidirectional = arg[0]
            self.firstPacket(arg[1])
            self.src = arg[2]
            self.dst = arg[3]
            self.sport = arg[4]
            self.dport = arg[5]
        elif status == 2:
            self.isBidirectional = arg[0]
            self.firstPacket(arg[1])
        elif status == 3:
            self.isBidirectional = True
            self.firstPacket(arg[0])

    def packetCount(self):
        if self.isBidirectional:
            return len(self.forward) + len(self.backward)
        else: len(self.forward)

    def firstPacket(self,packet):
        #packet class : BasicPacketInfo
        self.updateFlowBulk(packet)
        self.detectUpdateSubflows(packet)
        self.checkFlags(packet)

        self.flowStartTime = packet.timeStamp
        self.flowLastSeen = packet.timeStamp
        self.startActiveTime = packet.timeStamp
        self.endActiveTime = packet.timeStamp
        self.stat['flowLengthStats'].append(packet.payloadBytes)

        if self.src == None:
            self.src = packet.src
            self.sport = packet.sport
        if self.dst == None:
            self.dst = packet.dst
            self.dport = packet.dport
        #Forward
        if self.src == packet.src:
            self.min_seg_size_forward = packet.hdlen
            self.Init_Win_bytes_forward = packet.TCPWindow
            self.stat["flowLengthStats"].append(packet.payloadBytes)
            self.stat["fwdPktStats"].append(packet.payloadBytes)
            self.fHeaderBytes = packet.hdlen
            self.forwardLastSeen = packet.timeStamp
            self.forwardBytes += packet.payloadBytes
            self.forward.append(packet)
            if packet.flagPSH: self.fPSH_cnt+=1
            if packet.flagURG: self.fURG_cnt+=1

        else:
            self.Init_Win_bytes_backward = packet.TCPWindow
            self.stat['flowLengthStats'].append(packet.payloadBytes)
            self.stat['bwdPktStats'].append(packet.payloadBytes)
            self.bHeaderBytes = packet.hdlen
            self.backwardLastSeen = packet.timeStamp
            self.backwardBytes += packet.payloadBytes
            self.backward.append(packet)
            if packet.flagPSH: self.bPSH_cnt+=1
            if packet.flagURG: self.bURG_cnt+=1
        self.ptc = packet.ptc
        self.flowID = packet.flowID

    def addPacket(self,packet):
        self.updateFlowBulk(packet)
        self.detectUpdateSubflows(packet)
        self.checkFlags(packet)
        currentTS = packet.timeStamp
        if self.isBidirectional:
            self.stat['flowLengthStats'].append(packet.payloadBytes)
            if self.src == packet.src:
                if (packet.payloadBytes>=1): self.Act_data_pkt_forward+=1
                self.stat['fwdPktStats'].append(packet.payloadBytes)
                self.fHeaderBytes+= packet.hdlen
                self.forward.append(packet)
                self.forwardBytes += packet.payloadBytes
                if (len(self.forward) >1):
                    self.stat['forwardIAT'].append(currentTS - self.forwardLastSeen)
                self.forwardLastSeen = currentTS
                self.min_seg_size_forward = min(packet.hdlen,self.min_seg_size_forward)
            else:
                self.stat['bwdPktStats'].append(packet.payloadBytes)
                self.Init_Win_bytes_backward = packet.TCPWindow
                self.bHeaderBytes += packet.hdlen
                self.backward.append(packet)
                self.backwardBytes += packet.payloadBytes
                if (len(self.backward) > 1):
                    self.stat['backwardIAT'].append(currentTS - self.backwardLastSeen)
                self.backwardLastSeen = currentTS
        else:
            if (packet.payloadBytes >= 1):
                self.Act_data_pkt_forward+=1
            self.stat['fwdPktStats'].append(packet.payloadBytes)
            self.stat['flowLengthStats'].append(packet.payloadBytes)
            self.fHeaderBytes += packet.hdlen
            self.forward.append(packet)
            self.forwardBytes += packet.payloadBytes
            self.stat['forwardIAT'].append(currentTS - self.forwardLastSeen)
            self.forwardLastSeen = currentTS
            self.min_seg_size_forward = min(packet.hdlen,self.min_seg_size_forward)
        self.stat['flowIAT'].append(packet.timeStamp - self.flowLastSeen)
        self.flowLastSeen = packet.timeStamp

    def getPktsPerSecond(self,fob):
        duration = self.flowLastSeen - self.flowStartTime
        if (duration>0):
            return len(self.forward)/float(duration)/1000000 if (fob=='f') else len(self.backward)/float(duration)/1000000
        else:
            return 0

    def getDownUpRatio(self):
        if (len(self.forward) > 0):
            return float(len(self.backward))/len(self.forward)

    def getAvgPacketSize(self):
        if self.packetCount() > 0:
            return sum(self.stat['flowLengthStats'])/self.packetCount()
        else:
            return 0

    def fAvgSegmentSize(self):
        if len(self.forward) !=0:
            return sum(self.stat['fwdPktStats'])/len(self.forward)
        else:
            return 0

    def bAvgSegmentSize(self):
        if len(self.backward) !=0:
            return sum(self.stat['bwdPktStats'])/len(self.backward)
        else:
            return 0

    def checkFlags(self,packet):
        if (packet.flagFIN): self.flagCounts[0] +=1
        if (packet.flagSYN): self.flagCounts[1] +=1
        if (packet.flagRST): self.flagCounts[2] +=1
        if (packet.flagPSH): self.flagCounts[3] +=1
        if (packet.flagACK): self.flagCounts[4] +=1
        if (packet.flagURG): self.flagCounts[5] +=1
        if (packet.flagCWR): self.flagCounts[6] +=1
        if (packet.flagECE): self.flagCounts[7] +=1

    def getSflow(self,fob):
        if (self.sfCount <= 0): return 0
        else:
            #ForwardByte
            if (fob == "fb"): return self.forwardBytes/self.sfCount
            #ForwardPacket
            if (fob == "fp"): return len(self.forward)/self.sfCount
            #BackwardByte
            if (fob == "bb"): return self.backwardBytes/self.sfCount
            #BackwardPacket
            if (fob == "bp"): return len(self.backward)/self.sfCount

    def detectUpdateSubflows(self,packet):
        if self.sfLastPacketTS == -1:
            self.sfLastPacketTS = packet.timeStamp
            self.sfAcHelper = packet.timeStamp
        if (packet.timeStamp - self.sfLastPacketTS/float(1000000) > 1.0):
            self.sfCount +=1
            #lastSFduration = packet.timeStamp - self.sfAcHelper
            self.updateActiveIdleTime(packet.timeStamp - self.sfLastPacketTS,5000000)
            self.sfAcHelper = packet.timeStamp
        self.sfLastPacketTS = packet.timeStamp

    # bulk
    def updateFlowBulk(self,packet):
        if (self.src == packet.src):
            self.updateForwardBulk(packet,self.blastBulkTS)
        else:
            self.updateBackwardBulk(packet,self.flastBulkTS)

    def updateForwardBulk(self,packet,tsOfLastBulkInOther):
        size = packet.payloadBytes
        if (tsOfLastBulkInOther > self.fbulkStartHelper): self.fbulkStartHelper = 0
        if (size<=0): return
        if (self.fbulkStartHelper == 0):
            self.fbulkStartHelper = packet.timeStamp
            self.fbulkPacketCountHelper = 1
            self.fbulkSizeHelper = size
            self.flastBulkTS = packet.timeStamp
        else:
            if((packet.timeStamp - self.flastBulkTS)/float(1000000) >1.0):
                self.fbulkStartHelper = packet.timeStamp
                self.flastBulkTS = packet.timeStamp
                self.fbulkPacketCountHelper = 1
                self.fbulkSizeHelper = size
            else:
                self.fbulkPacketCountHelper +=1
                self.fbulkSizeHelper +=size
                if (self.fbulkPacketCountHelper == 4):
                    self.fbulkStateCount +=1
                    self.fbulkPacketCount += self.fbulkPacketCountHelper
                    self.fbulkSizeTotal += self.fbulkSizeHelper
                    self.fbulkDuration += packet.timeStamp - self.fbulkStartHelper
                elif (self.fbulkPacketCountHelper >4):
                    self.fbulkPacketCount +=1
                    self.fbulkSizeTotal += size
                    self.fbulkDuration += packet.timeStamp - self.flastBulkTS
                self.flastBulkTS = packet.timeStamp

    def updateBackwardBulk(self,packet,tsOfLastBulkInOther):
        size = packet.payloadBytes
        if (tsOfLastBulkInOther > self.bbulkStartHelper): self.bbulkStartHelper = 0
        if (size<=0): return
        if (self.bbulkStartHelper == 0):
            self.bbulkStartHelper = packet.timeStamp
            self.bbulkPacketCountHelper = 1
            self.bbulkSizeHelper = size
            self.blastBulkTS = packet.timeStamp
        else:
            if((packet.timeStamp - self.blastBulkTS)/float(1000000) >1.0):
                self.bbulkStartHelper = packet.timeStamp
                self.blastBulkTS = packet.timeStamp
                self.bbulkPacketCountHelper = 1
                self.bbulkSizeHelper = size
            else:
                self.bbulkPacketCountHelper +=1
                self.bbulkSizeHelper +=size
                if (self.bbulkPacketCountHelper == 4):
                    self.bbulkStateCount +=1
                    self.bbulkPacketCount += self.bbulkPacketCountHelper
                    self.bbulkSizeTotal += self.bbulkSizeHelper
                    self.bbulkDuration += packet.timeStamp - self.bbulkStartHelper
                elif (self.bbulkPacketCountHelper >4):
                    self.bbulkPacketCount +=1
                    self.bbulkSizeTotal += size
                    self.bbulkDuration += packet.timeStamp - self.blastBulkTS
                self.blastBulkTS = packet.timeStamp

    def fAvgPerBulk(self,bp):
        if (self.fbulkStateCount != 0):
            return self.fbulkSizeTotal/self.fbulkStateCount if (bp == 'b') else self.fbulkPacketCount/self.fbulkStateCount
        else: return 0

    def fAvgBulkRate(self):
        if (self.fbulkDuration != 0):
            return self.fbulkSizeTotal / (self.fbulkDuration/float(1000000))
        else: return 0

    def bAvgPerBulk(self,bp):
        if (self.bbulkStateCount != 0):
            return self.bbulkSizeTotal/self.bbulkStateCount if (bp == 'b') else self.bbulkPacketCount/self.bbulkStateCount
        else: return 0

    def bAvgBulkRate(self):
        if (self.bbulkDuration != 0):
            return self.bbulkSizeTotal / (self.bbulkDuration/float(1000000))
        else: return 0

    def updateActiveIdleTime(self,current,threshold):
        if (current - self.endActiveTime > threshold):
            if (self.endActiveTime - self.startActiveTime) >0:
                self.stat['flowActive'].append(self.endActiveTime - self.startActiveTime)
            self.stat['flowIdle'].append(current - self.endActiveTime)
            self.startActiveTime = current
            self.endActiveTime = current
        else:
            self.endActiveTime = current

    def endActiveIdleTime(self,current,threshold,flowTO,isEnd):
        if(self.endActiveTime - self.startActiveTime) > 0:
            self.temp['flowActive'] += self.endActiveTime - self.startActiveTime
        if (~isEnd and (flowTO - (self.endActiveTime - self.flowStartTime))>0):
            self.temp['flowIdle'] += flowTO - (self.endActiveTime- self.flowStartTime)


    def FlowBasedFeatures(self):
        self.name = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol','Timestamp', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets','Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
        'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
        'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
        'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
        'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
        'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
        'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk','Bwd Avg Bulk Rate',
        'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
        'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
        'Active Mean', 'Active Std', 'Active Max', 'Active Min','Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min']
        self.features = []
        self.features.append(self.flowID)
        self.features.append(self.src)
        self.features.append(self.sport)
        self.features.append(self.dst)
        self.features.append(self.dport)
        self.features.append(self.proto)
        startTime = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(self.flowStartTime))
        self.features.append(startTime)
        flowDuration = self.flowLastSeen - self.flowStartTime
        self.features.append(flowDuration*1000000)
        self.features.append(len(self.stat['fwdPktStats']))
        self.features.append(len(self.stat['bwdPktStats']))
        self.features.append(sum(self.stat['fwdPktStats']))
        self.features.append(sum(self.stat['bwdPktStats']))
        if len(self.stat['fwdPktStats']) >0:
            self.features.append(max(self.stat['fwdPktStats']))
            self.features.append(min(self.stat['fwdPktStats']))
            self.features.append(sum(self.stat['fwdPktStats'])/len(self.stat['fwdPktStats']))
            self.features.append(np.array(self.stat['fwdPktStats']).std())
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
        if len(self.stat['bwdPktStats']) >0:
            self.features.append(max(self.stat['bwdPktStats']))
            self.features.append(min(self.stat['bwdPktStats']))
            self.features.append(sum(self.stat['bwdPktStats'])/len(self.stat['bwdPktStats']))
            self.features.append(np.array(self.stat['bwdPktStats']).std())
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
        self.features.append((self.forwardBytes+self.backwardBytes)/float(flowDuration))
        self.features.append(self.packetCount()/float(flowDuration))
        self.features.append(sum(self.stat['flowIAT'])*1000000/len(self.stat['flowIAT']))
        self.features.append(np.array(self.stat['flowIAT']).std()*1000000)
        self.features.append(max(self.stat['flowIAT'])*1000000)
        self.features.append(min(self.stat['flowIAT'])*1000000)
        if len(self.forward)>1:
            self.features.append(sum(self.stat['forwardIAT'])*1000000)
            self.features.append(sum(self.stat['forwardIAT'])*1000000/len(self.stat['forwardIAT']))
            self.features.append(np.array(self.stat['forwardIAT']).std()*1000000)
            self.features.append(max(self.stat['forwardIAT'])*1000000)
            self.features.append(min(self.stat['forwardIAT'])*1000000)
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)

        if len(self.backward)>1:
            self.features.append(sum(self.stat['backwardIAT'])*1000000)
            self.features.append(sum(self.stat['backwardIAT'])*1000000/len(self.stat['backwardIAT']))
            self.features.append(np.array(self.stat['backwardIAT']).std()*1000000)
            self.features.append(max(self.stat['backwardIAT'])*1000000)
            self.features.append(min(self.stat['backwardIAT'])*1000000)
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
        self.features.append(self.fPSH_cnt)
        self.features.append(self.bPSH_cnt)
        self.features.append(self.fURG_cnt)
        self.features.append(self.bURG_cnt)
        self.features.append(self.fHeaderBytes)
        self.features.append(self.bHeaderBytes)
        self.features.append(self.getPktsPerSecond('f'))
        self.features.append(self.getPktsPerSecond('b'))

        if (len(self.forward)>0 or len(self.backward)>0):
            self.features.append(min(self.stat['flowLengthStats']))
            self.features.append(max(self.stat['flowLengthStats']))
            self.features.append(sum(self.stat['flowLengthStats'])/len(self.stat['flowLengthStats']))
            self.features.append(np.array(self.stat['flowLengthStats']).std())
            self.features.append(np.array(self.stat['flowLengthStats']).var())
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)

        self.features.append(self.flagCounts[0])        #FIN
        self.features.append(self.flagCounts[1])        #SYN
        self.features.append(self.flagCounts[2])        #RST
        self.features.append(self.flagCounts[3])        #PSH
        self.features.append(self.flagCounts[4])        #ACK
        self.features.append(self.flagCounts[5])        #URG
        self.features.append(self.flagCounts[6])        #CWR
        self.features.append(self.flagCounts[7])        #ECE

        self.features.append(self.getDownUpRatio())     #Down/Up
        self.features.append(self.getAvgPacketSize())   #Average Packet Size
        self.features.append(self.fAvgSegmentSize())    #Avg Fordward Segment
        self.features.append(self.bAvgSegmentSize())    #Avg Backward Segment
        
        self.features.append(self.fHeaderBytes)
        self.features.append(self.fAvgPerBulk('b'))
        self.features.append(self.fAvgPerBulk('p'))
        self.features.append(self.fAvgBulkRate())
        self.features.append(self.bAvgPerBulk('b'))
        self.features.append(self.bAvgPerBulk('p'))
        self.features.append(self.bAvgBulkRate())

        self.features.append(self.getSflow('fp'))
        self.features.append(self.getSflow('fb'))
        self.features.append(self.getSflow('bp'))
        self.features.append(self.getSflow('bb'))

        self.features.append(self.Init_Win_bytes_forward)
        self.features.append(self.Init_Win_bytes_backward)
        self.features.append(self.Act_data_pkt_forward)
        self.features.append(self.min_seg_size_forward)
        
        if len(self.stat['flowActive']) >0:
            self.features.append(sum(self.stat['flowActive'])/len(self.stat['flowActive']))
            self.features.append(np.array(self.stat['flowActive']).std())
            self.features.append(max(self.stat['flowActive']))
            self.features.append(min(self.stat['flowActive']))
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
        
        if len(self.stat['flowIdle']) >0:
            self.features.append(sum(self.stat['flowIdle'])/len(self.stat['flowIdle']))
            self.features.append(np.array(self.stat['flowIdle']).std())
            self.features.append(max(self.stat['flowIdle']))
            self.features.append(min(self.stat['flowIdle']))
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)