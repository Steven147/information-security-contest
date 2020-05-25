from FlowCheck.BasicPacket import BasicPacketInfo
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
        if self.src == packet.src:
            self.min_seg_size_forward = packet.hdlen
            self.Init_Win_bytes_forward = packet.TCPWindow
            self.stat["flowLengthStats"].append(packet.payloadBytes)
            self.stat["fwdPktStats"].append(packet.payloadBytes)
            self.fHeaderBytes = packet.hdlen
            self.forwardLastSeen = packet.timeStamp
            self.forwardBytes += packet.payloadBytes
            self.forward.append(packet)

        else:
            self.Init_Win_bytes_backward = packet.TCPWindow
            self.stat['flowLengthStats'].append(packet.payloadBytes)
            self.stat['bwdPktStats'].append(packet.payloadBytes)
            self.bHeaderBytes = packet.hdlen
            self.backwardLastSeen = packet.timeStamp
            self.backwardBytes += packet.payloadBytes
            self.backward.append(packet)
        self.ptc = packet.ptc
        self.flowID = packet.flowID

    def addPacket(self,packet):
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
            return len(self.forward)/(duration/1000000) if (fob=='f') else len(self.backward)/(duration/1000000)
        else:
            return 0

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

    def attrforDL(self):
        self.features = []
        self.features.append(self.dport)
        flowDuration = self.flowLastSeen - self.flowStartTime
        if flowDuration == 0:
            flowDuration = 0.1
        self.features.append(flowDuration)
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

        self.features.append((self.forwardBytes+self.backwardBytes)/(flowDuration/1000000))
        self.features.append(self.packetCount()/(flowDuration/1000000))
        self.features.append(sum(self.stat['flowIAT'])/len(self.stat['flowIAT']))
        self.features.append(np.array(self.stat['flowIAT']).std())
        self.features.append(max(self.stat['flowIAT']))
        self.features.append(min(self.stat['flowIAT']))
        if len(self.forward)>1:
            self.features.append(sum(self.stat['forwardIAT']))
            self.features.append(sum(self.stat['forwardIAT'])/len(self.stat['forwardIAT']))
            self.features.append(np.array(self.stat['forwardIAT']).std())
            self.features.append(max(self.stat['forwardIAT']))
            self.features.append(min(self.stat['forwardIAT']))
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)

        if len(self.backward)>1:
            self.features.append(sum(self.stat['backwardIAT']))
            self.features.append(sum(self.stat['backwardIAT'])/len(self.stat['backwardIAT']))
            self.features.append(np.array(self.stat['backwardIAT']).std())
            self.features.append(max(self.stat['backwardIAT']))
            self.features.append(min(self.stat['backwardIAT']))
        else:
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)
            self.features.append(0)

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

        self.features.append(self.getAvgPacketSize())
        self.features.append(self.fAvgSegmentSize())
        self.features.append(self.bAvgSegmentSize())
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