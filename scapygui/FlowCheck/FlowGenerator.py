from FlowCheck.BasicPacket import *
from FlowCheck.BasicFlow import *
'''
columns (total 85 columns)
Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol,Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets,Total Length of Fwd Packets, Total Length of Bwd Packets,
Fwd Packet Length Max, Fwd Packet Length Min, Fwd Packet Length Mean, Fwd Packet Length Std,
Bwd Packet Length Max, Bwd Packet Length Min, Bwd Packet Length Mean, Bwd Packet Length Std,
Flow Bytes/s, Flow Packets/s, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min,
Fwd IAT Total, Fwd IAT Mean, Fwd IAT Std, Fwd IAT Max, Fwd IAT Min,
Bwd IAT Total, Bwd IAT Mean, Bwd IAT Std, Bwd IAT Max, Bwd IAT Min,
Fwd PSH Flags, Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, Fwd Header Length, Bwd Header Length,
Fwd Packets/s, Bwd Packets/s, Min Packet Length, Max Packet Length, Packet Length Mean, Packet Length Std, Packet Length Variance,
FIN Flag Count, SYN Flag Count, RST Flag Count, PSH Flag Count, ACK Flag Count, URG Flag Count, 
CWE Flag Count, ECE Flag Count, Down/Up Ratio, Average Packet Size, Avg Fwd Segment Size, Avg Bwd Segment Size, Fwd Header Length,
Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk,Bwd Avg Bulk Rate,
Subflow Fwd Packets, Subflow Fwd Bytes, Subflow Bwd Packets, Subflow Bwd Bytes,
Init_Win_bytes_forward, Init_Win_bytes_backward, act_data_pkt_fwd, min_seg_size_forward,
Active Mean, Active Std, Active Max, Active Min,"
Idle Mean, Idle Std, Idle Max, Idle Min, Label
'''
# Dictionary refer to hash table
class FlowGenerator:
    def __init__(self,bid,fTO,actTO):
        self.mListener = None
        self.currentFlows = {"ID":[],"Flow":[]}
        self.finishedFlows = {"ID":[],"Flow":[]}
        self.IPAdresses = {"ID":[],"Flow":[]}
        self.bidirectional = bid
        self.flowTimeOut = fTO
        self.flowActivityTimeOut = actTO
        self.finishedFlowCount = 0

    def addFlowListener(self,listener):
        self.mListener = listener

    def addPacket(self,packet):
        if (packet==None): return
        current = packet.timeStamp
        if (packet.fwdFlowID() in self.currentFlows['ID']) or (packet.bwdFlowID() in self.currentFlows['ID']):
            if (packet.fwdFlowID() in self.currentFlows['ID']):
                id = packet.fwdFlowID()
            else:
                id = packet.bwdFlowID()
            #(从currentFlows 中的ID找到对应的Flow)
            index = self.currentFlows['ID'].index(id)
            flow = self.currentFlows['Flow'][index]
            # Flow finished due flowtimeout
            if ((current - flow.flowStartTime)>self.flowTimeOut):
                if (flow.packetCount() >1):
                    if (self.mListener != None):
                        self.mListener.onFlowGenerated(flow)
                    else:
                        self.finishedFlows['ID'].append(self.getFlowCount())
                        self.finishedFlows['Flow'].append(flow)
                self.currentFlows['ID'].remove(self.currentFlows['ID'][index])
                self.currentFlows['Flow'].remove(self.currentFlows['Flow'][index])
                self.currentFlowsUpdate(id,BasicFlow(1,[self.bidirectional,packet,flow.src,flow.dst,flow.sport,flow.dport]))
                '''
                self.currentFlows['ID'].append(id)
                self.currentFlows['Flow'].append(BasicFlow(1,[self.bidirectional,packet]))
                '''
            # Flow finished due FIN flag (TCP)
            elif (packet.flagFIN):
                flow.addPacket(packet)
                if (self.mListener != None): self.mListener.onFlowGenerated(flow)
                else: 
                    self.finishedFlows['ID'].append(self.getFlowCount())
                    self.finishedFlows['Flow'].append(flow)
                self.currentFlows['ID'].remove(self.currentFlows['ID'][index])
                self.currentFlows['Flow'].remove(self.currentFlows['Flow'][index])
            else:
                flow.updateActiveIdleTime(current,self.flowActivityTimeOut)
                flow.addPacket(packet)
                self.currentFlowsUpdate(id,flow)
                '''
                self.currentFlows['ID'].append(id)
                self.currentFlows['Flow'].append(flow)
                '''
        else:
            self.currentFlowsUpdate(packet.fwdFlowID(),BasicFlow(2,[self.bidirectional,packet]))
            '''
            self.currentFlows['ID'].append(packet.fwdFlowID())
            self.currentFlows['Flow'].append(BasicFlow(2,[self.bidirectional,packet]))
            '''

    def getFlowCount(self):
        self.finishedFlowCount+=1
        return self.finishedFlowCount
        
    def currentFlowsUpdate(self,key,target):
        flag = True
        for i in range(0,len(self.currentFlows['ID'])):
            if self.currentFlows['ID'][i] == key:
                self.currentFlows['Flow'][i] = target
                flag = False
        if flag:
            self.currentFlows['ID'].append(key)
            self.currentFlows['Flow'].append(target)


