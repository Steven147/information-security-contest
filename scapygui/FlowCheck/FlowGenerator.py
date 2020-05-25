from FlowCheck.BasicFlow import BasicFlow

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
            index = self.currentFlows['ID'].index(id)
            flow = self.currentFlows['Flow'][index]
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
            elif (packet.flagFIN):
                flow.addPacket(packet)
                if (self.mListener != None): self.mListener.onFlowGenerated(flow)
                else: 
                    self.finishedFlows['ID'].append(self.getFlowCount())
                    self.finishedFlows['Flow'].append(flow)
                self.currentFlows['ID'].remove(self.currentFlows['ID'][index])
                self.currentFlows['Flow'].remove(self.currentFlows['Flow'][index])
            else:
                flow.addPacket(packet)
                self.currentFlowsUpdate(id,flow)
                
        else:
            self.currentFlowsUpdate(packet.fwdFlowID(),BasicFlow(2,[self.bidirectional,packet]))

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


