from FlowCheck.BasicFlow import *
from FlowCheck.FlowGenerator import *
from FlowCheck.PcapReader import *

def getFlowInfo(packet):
    ret = pcapReader(packet)
    flowgen = FlowGenerator(True,120000000, 5000000)
    for i in range(0,len(ret)):
        if (ret[i] != None):
            flowgen.addPacket(ret[i])
    for i in flowgen.finishedFlows['Flow']:
        try:
            i.FlowBasedFeatures()
        except:
            break
    return flowgen.finishedFlows