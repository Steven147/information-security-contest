import numpy as np
import tensorflow.keras.backend as K
from tensorflow.keras.models import load_model
from sklearn import preprocessing
from FlowCheck.FlowGenerator import FlowGenerator
from FlowCheck.PcapReader import pcapReader
from PyQt5.QtCore import QObject,QRunnable,pyqtSignal

class Signal(QObject):
    doneSignal = pyqtSignal()

class FlowPredict(QRunnable):
    def __init__(self,packet):
        super(FlowPredict,self).__init__()
        self.signal = Signal()
        self.packet = packet

    def run(self):
        import ptvsd
        ptvsd.debug_this_thread()
        sth = getFlowInfo(self.packet)
        target = []
        for i in sth['Flow']:
            i.attrforDL()
            target.append(preprocess(i.features))
        result = predict(target)
        with open('result.txt','w') as infile:
            for i in range (0,len(sth['Flow'])):
                infile.write(sth['Flow'][i].flowID +','+ str(result[i]) + '\n')
        self.signal.doneSignal.emit()

def getFlowInfo(packet):
    ret = pcapReader(packet)
    flowgen = FlowGenerator(True,120000000, 5000000)
    for i in range(0,len(ret)):
        if (ret[i] != None):
            flowgen.addPacket(ret[i])
    for i in flowgen.finishedFlows['Flow']:
        i.attrforDL()
    return flowgen.finishedFlows

def preprocess(target):
    from pickle import load
    scaler = load(open('scaler.pkl','rb'))
    target = scaler.transform([target])
    target_float = K.cast_to_floatx(target)
    target_arr = np.array(target_float)
    target_arr = np.pad(target_arr,(0,14))
    return target_arr[0].reshape(1,8,8,1)

def predict(target):
    model = load_model('predict.h5')
    result = []
    for i in target:
        result.append(model.predict(i))
    return result