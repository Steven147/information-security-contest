import numpy as np
import tensorflow.keras.backend as K #转换为张量
from tensorflow.keras.models import Sequential,Model,load_model
from tensorflow.keras.layers import Dense,Flatten,Conv2D,MaxPooling2D
from sklearn import preprocessing
from FlowCheck.BasicFlow import *
from FlowCheck.FlowGenerator import *
from FlowCheck.PcapReader import *
from PyQt5.QtCore import *

class Signal(QObject):
    doneSignal = pyqtSignal()

class FlowPredict(QRunnable):
    def __init__(self,packet):
        super(FlowPredict,self).__init__()
        self.signal = Signal()
        self.packet = packet

    def run(self):
        sth = getFlowInfo(self.packet)
        target = []
        for i in sth['Flow']:
            i.attrforDL()
            target.append(preprocess(i.features))
        # DDos test
        #target =  preprocess([80,1293792,3,7,26,11607,20,0,8.666666667,10.26320288,5840,0,1658.142857,2137.29708,8991.398927,7.72921768,143754.6667,430865.8067,1292730,2,747,373.5,523.9661249,744,3,1293746,215624.3333,527671.9348,1292730,2,72,152,2.318765304,5.410452376,0,5840,1057.545455,1853.437529,3435230.673,1163.3,8.666666667,1658.142857,8192,229,2,20,0,0,0,0,])
        #result = predict([target])
        result = predict(target)
        with open('result.txt','w') as infile:
            #infile.write("test" + ',' + str(result))
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
    #for i in range(0,50):
    #    target[i] = (float(target[i]) - scaler.mean_[i])/scaler.var_[i]
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