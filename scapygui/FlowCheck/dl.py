import warnings
import numpy as np
import tensorflow.keras.backend as K #转换为张量
warnings.filterwarnings('ignore',category=FutureWarning)
from tensorflow.keras.models import Sequential,Model,load_model
from tensorflow.keras.layers import Dense,Flatten,Conv2D,MaxPooling2D
from sklearn import preprocessing
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
        i.attrforDL()
    return flowgen.finishedFlows

def preprocess(target):
    from pickle import load
    scaler = load(open('scaler.pkl','rb'))
    for i in range(0,50):
        target[i] = (float(target[i]) - scaler.mean_[i])/scaler.var_[i]
    target_float = K.cast_to_floatx(target)
    target_arr = np.array(target_float)
    target_arr = np.pad(target_arr,(0,14))
    return target_arr.reshape(1,8,8,1)

def predict(target):
    #model = model_construct()
    model = load_model('my_model.h5')
    result = []
    for i in target:
        result.append(model.predict(i))
    return result