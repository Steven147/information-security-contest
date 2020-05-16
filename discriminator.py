# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras import datasets, layers, models
#from sklearn.preprocessing import LabelEncoder,OneHotEncoder
from sklearn import preprocessing
from tensorflow.keras import backend as K 
from pickle import dump


def replace():
    data2017 = pd.read_csv('weekday1_final.csv', header=0)
    print(data2017.shape)
    label2017=data2017[' Label']

    newlabel2017=label2017.replace({
        'BENIGN':0, 'DoS Hulk':1, 'PortScan':2, 'DDoS':1, 'DoS GoldenEye':1,'FTP-Patator':4, 'SSH-Patator':4, 'DoS slowloris':1, 'DoS Slowhttptest':1, 'WebAttackorBruteForce':4, 
        'WebAttackorXSS':4, 'Infiltration':3, 'WebAttackorSqlInjection':4,'Heartbleed':4
    })
    xof2017=data2017.drop(' Label',1)
    yof2017=newlabel2017
    return xof2017,yof2017


def tensor():
    xof2017,yof2017 = replace()
    scaler1 = preprocessing.StandardScaler().fit(xof2017)
    xof2017 = scaler1.transform(xof2017)
    xoftrain1 = K.cast_to_floatx(xof2017)
    print(xoftrain1.shape)
    yoftrain1 = K.cast_to_floatx(yof2017)
    print(yoftrain1)
    dump(scaler1,open('name.pkl','wb')) # save scaler to name.pkl file
    return xoftrain1,yoftrain1

def to_image(array0):
    array0 = np.array(array0)
    array0 = np.column_stack((array0, np.zeros((array0.shape[0], 14))))
    return array0.reshape((array0.shape[0],8,8,1))

train_list = [xof2017]

def to_label(array0):
    array0 = np.array(array0)
    return array0.reshape((array0.shape[0],1))

def train():
    xoftrain1,yoftrain1 = tensor()
    train_images0, train_labels0 = to_image(xoftrain1), to_label(yoftrain1)
    train_images, test_images, train_labels, test_labels = train_test_split(train_images0, train_labels0,test_size=0.2,random_state=1)

    model = models.Sequential()
    model.add(layers.Conv2D(32, (3, 3), padding='same',activation='relu', input_shape=(8,8, 1)))
    model.add(layers.MaxPooling2D((3, 3),padding='same'))
    model.add(layers.Conv2D(64, (3, 3), padding='same', activation='relu'))
    model.add(layers.MaxPooling2D((3, 3),padding='same'))
    model.add(layers.Conv2D(64, (3, 3), padding='same', activation='relu'))
    model.add(layers.Flatten())
    model.add(layers.Dense(64, activation='relu'))
    model.add(layers.Dense(5))   #softmax

    model.compile(optimizer='adam',
                  loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),  
                  metrics=['accuracy'])

    history = model.fit(train_images, train_labels, epochs=2, 
                        validation_data=(test_images, test_labels))

    test_loss, test_acc = model.evaluate(test_images,  test_labels, verbose=2)
    print(test_acc)
    model.save('my_model.h5')