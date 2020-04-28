import sys
from PyQt5 import uic
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from packetcatch import packetsniff
from PcapReader import pcapReader

class Main(QMainWindow):
    def __init__(self):
        super(Main,self).__init__()
        uic.loadUi('main.ui',self)                                          #读取.ui文件（于QtDesigner设计）
        self.setWindowTitle("Something like Scapy")
        self.setFixedSize(800,800)
        self.last_dir = None
        #Behavior
        self.summary.setSelectionBehavior(QAbstractItemView.SelectRows)     #点击表格时选择整行
        self.analysis.setHeaderHidden(True)                                 #TreeWidget列头隐藏
        #signal
        self.summary.cellClicked.connect(self.moreInfo)                     #点击单行表格显示该数据的详细信息
        self.actionOnlineSniff.triggered.connect(self.onlineSniff)          #暂定，menuBar下启动在线抓包
        self.actionOpen.triggered.connect(self.offlineSniff)                #menuBat下选择指定pcap文件读取分析
        #Layout setting
        self.layout = QGridLayout()                                         #排版信息
        self.layout.addWidget(self.summary,0,0)
        self.layout.addWidget(self.analysis,1,0)
        
    def onlineSniff(self):
        #thread settings
        self.threadpool = QThreadPool()                                     #线程池
        thread = packetsniff()
        thread.signals.doneSignal.connect(self.updateOnline)                #捕捉到一条流量的反馈
        self.sniffStop.clicked.connect(thread.stop)                         #暂定，在线捕抓停止按钮
        self.threadpool.start(thread)

    def offlineSniff(self):
        dialog = QFileDialog()
        dialog.setAcceptMode(QFileDialog.AcceptOpen)
        dialog.setFileMode(QFileDialog.ExistingFile)
        dialog.setViewMode(QFileDialog.Detail)
        if self.last_dir != None:
            dialog.setDirectory(last_dir)
        while True:
            url = dialog.getOpenFileName()
            if (url[0][-4:] == 'pcap' ):
                packet = pcapReader(url[0])
                self.updateOffline(packet)
                break
            elif len(url[0]) == 0:                                           #Cancel Button Selected
                break
            else:
                QMessageBox.information(self,"File Extension Error","Only Accept .pcap file")
        
    def updateOnline(self,packet):                                          #在线捕捉的流量显示（单条）
        rowposition = self.summary.rowCount()
        self.summary.insertRow(rowposition)
        self.summary.setItem(rowposition,0,QTableWidgetItem(packet.src))
        self.summary.setItem(rowposition,1,QTableWidgetItem(str(packet.sport)))
        self.summary.setItem(rowposition,2,QTableWidgetItem(str(packet.ptc)))
        self.summary.setItem(rowposition,3,QTableWidgetItem(packet.dst))
        self.summary.setItem(rowposition,4,QTableWidgetItem(str(packet.dport)))

    def updateOffline(self,packet):                                         #离线捕捉的流量显示（多条）
        for i in packet:
            rowposition = self.summary.rowCount()
            self.summary.insertRow(rowposition)
            self.summary.setItem(rowposition,0,QTableWidgetItem(i.src))
            self.summary.setItem(rowposition,1,QTableWidgetItem(str(i.sport)))
            self.summary.setItem(rowposition,2,QTableWidgetItem(str(i.ptc)))
            self.summary.setItem(rowposition,3,QTableWidgetItem(i.dst))
            self.summary.setItem(rowposition,4,QTableWidgetItem(str(i.dport)))

    def moreInfo(self,line,col):                                            #暂定，流量详细信息
        self.analysis.clear()
        eth = QTreeWidgetItem(['Ethernel II'])                              #数据链路层
        ip = QTreeWidgetItem(["IP version 4 .."])                           #IP层
        tcp = QTreeWidgetItem(["Transport Control Protocol"])               #传输层
        eth_sum = QTreeWidgetItem(['Destination...'])                       #数据链路层补充信息
        eth.addChild(eth_sum)
        ip_sum = QTreeWidgetItem(['IP Information...'])                     #IP层补充信息
        ip.addChild(ip_sum)
        self.analysis.addTopLevelItem(eth)                                  #连接到主TreeWidget
        self.analysis.addTopLevelItem(ip)
        self.analysis.addTopLevelItem(tcp)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Main()
    window.show()
    sys.exit(app.exec_())
