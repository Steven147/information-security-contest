import sys
from PyQt5 import uic
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from packetcatch import packetsniff
from PcapReader import pcapReader
from scapy.all import *

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
        self.packet = []
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
                self.packet = sniff(offline = url[0])
                self.updateOffline()
                break
            elif len(url[0]) == 0:                                           #Cancel Button Selected
                break
            else:
                QMessageBox.information(self,"File Extension Error","Only Accept .pcap file")
        
    def updateOnline(self,packet):                                          #在线捕捉的流量显示（单条）
        rowposition = self.summary.rowCount()
        self.summary.insertRow(rowposition)
        if IP in packet:
            self.summary.setItem(rowposition,0,QTableWidgetItem(packet[IP].src))
            self.summary.setItem(rowposition,1,QTableWidgetItem(str(packet[IP].proto)))
            self.summary.setItem(rowposition,2,QTableWidgetItem(packet[IP].dst))
        elif IPv6 in pacekt:
            pass
        self.packet.append(packet)

    def updateOffline(self):                                         #离线捕捉的流量显示（多条）
        for i in self.packet:
            rowposition = self.summary.rowCount()
            self.summary.insertRow(rowposition)
            if ARP in i:
                self.summary.setItem(rowposition,0,QTableWidgetItem(i[ARP].psrc))
                self.summary.setItem(rowposition,1,QTableWidgetItem('-'))
                self.summary.setItem(rowposition,2,QTableWidgetItem(i[ARP].pdst))
            elif IP in i:
                self.summary.setItem(rowposition,0,QTableWidgetItem(i[IP].src))
                self.summary.setItem(rowposition,1,QTableWidgetItem(str(i[IP].proto)))
                self.summary.setItem(rowposition,2,QTableWidgetItem(i[IP].dst))

    def moreInfo(self,line,col):                                            #暂定，流量详细信息
        packet = self.packet[line]
        self.analysis.clear()
        eth = QTreeWidgetItem(['Ethernel II'])                              #数据链路层
        ip = QTreeWidgetItem(["IP version 4 .."])                           #IP层
        tcp = QTreeWidgetItem(["Transport Control Protocol"])               #传输层
        eth.addChild(QTreeWidgetItem(["Source:" + packet[Ether].src]))
        eth.addChild(QTreeWidgetItem(["Destination:" + packet[Ether].dst]))
        eth.addChild(QTreeWidgetItem(["Type:" + str(packet[Ether].type)]))
        self.analysis.addTopLevelItem(eth)

        if IP in packet:
            ip = QTreeWidgetItem(["IP version 4"])                           #IP层
            ip.addChild(QTreeWidgetItem(["Source:"+packet[IP].src]))
            ip.addChild(QTreeWidgetItem(["Destination:"+packet[IP].dst]))
            ip.addChild(QTreeWidgetItem(["HeaderLength:"+str(packet[IP].ihl*4)]))
            ip.addChild(QTreeWidgetItem(["Type Of Service:"+str(packet[IP].tos)]))
            ip.addChild(QTreeWidgetItem(["Identification:"+str(packet[IP].id)]))
            self.analysis.addTopLevelItem(ip)
        elif ARP in packet:
            ip = QTreeWidgetItem(['Address Resolution Protocol'])
            self.analysis.addTopLevelItem(ip)
        elif IPv6 in packet:
            ip = QTreeWidgetItem("[Ip version 6]")
            self.analysis.addTopLevelItem(ip)

        if TCP in packet:
            tcp = QTreeWidgetItem(["Transport Control Protocol"])
            tcp.addChild(QTreeWidgetItem(['Source Port' + str(packet[TCP].sport)]))
            tcp.addChild(QTreeWidgetItem(['Destination Port' + str(packet[TCP].dport)]))
            self.analysis.addTopLevelItem(tcp)
        elif UDP in packet:
            tcp = QTreeWidgetItem(['User Datagram Protocol'])
            tcp.addChild(QTreeWidgetItem(['Source Port' + str(packet[UDP].sport)]))
            tcp.addChild(QTreeWidgetItem(['Destination Port' + str(packet[UDP].dport)]))
            self.analysis.addTopLevelItem(tcp)
        elif ICMP in packet:
            tcp = QTreeWidgeItem(['Internet Control Message Protocol'])
            self.analysis.addTopLevelItem(tcp)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Main()
    window.show()
    sys.exit(app.exec_())
