import sys
import requests
from PyQt5 import uic
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from scapy.all import *
from packetcatch import packetsniff
from Geo.geo import *
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as Nav
from FlowCheck.run import getFlowInfo


class Main(QMainWindow):
    def __init__(self):
        '''
        主界面初始化，利用Qt Designer设计的main.ui作为布局，其中
        self.summary    -> QTableWidget,表格,显示各条数据的源、目的、协议、详细信息等等
        self.analysis   -> QTreeWidget,树状图，显示在self.summary中选中的数据的详细信息
        self.filterLine -> QLineEdit,文本输入,回车表示信号发送,根据特定指令格式将符合条件的数据给隐藏起来
        '''
        super(Main,self).__init__()
        uic.loadUi('main.ui',self)                                              #读取.ui文件（于QtDesigner设计）
        self.setWindowTitle("Something like Scapy")
        self.setFixedSize(800,800)
        #Behavior,一些widget的特性设置
        self.summary.setSelectionBehavior(QAbstractItemView.SelectRows)         #点击表格时选择整行
        self.summary.verticalHeader().setVisible(False)                         #表格自带的行号隐藏
        self.summary.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)  #表格大小根据所拥有的内容自动调整
        self.summary.horizontalHeader().setStretchLastSection(True)             #表格最后一列自动拉满
        self.analysis.setHeaderHidden(True)                                     #QTreeWidget列头隐藏
        #signal,各个信号与函数的连接
        self.summary.cellClicked.connect(self.moreInfo)                         #点击单行表格显示该数据的详细信息
        self.actionOnlineSniff.triggered.connect(self.onlineSniff)              #menuBar下启动在线抓包
        self.actionOpen.triggered.connect(self.offlineSniff)                    #menuBar下选择指定pcap文件读取分析
        self.actionSave.triggered.connect(self.save)                            #menuBar下将捕抓的数据包储存
        self.actionLocation.triggered.connect(self.geoGet)
        self.actionFlow.triggered.connect(self.flowPredict)
        self.filterLine.returnPressed.connect(self.filter)                      #QLineEdit接收到回车后将发送信号进行处理
        #Layout setting
        self.layout = QGridLayout()                                             #排版信息
        self.layout.addWidget(self.summary,0,0)
        self.layout.addWidget(self.analysis,1,0)
        #initialize
        self.packet = []                                                        #捕抓报的储存（用于过滤及显示详细信息用）
        self.filterFlag = False                                                 #表格显示的信息是否已经被过滤了
        self.count = 0                                                          #捕抓的第几个包（表格中的No）
                
    def updateOnline(self,packet):
        '''
        在线捕抓信号的返回函数，其中packet为scapy捕抓下来的格式
        '''
        self.tableUpdate(packet)                    #表格更新
        self.count+=1                               #捕抓到的包+1
        self.summary.resizeColumnsToContents()
        self.packet.append(packet)

    def updateOffline(self):
        '''
        离线.pcap包的内容
        '''
        for i in self.packet:
            self.tableUpdate(i)
            self.count+=1
        self.summary.resizeColumnsToContents()

    def tableUpdate(self,packet):
        '''
        self.summary QTableWidget的更新，其中pacet的格式为scapy捕抓的原本格式(scapy.layers.l2.Ether)
        packet[IP] -> IP信息 , packet[IP].src -> 该数据包的IP源地址
        packet[TCP] -> TCP信息 , packet[TCP].sport -> 该数据包的TCP源端口
        具体有那些属性可以调用sniff()来查看，或是直接到scapy的Documentation查找
        TableWidget添加内容方法 - > self.summary.setItem(行号，列号，QTableWidgetItem(你要加入的玩意（需要是str类型）))
        目前暂定(以下数组均为列号) ,0 -> 第几个数据包 , 1 -> 信息源头 , 2 -> 协议 , 3 -> 信息目的端 , 4 -> 数据包长度 , 5 -> 该条数据包的详细信息
        '''
        rowposition = self.summary.rowCount()
        self.summary.insertRow(rowposition)
        self.summary.setItem(rowposition,0,QTableWidgetItem(str(self.count)))
        self.summary.setItem(rowposition,4,QTableWidgetItem(str(len(packet))))
        '''
        各个数据包中的每个数值代表意义可以查找相应的标准（RFC...）或是查找别人整理好的
        如:http://www.023wg.com/message/message/cd_feature_cover.html
        '''        
        #ARP数据包设置
        if ARP in packet:
            self.summary.setItem(rowposition,1,QTableWidgetItem(packet[ARP].hwsrc))
            self.summary.setItem(rowposition,2,QTableWidgetItem('ARP'))
            self.summary.setItem(rowposition,3,QTableWidgetItem(packet[ARP].hwdst))
            if (packet[ARP].op == 1): info = "Who has" + packet[ARP].psrc + "? Tell" + packet[ARP].pdst #ARP请求
            elif (packet[ARP].op == 2): info = packet[ARP].pdst + "is at " + packet[ARP].hwsrc          #ARP回应
            elif (packet[ARP].op == 3): pass                                                            #RARP请求
            elif (packet[ARP].op == 4): pass                                                            #RARP回应
            self.summary.setItem(rowposition,5,QTableWidgetItem(info))
        #IP数据包设置
        elif IP in packet:
            self.summary.setItem(rowposition,1,QTableWidgetItem(packet[IP].src))
            if (packet[IP].proto == 1): 
                self.summary.setItem(rowposition,2,QTableWidgetItem('ICMP'))                            #ICMP包
            elif (packet[IP].proto == 6): 
                self.summary.setItem(rowposition,2,QTableWidgetItem('TCP'))                             #TCP包
                temp = ""
                for k in packet[TCP].flags:                                                             #TCP包中flags的状况
                    if k == 'C': temp += 'CWR,'
                    if k == 'E': temp += 'ECE,'
                    if k == 'U': temp += 'URG,'
                    if k == 'A': temp += 'ACK,'
                    if k == 'P': temp += 'PSH,'
                    if k == 'R': temp += 'RST,'
                    if k == 'S': temp += 'SYN,'
                    if k == 'F': temp += 'FIN,'
                info = str(packet[TCP].sport) + '->' + str(packet[TCP].dport) + '[' + temp[:-1] + ']'   #显示示例 54376->443['PSH,ACK']
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
            elif (packet[IP].proto == 17):                                                              #UDP包
                self.summary.setItem(rowposition,2,QTableWidgetItem('UDP'))
                info = str(packet[UDP].sport) + '->' + str(packet[UDP].dport)
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
            self.summary.setItem(rowposition,3,QTableWidgetItem(packet[IP].dst))

    def moreInfo(self,line,col):
        '''
        QTreeWidget self.analysis 的设置，当在QTableWidget(self.summary)选中某行后接收到信号，其中line及col表示是选中的是第几行第几列
        因为有可能filter过后隐藏了某些行因此不能直接用line去self.packet查找对应的应该是第几个数据包，因此要根据选中行的No来查找
        同tableUpdate,各数据包的详细接释可以从wireshark查看或者是 http://www.023wg.com/message/message/cd_feature_cover.html
        QTreewidget 的格式如下:
        self.analysis(QTreewidget)
        -eth(QTreeWidgeItem)
          -child1
        -ip(QTreeWidgetItem)
          -child2
        child1添加在eth的方法 -> eth.addChild(QTreeWidgetItem([要添加的字符串]))
        eth添加在self.analysis的方法 -> self.analysis.addTopLevelItem(eth)
        '''
        packet = self.packet[int(self.summary.item(line,0).text())]
        self.analysis.clear()
        eth = QTreeWidgetItem(['Ethernel II'])                                      #数据链路层
        eth.addChild(QTreeWidgetItem(["Source: " + packet[Ether].src]))
        eth.addChild(QTreeWidgetItem(["Destination: " + packet[Ether].dst]))
        eth.addChild(QTreeWidgetItem(["Type: " + str(packet[Ether].type)]))
        self.analysis.addTopLevelItem(eth)
        #流量检测只检测TCP,UDP的包，非以上两者的包是否要在则例分析与解释?
        if IP in packet:
            ip = QTreeWidgetItem(["IP version 4"])                                  #IP层（其中有可能是IPv6，可以再修改），以下可以在补充，如IP flags
            ip.addChild(QTreeWidgetItem(["Source:"+packet[IP].src]))                #IP源
            ip.addChild(QTreeWidgetItem(["Destination:"+packet[IP].dst]))           #IP目的
            ip.addChild(QTreeWidgetItem(["HeaderLength:"+str(packet[IP].ihl*4)]))   #IP头信息
            ip.addChild(QTreeWidgetItem(["Type Of Service:"+str(packet[IP].tos)]))  #IP Type Of Service
            ip.addChild(QTreeWidgetItem(["Identification:"+str(packet[IP].id)]))    #IP 认证
            self.analysis.addTopLevelItem(ip)
        elif ARP in packet:
            ip = QTreeWidgetItem(['Address Resolution Protocol'])                   #ARP层,以下都是根据wireshark格式复写
            ip.addChild(QTreeWidgetItem(["Hardware type:"+str(packet[ARP].hwtype)]))
            ip.addChild(QTreeWidgetItem(["Protocol Type:"+str(packet[ARP].ptype)]))
            ip.addChild(QTreeWidgetItem(["Hardware Size:"+str(packet[ARP].hwlen)]))
            ip.addChild(QTreeWidgetItem(["Protocol Size:"+str(packet[ARP].plen)]))
            ip.addChild(QTreeWidgetItem(["Opcode:"+str(packet[ARP].op)]))
            ip.addChild(QTreeWidgetItem(["Sender MAC address:"+str(packet[ARP].hwsrc)]))
            ip.addChild(QTreeWidgetItem(["Sender IP address:"+str(packet[ARP].psrc)]))
            ip.addChild(QTreeWidgetItem(["Target MAC address:"+str(packet[ARP].hwdst)]))
            ip.addChild(QTreeWidgetItem(["Target IP address:"+str(packet[ARP].pdst)]))
            self.analysis.addTopLevelItem(ip)
        elif IPv6 in packet:
            ip = QTreeWidgetItem("[Ip version 6]")                                  #未完整
            self.analysis.addTopLevelItem(ip)

        if TCP in packet:
            tp = QTreeWidgetItem(["Transport Control Protocol"])                    #TCP层，以下内容根据Wireshark格式复写
            tp.addChild(QTreeWidgetItem(['Source Port:' + str(packet[TCP].sport)]))
            tp.addChild(QTreeWidgetItem(['Destination Port:' + str(packet[TCP].dport)]))
            tp.addChild(QTreeWidgetItem(['Sequence Number:' + str(packet[TCP].seq)]))
            tp.addChild(QTreeWidgetItem(['Acknowledgment Number:' + str(packet[TCP].ack)]))
            tp.addChild(QTreeWidgetItem(['Header Length:' + str(packet[TCP].dataofs)]))
            tp.addChild(QTreeWidgetItem(['Flags:' + str(packet[TCP].flags)]))
            #more flag information ..?                                              #TCP各个flag的补充
            tp.addChild(QTreeWidgetItem(['Windows Size:' + str(packet[TCP].window)]))
            tp.addChild(QTreeWidgetItem(['Checksum:' + str(packet[TCP].chksum)]))
            tp.addChild(QTreeWidgetItem(['Urgent Pointer:' + str(packet[TCP].urgptr)]))
            self.analysis.addTopLevelItem(tp)
        elif UDP in packet:
            tp = QTreeWidgetItem(['User Datagram Protocol'])                        #UDP层
            tp.addChild(QTreeWidgetItem(['Source Port:' + str(packet[UDP].sport)]))
            tp.addChild(QTreeWidgetItem(['Destination Port:' + str(packet[UDP].dport)]))
            tp.addChild(QTreeWidgetItem(['Length:' + str(packet[UDP].len)]))
            tp.addChild(QTreeWidgetItem(['Checksum:' + str(packet[UDP].chksum)]))
            self.analysis.addTopLevelItem(tp)
        elif ICMP in packet:
            tp = QTreeWidgeItem(['Internet Control Message Protocol'])
            self.analysis.addTopLevelItem(tp)

    def filter(self):
        '''
        self.filterLine在接收到回车后将进入该函数，根据输入的命令将复合的数据项给隐藏起来
        目前设定的命令为:ip.src=1.1.1.1,ip.dst=2.2.2.2,arp.src=(硬件地址),arp.dst=(硬件地址),tcp.dport=23,tcp=sport=1231,udp.port=231,udp.sport=1234
        '''
        if self.filterFlag == True:
            for i in range(0,self.summary.rowCount()):
                self.summary.showRow(i)
        self.filterFlag = True
        temp = self.filterLine.text()               #temp example : ip.src = 192.168.0.105
        if temp == '':
            self.filterFlag = False
            return
        temp = temp.replace(' ','')
        #cmd    -> 命令
        #targe  -> 目标
        #chk    -> 待检查项
        cmd = temp[:temp.find('=')]
        target = temp[temp.find('=')+1:]
        chk = None
        for i in range(0,self.summary.rowCount()):
            #check from tableWidget
            ptc = self.summary.item(i,2).text().lower()
            if 'src' in cmd:
                chk = self.summary.item(i,1).text()
            elif 'dst' in cmd:
                chk = self.summary.item(i,3).text()
            if (chk == target):
                self.summary.hideRow(i)
                continue
            #Check from self.packet
            if 'tcp' in cmd:
                if TCP in self.packet[i]:
                    if 'sport' in cmd:      chk = self.packet[i][TCP].sport
                    elif 'dport' in cmd:    chk = self.packet[i][TCP].dport
                else: continue
            elif 'udp' in cmd:
                if UDP in self.packet[i]:
                    if 'sport' in cmd:      chk = self.packet[i][UDP].sport
                    elif 'dport' in cmd:    chk = self.packet[i][UDP].dport
                else: continue
            if (str(chk) == target):
                self.summary.hideRow(i)

    #File Menubar        
    def save(self):
        '''
        调用QFileDialog完成储存
        '''
        dialog = QFileDialog()
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)
        fileName = dialog.getSaveFileName()
        if (fileName != None) and (len(self.packet) != 0):
            _ = wrpcap(fileName[0],self.packet)

    def onlineSniff(self):
        '''
        开启一个新的线程以进行在线嗅探，具体嗅探过程与packetcatch.py中
        '''
        #initialize,将上一次捕捉的信息清零，同时表格清空
        self.packet = []
        self.summary.setRowCount(0)
        self.count = 0
        self.select = QDialog()
        self.select = uic.loadUi('select.ui')
        for i in get_windows_if_list():                                        #网卡信息
            self.select.networkIF.addItem(i['name'])

        import pandas as pd
        location = pd.read_csv('worldcities.csv')
        city = location['city_ascii'].to_list()
        country = location['country'].to_list()
        self.country_city = []
        for i in range(0,len(city)):
            self.country_city.append(country[i]+','+city[i])
        country = list(dict.fromkeys(country))
        country.sort()
        self.select.Country.addItems(country)
        self.select.Country.currentIndexChanged.connect(self.cityInfo)
        if (self.select.exec_()):
            #thread settings
            self.city = self.select.City.currentText()
            ifname = self.select.networkIF.currentText()
            self.locallat = float(location.loc[location['city_ascii'] == self.city]['lat'])
            self.locallon = float(location.loc[location['city_ascii'] == self.city]['lng'])
            self.threadpool = QThreadPool()                                     #线程池
            thread = packetsniff(ifname)
            thread.signals.doneSignal.connect(self.updateOnline)                #捕捉到一条流量的反馈
            self.sniffStop.clicked.connect(thread.stop)                         #暂定，在线捕抓停止按钮
            self.threadpool.start(thread)

    def cityInfo(self):
        city = []
        country = self.select.Country.currentText()
        for i in self.country_city:
            if country in i:
                city.append(i.split(',')[1])
        city.sort()
        self.select.City.clear()
        self.select.City.addItems(city)

    def offlineSniff(self):
        '''
        通过调用QFileDialog打开.pcap文件达成离线读取
        '''
        dialog = QFileDialog()
        dialog.setAcceptMode(QFileDialog.AcceptOpen)        #QFileDialog设定打开模式
        dialog.setFileMode(QFileDialog.ExistingFile)
        dialog.setViewMode(QFileDialog.Detail)
        while True:
            url = dialog.getOpenFileName()                  #url[0]为路径，其它..
            if (url[0][-4:] == 'pcap' ):                
                self.summary.setRowCount(0)
                self.count = 0
                self.select = uic.loadUi('select.ui')
                self.select.networkIF.setEnabled(False)
                import pandas as pd
                location = pd.read_csv('worldcities.csv')
                city = location['city_ascii'].to_list()
                country = location['country'].to_list()
                self.country_city = []
                for i in range(0,len(city)):
                    self.country_city.append(country[i]+','+city[i])
                country = list(dict.fromkeys(country))
                country.sort()
                self.select.Country.addItems(country)
                self.select.Country.currentIndexChanged.connect(self.cityInfo)
                if (self.select.exec_()):
                    #thread settings
                    self.city = self.select.City.currentText()
                    self.locallat = float(location.loc[location['city_ascii'] == self.city]['lat'])
                    self.locallon = float(location.loc[location['city_ascii'] == self.city]['lng'])
                    self.packet = sniff(offline = url[0])
                    self.updateOffline()
                break
            elif len(url[0]) == 0:                          #Cancel Button Selected
                break
            else:
                QMessageBox.information(self,"File Extension Error","Only Accept .pcap file")
    #Plot Menubar
    def geoGet(self):
        '''
        从IP地址透过requset ipstack获得地理位置（经纬度）
        Lat - > Latitude 纬度
        Lon -> Longitude 经度
        在通过cartopy(matplotlib下开发)画出地理位置
        cartopy 安装 https://www.lfd.uci.edu/~gohlke/pythonlibs/#cartopy (需要wheel)
        '''
        temp  = []
        repeat_ip = []
        for i in self.packet:
            if IP in i:
                #尽可能减少getLanLon的进入（耗时长）
                src = self.isNat(i[IP].src)
                dst = self.isNat(i[IP].dst)
                if ((src,dst) in repeat_ip) or ((dst,src) in repeat_ip):
                    continue
                else:
                    repeat_ip.append((src,dst))
                if src != None: 
                    slat,slon,city_src = self.getLatLon(src)
                else:           
                    slat,slon = self.locallat,self.locallon
                    city_src = self.city
                if dst != None: 
                    dlat,dlon,city_dst = self.getLatLon(dst)
                else:           
                    dlat,dlon = self.locallat,self.locallon
                    city_dst = self.city
                temp.append([[slon,dlon],[slat,dlat],city_src,city_dst])
        map = plotFlow(temp)
        toolbar = Nav(map,self)
        layout = QVBoxLayout()
        layout.addWidget(toolbar)
        layout.addWidget(map)

    def getLatLon(self,ip):
        '''
        从ipstack获得ip的物理位置
        data.get(continent_name,country_name,region_name,city)
        '''
        url = 'http://api.ipstack.com/{}?access_key=1bdea4d0bf1c3bf35c4ba9456a357ce3'
        res = requests.get(url.format(ip))
        data = res.json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        country = data.get('city')
        return latitude,longitude,country

    def isNat(self,ip):
        '''
        判断ip是不是私有地址
        A 类地址 10.0.0.0 ~ 10.255.255.255
        B 类地址 172.16.0.0 ~ 17.31.255.255
        C 类地址 192.168.0.0 ~ 192.168.255.255
        '''
        ipnum = [int(i) for i in ip.split('.')]
        if (ipnum[0] == 10): return 
        elif ((ipnum[0] == 172) and (ipnum[1]>=16 and ipnum[1]<32)): return
        elif ((ipnum[0] == 192) and (ipnum[1] == 168)): return
        else: return ip
    
    def flowPredict(self):
        sth = getFlowInfo(self.packet)
        print(sth)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Main()
    window.show()
    sys.exit(app.exec_())
