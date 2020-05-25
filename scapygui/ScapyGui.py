import sys
import requests
from PyQt5 import uic
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from scapy.all import *
from packetcatch import packetsniff
from Geo.geo import plotFlow
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as Nav

class Main(QMainWindow):
    def __init__(self):
        super(Main,self).__init__()
        uic.loadUi('main.ui',self)
        self.setWindowTitle("AnalysisAndCheck")
        self.summary.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.summary.verticalHeader().setVisible(False)
        self.summary.setSizeAdjustPolicy(QAbstractScrollArea.AdjustToContents)
        self.summary.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.analysis.setHeaderHidden(True)
        self.filterLine.setPlaceholderText("Filter that you don't care,e.g: ip.src=192.168.0.1")
        self.summary.cellClicked.connect(self.moreInfo)
        self.actionOnlineSniff.triggered.connect(self.onlineSniff)
        self.actionOpen.triggered.connect(self.offlineSniff)
        self.actionSave.triggered.connect(self.save)
        self.actionLocation.triggered.connect(self.geoGet)
        self.actionFlow.triggered.connect(self.flowPredictStart)
        self.filterLine.returnPressed.connect(self.filter)
        self.packet = []
        self.filterFlag = False
        self.count = 0
                
    def updateOnline(self,packet):
        self.tableUpdate(packet)
        self.count+=1
        self.summary.resizeColumnsToContents()
        self.packet.append(packet)

    def updateOffline(self):
        for i in self.packet:
            self.tableUpdate(i)
            self.count+=1
        self.summary.resizeColumnsToContents()

    def tableUpdate(self,packet):
        rowposition = self.summary.rowCount()
        self.summary.insertRow(rowposition)
        self.summary.setItem(rowposition,0,QTableWidgetItem(str(self.count+1)))
        self.summary.setItem(rowposition,4,QTableWidgetItem(str(len(packet))))        
        if ARP in packet:
            self.summary.setItem(rowposition,1,QTableWidgetItem(packet[ARP].hwsrc))
            self.summary.setItem(rowposition,2,QTableWidgetItem('ARP'))
            self.summary.setItem(rowposition,3,QTableWidgetItem(packet[ARP].hwdst))
            if (packet[ARP].op == 1): info = "Who has" + packet[ARP].psrc + "? Tell" + packet[ARP].pdst
            elif (packet[ARP].op == 2): info = packet[ARP].pdst + "is at " + packet[ARP].hwsrc
            self.summary.setItem(rowposition,5,QTableWidgetItem(info))
            self.summary.item(rowposition, 0).setBackground(QColor(255, 203, 255))
            self.summary.item(rowposition, 1).setBackground(QColor(255, 203, 255))
            self.summary.item(rowposition, 2).setBackground(QColor(255, 203, 255))
            self.summary.item(rowposition, 3).setBackground(QColor(255, 203, 255))
            self.summary.item(rowposition, 4).setBackground(QColor(255, 203, 255))
            self.summary.item(rowposition, 5).setBackground(QColor(255, 203, 255))
            
        elif IP in packet:
            self.summary.setItem(rowposition,1,QTableWidgetItem(packet[IP].src))
            self.summary.setItem(rowposition, 3, QTableWidgetItem(packet[IP].dst))
            if (packet[IP].proto == 1): 
                action = ICMP().get_field('type')
                self.summary.setItem(rowposition,2,QTableWidgetItem('ICMP'))
                self.summary.setItem(rowposition,5,QTableWidgetItem('(' + action.i2s[packet[ICMP].type] + ')'))
                self.summary.item(rowposition, 0).setBackground(QColor(217, 203, 255))
                self.summary.item(rowposition, 1).setBackground(QColor(217, 203, 255))
                self.summary.item(rowposition, 2).setBackground(QColor(217, 203, 255))
                self.summary.item(rowposition, 3).setBackground(QColor(217, 203, 255))
                self.summary.item(rowposition, 4).setBackground(QColor(217, 203, 255))
                self.summary.item(rowposition, 5).setBackground(QColor(217, 203, 255))
            elif (packet[IP].proto == 6): 
                self.summary.setItem(rowposition,2,QTableWidgetItem('TCP'))
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
                info = str(packet[TCP].sport) + '->' + str(packet[TCP].dport) + '[' + temp[:-1] + ']'
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
                self.summary.item(rowposition, 0).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 1).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 2).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 3).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 4).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 5).setBackground(QColor(203, 255, 209))
                
            elif (packet[IP].proto == 17):
                self.summary.setItem(rowposition,2,QTableWidgetItem('UDP'))
                info = str(packet[UDP].sport) + '->' + str(packet[UDP].dport)
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
                self.summary.item(rowposition, 0).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 1).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 2).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 3).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 4).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 5).setBackground(QColor(203, 255, 247))

        elif IPv6 in packet:
            self.summary.setItem(rowposition,1,QTableWidgetItem(packet[IPv6].src))
            self.summary.setItem(rowposition,3,QTableWidgetItem(packet[IPv6].dst))
            if (packet[IPv6].nh == 6): 
                self.summary.setItem(rowposition,2,QTableWidgetItem('TCP'))
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
                info = str(packet[TCP].sport) + '->' + str(packet[TCP].dport) + '[' + temp[:-1] + ']'
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
                self.summary.item(rowposition, 0).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 1).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 2).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 3).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 4).setBackground(QColor(203, 255, 209))
                self.summary.item(rowposition, 5).setBackground(QColor(203, 255, 209))
            elif (packet[IPv6].nh == 17):
                self.summary.setItem(rowposition,2,QTableWidgetItem('UDP'))
                info = str(packet[UDP].sport) + '->' + str(packet[UDP].dport)
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
                self.summary.item(rowposition, 0).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 1).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 2).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 3).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 4).setBackground(QColor(203, 255, 247))
                self.summary.item(rowposition, 5).setBackground(QColor(203, 255, 247))

        elif IPv6 in packet:
            self.summary.setItem(rowposition,1,QTableWidgetItem(packet[IPv6].src))
            if (packet[IPv6].nh == 6): 
                self.summary.setItem(rowposition,2,QTableWidgetItem('TCP'))
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
                info = str(packet[TCP].sport) + '->' + str(packet[TCP].dport) + '[' + temp[:-1] + ']'
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
            elif (packet[IPv6].nh == 17):
                self.summary.setItem(rowposition,2,QTableWidgetItem('UDP'))
                info = str(packet[UDP].sport) + '->' + str(packet[UDP].dport)
                self.summary.setItem(rowposition,5,QTableWidgetItem(info))
            self.summary.setItem(rowposition,3,QTableWidgetItem(packet[IPv6].dst))

    def moreInfo(self,line,col):
        packet = self.packet[int(self.summary.item(line,0).text())]
        self.analysis.clear()
        eth = QTreeWidgetItem(['Ethernel II'])
        field = Ether().get_field('type')
        eth.addChild(QTreeWidgetItem(["Source: " + packet[Ether].src]))
        eth.addChild(QTreeWidgetItem(["Destination: " + packet[Ether].dst]))
        eth.addChild(QTreeWidgetItem(["Type: " + str(hex(packet[Ether].type)) + '('+ field.i2s[packet.type].upper()+')']))
        self.analysis.addTopLevelItem(eth)
        if IP in packet:
            field = IP().get_field('proto')
            ip = QTreeWidgetItem(["IP version 4"])
            ip.addChild(QTreeWidgetItem(["Source: "+packet[IP].src]))
            ip.addChild(QTreeWidgetItem(["Destination: "+packet[IP].dst]))
            ip.addChild(QTreeWidgetItem(["Header Length: "+str(packet[IP].ihl*4)]))
            ip.addChild(QTreeWidgetItem(["Type Of Service: "+str(hex(packet[IP].tos))]))
            ip.addChild(QTreeWidgetItem(["Identification: "+str(packet[IP].id)]))
            ext = " Unused"
            for i in packet[IP].flags:
                if i == "DF": 
                    ext = " Don't Fragment"
                    break
                if i == "MF": 
                    ext = " More Fragment"
                    break
            ip.addChild(QTreeWidgetItem(["Flags: "+str(packet[IP].flags) + ext]))   #Flag
            ip.addChild(QTreeWidgetItem(["Fragment: "+str(packet[IP].frag)]))       #分段
            ip.addChild(QTreeWidgetItem(["Time to live: "+str(packet[IP].ttl)]))    #Time To Live
            ip.addChild(QTreeWidgetItem(["Protocol: "+str(hex(packet[IP].proto)) + '(' + field.i2s[packet[IP].proto].upper() + ')'])) #Next Protocol used 
            ip.addChild(QTreeWidgetItem(["Checksum: "+str(hex(packet[IP].chksum))])) #Checksum
            self.analysis.addTopLevelItem(ip)
        elif ARP in packet:
            p_field = ARP().get_field('ptype')
            op_field = ARP().get_field('op')
            ip = QTreeWidgetItem(['Address Resolution Protocol'])
            ip.addChild(QTreeWidgetItem(["Hardware type: "+str(hex(packet[ARP].hwtype))]))
            ip.addChild(QTreeWidgetItem(["Protocol Type: "+str(hex(packet[ARP].ptype)) + '(' + p_field.i2s[packet[ARP].ptype].upper()+ ')']))
            ip.addChild(QTreeWidgetItem(["Hardware Size: "+str(packet[ARP].hwlen)]))
            ip.addChild(QTreeWidgetItem(["Protocol Size: "+str(packet[ARP].plen)]))
            ip.addChild(QTreeWidgetItem(["Opcode: "+ str(packet[ARP].op) + '(' + op_field.i2s[packet[ARP].op] +')']))
            ip.addChild(QTreeWidgetItem(["Sender MAC address: "+str(packet[ARP].hwsrc)]))
            ip.addChild(QTreeWidgetItem(["Sender IP address: "+str(packet[ARP].psrc)]))
            ip.addChild(QTreeWidgetItem(["Target MAC address: "+str(packet[ARP].hwdst)]))
            ip.addChild(QTreeWidgetItem(["Target IP address: "+str(packet[ARP].pdst)]))
            self.analysis.addTopLevelItem(ip)
        elif IPv6 in packet:
            ip = QTreeWidgetItem(["Ip version 6"])
            nh_field = IPv6().get_field('nh')
            ip.addChild(QTreeWidgetItem(["Source: "+str(packet[IPv6].src)]))
            ip.addChild(QTreeWidgetItem(["Destination: "+str(packet[IPv6].dst)]))
            ip.addChild(QTreeWidgetItem(["Traffic Class: "+str(hex(packet[IPv6].tc))]))
            ip.addChild(QTreeWidgetItem(["Flow Label: "+str(hex(packet[IPv6].fl))]))
            ip.addChild(QTreeWidgetItem(["Payload Length: "+str(packet[IPv6].plen)]))
            ip.addChild(QTreeWidgetItem(["Next Header: "+str(packet[IPv6].nh) + '(' + nh_field.i2s[packet[IPv6].nh].upper() + ')']))
            ip.addChild(QTreeWidgetItem(["Hop Limit: "+str(packet[IPv6].hlim)]))
            self.analysis.addTopLevelItem(ip)

        if TCP in packet:
            tp = QTreeWidgetItem(["Transport Control Protocol"])
            tp.addChild(QTreeWidgetItem(['Source Port: ' + str(packet[TCP].sport)]))
            tp.addChild(QTreeWidgetItem(['Destination Port: ' + str(packet[TCP].dport)]))
            tp.addChild(QTreeWidgetItem(['Sequence Number: ' + str(packet[TCP].seq)]))
            tp.addChild(QTreeWidgetItem(['Acknowledgment Number: ' + str(packet[TCP].ack)]))
            tp.addChild(QTreeWidgetItem(['Header Length: ' + str(packet[TCP].dataofs)]))
            temp = ""
            for k in packet[TCP].flags:
                if k == 'C': temp += 'CWR,'
                if k == 'E': temp += 'ECE,'
                if k == 'U': temp += 'URG,'
                if k == 'A': temp += 'ACK,'
                if k == 'P': temp += 'PSH,'
                if k == 'R': temp += 'RST,'
                if k == 'S': temp += 'SYN,'
                if k == 'F': temp += 'FIN,'
            tp.addChild(QTreeWidgetItem(['Flags: ' + temp[:-1]]))
            tp.addChild(QTreeWidgetItem(['Windows Size: ' + str(packet[TCP].window)]))
            tp.addChild(QTreeWidgetItem(['Checksum: ' + str(hex(packet[TCP].chksum))]))
            tp.addChild(QTreeWidgetItem(['Urgent Pointer: ' + str(hex(packet[TCP].urgptr))]))
            self.analysis.addTopLevelItem(tp)
        elif UDP in packet:
            tp = QTreeWidgetItem(['User Datagram Protocol'])
            tp.addChild(QTreeWidgetItem(['Source Port: ' + str(packet[UDP].sport)]))
            tp.addChild(QTreeWidgetItem(['Destination Port: ' + str(packet[UDP].dport)]))
            tp.addChild(QTreeWidgetItem(['Length: ' + str(packet[UDP].len)]))
            tp.addChild(QTreeWidgetItem(['Checksum: ' + str(hex(packet[UDP].chksum))]))
            self.analysis.addTopLevelItem(tp)
        elif ICMP in packet:
            type_field = ICMP().get_field('type')
            tp = QTreeWidgetItem(['Internet Control Message Protocol'])
            tp.addChild(QTreeWidgetItem(['Type: ' + str(packet[ICMP].type) + '(' + type_field.i2s[packet[ICMP].type] +')']))
            tp.addChild(QTreeWidgetItem(['Code: ' + str(packet[ICMP].code)]))
            tp.addChild(QTreeWidgetItem(['Checksum: ' + str(hex(packet[ICMP].chksum))]))
            self.analysis.addTopLevelItem(tp)

    def filter(self):
        if self.filterFlag == True:
            for i in range(0,self.summary.rowCount()):
                self.summary.showRow(i)
        self.filterFlag = True
        temp = self.filterLine.text()
        if temp == '':
            self.filterFlag = False
            return
        temp = temp.replace(' ','')
        cmd = temp[:temp.find('=')]
        target = temp[temp.find('=')+1:]
        chk = None
        for i in range(0,self.summary.rowCount()):
            ptc = self.summary.item(i,2).text().lower()
            if 'src' in cmd:
                chk = self.summary.item(i,1).text()
            elif 'dst' in cmd:
                chk = self.summary.item(i,3).text()
            if (chk == target):
                self.summary.hideRow(i)
                continue
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
      
    def save(self):
        dialog = QFileDialog()
        dialog.setAcceptMode(QFileDialog.AcceptSave)
        dialog.setFileMode(QFileDialog.AnyFile)
        dialog.setViewMode(QFileDialog.Detail)
        fileName = dialog.getSaveFileName()
        if (fileName[0] != "") and (len(self.packet) != 0):
            _ = wrpcap(fileName[0],self.packet)

    def onlineSniff(self):
        self.packet = []
        self.summary.setRowCount(0)
        self.count = 0
        self.select = QDialog()
        self.select = uic.loadUi('select.ui')
        for i in get_windows_if_list():
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
            self.city = self.select.City.currentText()
            ifname = self.select.networkIF.currentText()
            try:
                sth = sniff(iface=IFACES.dev_from_name(ifname),count=1)
            except scapy.error.Scapy_Exception:
                QMessageBox.information(self,"Interface Invalid","Cannot get pcap from this interface.")
                return
            self.locallat = float(location.loc[location['city_ascii'] == self.city]['lat'])
            self.locallon = float(location.loc[location['city_ascii'] == self.city]['lng'])
            self.threadpool = QThreadPool()
            thread = packetsniff(ifname)
            thread.signals.doneSignal.connect(self.updateOnline)
            self.sniffStop.clicked.connect(thread.stop)
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
        dialog = QFileDialog()
        dialog.setAcceptMode(QFileDialog.AcceptOpen)
        dialog.setFileMode(QFileDialog.ExistingFile)
        dialog.setViewMode(QFileDialog.Detail)
        while True:
            url = dialog.getOpenFileName()
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
                    self.city = self.select.City.currentText()
                    self.locallat = float(location.loc[location['city_ascii'] == self.city]['lat'])
                    self.locallon = float(location.loc[location['city_ascii'] == self.city]['lng'])
                    self.packet = sniff(offline = url[0])
                    self.updateOffline()
                break
            elif len(url[0]) == 0:
                break
            else:
                QMessageBox.information(self,"File Extension Error","Only Accept .pcap file")

    def geoGet(self):
        temp  = []
        repeat_ip = []
        for i in self.packet:
            if IP in i:
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
        url = 'http://api.ipstack.com/{}?access_key=1bdea4d0bf1c3bf35c4ba9456a357ce3'
        res = requests.get(url.format(ip))
        data = res.json()
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        country = data.get('city')
        return latitude,longitude,country

    def isNat(self,ip):
        ipnum = [int(i) for i in ip.split('.')]
        if (ipnum[0] == 10): return 
        elif ((ipnum[0] == 172) and (ipnum[1]>=16 and ipnum[1]<32)): return
        elif ((ipnum[0] == 192) and (ipnum[1] == 168)): return
        else: return ip
    
    def flowPredictStart(self):
        from FlowCheck.dl import FlowPredict
        self.statusbar.showMessage("Predict Flow...")
        self.threadpool = QThreadPool()
        thread = FlowPredict(self.packet)
        thread.signal.doneSignal.connect(self.flowPredictEnd)
        self.threadpool.start(thread)

    def flowPredictEnd(self):
        self.statusbar.showMessage("Done!",2000)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = Main()
    window.show()
    sys.exit(app.exec_())