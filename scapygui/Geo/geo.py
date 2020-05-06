import cartopy.crs as ccrs
import matplotlib
matplotlib.use('Qt5Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg

class plotFlow(FigureCanvasQTAgg):
    def __init__(self,packet):
        fig = plt.figure(figsize=(9, 5), dpi=150)
        ax = plt.axes(projection=ccrs.Robinson())
        ax.set_global()
        ax.coastlines()
        #自身所在经纬度（暂定，该位置位于马来西亚）
        locallat = 1.8504
        locallon = 102.933
        for i in packet:
            #如果是私有地址（None）则改为当前所在位置
            if i[0][0] != None: slat,slon = i[0]
            else: slat,slon = locallat,locallon
            if i[1][0] != None:  dlat,dlon = i[1]
            else:  dlat,dlon = locallat,locallon
            plt.plot([slon,dlon],[slat,dlat], color='red',transform=ccrs.PlateCarree())
            plt.pause(0.01)
        super(plotFlow,self).__init__(fig)