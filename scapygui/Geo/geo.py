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
        for i in packet:
            #如果是私有地址（None）则改为当前所在位置
            plt.plot(i[0],i[1], color='red',transform=ccrs.PlateCarree())
            plt.text(i[0][0]-3,i[1][0]-3,i[2],fontsize=7,transform=ccrs.Geodetic())
            plt.text(i[0][1]-3,i[1][1]-3,i[3],fontsize=7,transform=ccrs.Geodetic())
            plt.pause(0.01)
        super(plotFlow,self).__init__(fig)