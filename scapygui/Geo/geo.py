import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
import cartopy.crs as ccrs

class plotFlow(FigureCanvasQTAgg):
    def __init__(self,packet):
        fig = matplotlib.pyplot.figure(figsize=(9, 5), dpi=150)
        ax = matplotlib.pyplot.axes(projection=ccrs.Robinson())
        ax.set_global()
        ax.coastlines()
        lineplot = []
        textplot = []
        for i in packet:
            if (i[0],i[1]) not in lineplot:
                matplotlib.pyplot.plot(i[0],i[1], color='red',transform=ccrs.PlateCarree())
                lineplot.append((i[0],i[1]))
            if (i[0][0],i[1][0],i[2]) not in textplot:
                matplotlib.pyplot.text(i[0][0]-3,i[1][0]-3,i[2],fontsize=7,bbox={'facecolor':'yellow','pad':1},transform=ccrs.Geodetic())
                textplot.append((i[0][0],i[0][1],i[2]))
            if (i[0][1],i[1][1],i[3]) not in textplot:
                matplotlib.pyplot.text(i[0][1]-3,i[1][1]-3,i[3],fontsize=7,bbox={'facecolor':'yellow','pad':1},transform=ccrs.Geodetic())
                textplot.append((i[0][1],i[1][1],i[3]))
            matplotlib.pyplot.pause(0.01)
        super(plotFlow,self).__init__(fig)