import tkinter 

windows = tkinter.Tk()
windows.title('流量识别')
windows.geometry('800x600')

def func0():
    string0.set(entry0.get())

#按钮
botton0 = tkinter.Button(windows, text = '显示图像', font=('Arial, 20'), width = 20, height=3, command=func0)
botton0.pack()

#用tkinter函数初始化字符串变量
string0 = tkinter.StringVar()
label0 = tkinter.Label(windows, textvariable=string0,font=('Arial, 20'), width=75, height=2)
label0.pack()

entry0 = tkinter.Entry(windows)
entry0.pack()

#enter0 

windows.mainloop()