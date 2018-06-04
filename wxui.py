import wx
import wx.grid as gridlib
from scapy.all import *
import os
import threading

CLI_PATH='/home/wsb/bmv2/targets/simple_switch/sswitch_CLI LBswitch.json'

def do_cmd(CMD):
    os.system('echo %s | %s'%(CMD,CLI_PATH))


class MyFrame(wx.Frame):  
  
    def __init__(self):  
        wx.Frame.__init__(self, parent=None,title="Controller",pos = (0,0), size=(1024,768))
        self.bms=[wx.Bitmap('figure/DIP3%d.png'%(i,),wx.BITMAP_TYPE_PNG) for i in range(4)]
        panel = wx.Panel(self)
        self.panel=panel
        self.bmp = wx.StaticBitmap(parent=panel, bitmap=self.bms[0])  
        self.btnadd= wx.BitmapButton(panel,-1,wx.Bitmap('figure/btnadd.png',wx.BITMAP_TYPE_PNG),(90,90))
        self.btnadd.Bind(wx.EVT_BUTTON,self.update_DIPs)
        self.btnweight= wx.BitmapButton(panel,-1,wx.Bitmap('figure/btnweight.png',wx.BITMAP_TYPE_PNG),(400,90))
        self.btnweight.Bind(wx.EVT_BUTTON,self.update_weights)
        self.btnquit= wx.BitmapButton(panel,-1,wx.Bitmap('figure/btnquit.png',wx.BITMAP_TYPE_PNG),(880,70))
        self.btnquit.Bind(wx.EVT_BUTTON,self.OnQuit)
        self.btnrefreshconntable= wx.BitmapButton(panel,-1,wx.Bitmap('figure/btnrefreshconn.png',wx.BITMAP_TYPE_PNG),(800,500))
        self.btnrefreshconntable.Bind(wx.EVT_BUTTON,self.refresh_conntable)
        self.btnrefreshroutetable= wx.BitmapButton(panel,-1,wx.Bitmap('figure/btnrefreshroute.png',wx.BITMAP_TYPE_PNG),(800,600))
        self.btnrefreshroutetable.Bind(wx.EVT_BUTTON,self.refresh_routetable)
        self.hostinfo= wx.StaticText(panel,-1,"From ",(100,410))
        self.hostinfo.SetForegroundColour("WHITE")
        self.hostinfo.SetFont(wx.Font(20,wx.DECORATIVE,wx.NORMAL,wx.NORMAL))
        self.textweight= wx.TextCtrl(panel,-1,"weights",(240,100),size=(140,50))
        self.entrieslist= wx.ListCtrl(panel,-1,(300,500),(400,200),wx.LC_REPORT)
        self.list_state=0
        self.add_column()
        self.entrynum=0
        self.VER=0
        self.connentrynum=0
        self.routeentrynum=0
        self.hash_const=6
        self.hashes=[]
        self.connentries=[]
        self.routeentries=[]
        self.weights=[2,0,1,1,0,2]
        for i in range(len(self.weights)):
            self.routeentries.append([self.routeentrynum,"%d"%(self.VER,),"%d"%(i,),"select_dip",self.weights[i]])
            self.routeentrynum+=1
        self.t1=threading.Thread(target=self.data_plane)
        self.t1.setDaemon(True)
        self.t1.start()
        self.Centre()
        self.Show(True)

    def add_column(self):
        if self.list_state==0:
            self.entrieslist.AppendColumn("entry",wx.LIST_FORMAT_LEFT,50)
            self.entrieslist.AppendColumn("hash",wx.LIST_FORMAT_LEFT,150)
            self.entrieslist.AppendColumn("action",wx.LIST_FORMAT_LEFT,100)
            self.entrieslist.AppendColumn("version",wx.LIST_FORMAT_LEFT,100)
        else:
            self.entrieslist.AppendColumn("entry",wx.LIST_FORMAT_LEFT,50)
            self.entrieslist.AppendColumn("version",wx.LIST_FORMAT_LEFT,75)
            self.entrieslist.AppendColumn("hash mod",wx.LIST_FORMAT_LEFT,75)
            self.entrieslist.AppendColumn("action",wx.LIST_FORMAT_LEFT,100)
            self.entrieslist.AppendColumn("DIP index",wx.LIST_FORMAT_LEFT,100)
    def change_image(self,k):
        self.bmp.SetBitmap(self.bms[k])

    def data_plane(self):
        sniff(iface = "veth11",
             prn = lambda x: self.handle_pkt(x))

    def refresh_conntable(self, event):
        self.list_state=0
        self.entrieslist.ClearAll()
        self.add_column()
        for i in self.connentries:
            self.entrieslist.Append(i)

    def refresh_routetable(self, event):
        self.list_state=1
        self.entrieslist.ClearAll()
        self.add_column()

        for i in self.routeentries:
            self.entrieslist.Append(i)

    def load_weights(self, args):
        self.VER+=1
        f=open('temp_commands.txt','w')
        i=0
        for arg in args:
            f.write('table_add route_table select_dip %d %d => %d\n'%(i,self.VER,arg))
            i+=1
        f.write('register_write version_register 0 %d\n'%(self.VER,))
        f.close()
        os.system('%s < %s'%(CLI_PATH, 'temp_commands.txt'))

    def update_DIPs(self,event):
        self.bms=[wx.Bitmap('figure/DIP4%d.png'%(i,),wx.BITMAP_TYPE_PNG) for i in range(5)]
        self.bmp.SetBitmap(self.bms[0])

    def update_weights(self, event):
        temp=[int(x)-1 for x in self.textweight.GetValue().split(" ")]
        self.load_weights(temp)
        self.weights=temp
        for i in range(len(temp)):
            self.routeentries.append([self.routeentrynum,"%d"%(self.VER,),"%d"%(i,),"select_dip",self.weights[i]])
            self.routeentrynum+=1


    def OnQuit(self, event):
        self.Close()   

    def handle_pkt(self, pkt):
        if IP in pkt and TCP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            id_tup = (src_ip, dst_ip, proto, sport, dport)
            res_dst=bytes(pkt)[:6]
            res_src=bytes(pkt)[6:12]
            if int.from_bytes(res_src,byteorder='big')==723:
                hash_res=int.from_bytes(res_dst,byteorder='big')
                if not (hash_res in self.hashes):
                    self.hashes.append(hash_res)
                    CMD="'table_add version_table select_version %d => %d'"%(hash_res,self.VER)
                    do_cmd(CMD)
                    self.change_image(self.weights[hash_res%self.hash_const]+1)
                    _entry=[self.connentrynum,"0x%x"%(hash_res,),"select_version",self.VER]
                    self.connentries.append(_entry)
                    if self.list_state==0:
                        wx.CallAfter(self.entrieslist.Append,_entry)
                    wx.CallAfter(self.hostinfo.SetLabel,"From %s:%s"%(src_ip,sport))
                    self.connentrynum+=1

if __name__ == '__main__':
    app = wx.App()  
    frame = MyFrame()  
    app.MainLoop() 
