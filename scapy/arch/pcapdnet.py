## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Packet sending and receiving with libdnet and libpcap/WinPcap.
"""

import time,struct,sys
if not sys.platform.startswith("win"):
    from fcntl import ioctl
from scapy.data import *
from scapy.config import conf
from scapy.utils import warning
from scapy.supersocket import SuperSocket
from scapy.error import Scapy_Exception
import scapy.arch

if conf.use_dnet:
  try:
    from .cdnet import *
  except OSError as e:
    if conf.interactive:
      log_loading.error("Unable to import libdnet library: %s" % e)
      conf.use_dnet = False
    else:
      raise

if conf.use_winpcapy:
  try:
    from .winpcapy import *
  except OSError as e:
    if conf.interactive:
      log_loading.error("Unable to import libpcap library: %s" % e)
      conf.use_winpcapy = False
    else:
      raise

  # From BSD net/bpf.h
  #BIOCIMMEDIATE=0x80044270
  BIOCIMMEDIATE=-2147204496

  class PcapTimeoutElapsed(Scapy_Exception):
      pass
    
if conf.use_netifaces:
  try:
    import netifaces
  except ImportError as e:
    log_loading.warning("Could not load module netifaces: %s" % e)
    conf.use_netifaces = False

if conf.use_netifaces:
  def get_if_raw_hwaddr(iff):
      if iff == scapy.arch.LOOPBACK_NAME:
          return (772, '\x00'*6)
      try:
          s = netifaces.ifaddresses(iff)[netifaces.AF_LINK][0]['addr']
          return struct.pack('BBBBBB', *[ int(i, 16) for i in s.split(':') ])
      except:
          raise Scapy_Exception("Error in attempting to get hw address for interface [%s]" % iff)
      return l
  def get_if_raw_addr(ifname):
      try:
        s = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
        return socket.inet_aton(s)
      except:
        return None
  def get_if_list():
      #return [ i[1] for i in socket.if_nameindex() ]
      return netifaces.interfaces()

elif conf.use_dnet:
  intf = dnet_intf()
  def get_if_raw_hwaddr(iff):
      return bytes(intf.get(iff)['link_addr'])
  def get_if_raw_addr(iff):
      return bytes(intf.get(iff)['addr'])
  def get_if_list():
      return intf.names

else:
  log_loading.warning("No known method to get ip and hw address for interfaces")
  def get_if_raw_hwaddr(iff):
      "dummy"
      return b"\0\0\0\0\0\0"
  def get_if_raw_addr(iff):
      "dummy"
      return b"\0\0\0\0"
  def get_if_list():
      "dummy"
      return []

if conf.use_winpcapy:
  from ctypes import POINTER, byref, create_string_buffer
  class _PcapWrapper_pypcap:
      def __init__(self, device, snaplen, promisc, to_ms):
          self.errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
          self.iface = create_string_buffer(device.encode('ascii'))
          self.pcap = pcap_open_live(self.iface, snaplen, promisc, to_ms, self.errbuf)
          self.header = POINTER(pcap_pkthdr)()
          self.pkt_data = POINTER(c_ubyte)()
          self.bpf_program = bpf_program()
      def next(self):
          c = pcap_next_ex(self.pcap, byref(self.header), byref(self.pkt_data))
          if not c > 0:
              return
          ts = self.header.contents.ts.tv_sec
          #pkt = "".join([ chr(i) for i in self.pkt_data[:self.header.contents.len] ])
          pkt = bytes(self.pkt_data[:self.header.contents.len])
          return ts, pkt
      def datalink(self):
          return pcap_datalink(self.pcap)
      def fileno(self):
          if sys.platform.startswith("win"):
            error("Cannot get selectable PCAP fd on Windows")
            return 0
          return pcap_get_selectable_fd(self.pcap) 
      def setfilter(self, f):
          filter_exp = create_string_buffer(f.encode('ascii'))
          if pcap_compile(self.pcap, byref(self.bpf_program), filter_exp, 0, -1) == -1:
            error("Could not compile filter expression %s" % f)
            return False
          else:
            if pcap_setfilter(self.pcap, byref(self.bpf_program)) == -1:
              error("Could not install filter %s" % f)
              return False
          return True
      def setnonblock(self, i):
          pcap_setnonblock(self.pcap, i, self.errbuf)
      def close(self):
          pcap_close(self.pcap)
  open_pcap = lambda *args,**kargs: _PcapWrapper_pypcap(*args,**kargs)
  class PcapTimeoutElapsed(Scapy_Exception):
      pass

  class L2pcapListenSocket(SuperSocket):
      desc = "read packets at layer 2 using libpcap"
      def __init__(self, iface = None, type = ETH_P_ALL, promisc=None, filter=None):
          self.type = type
          self.outs = None
          self.iface = iface
          if iface is None:
              iface = conf.iface
          if promisc is None:
              promisc = conf.sniff_promisc
          self.promisc = promisc
          self.ins = open_pcap(iface, 1600, self.promisc, 100)
          try:
              ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
          except:
              pass
          if type == ETH_P_ALL: # Do not apply any filter if Ethernet type is given
              if conf.except_filter:
                  if filter:
                      filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                  else:
                      filter = "not (%s)" % conf.except_filter
              if filter:
                  self.ins.setfilter(filter)
  
      def close(self):
          self.ins.close()
          
      def recv(self, x=MTU):
          ll = self.ins.datalink()
          if ll in conf.l2types:
              cls = conf.l2types[ll]
          else:
              cls = conf.default_l2
              warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
  
          pkt = None
          while pkt is None:
              pkt = self.ins.next()
              if pkt is not None:
                  ts,pkt = pkt
              if scapy.arch.WINDOWS and pkt is None:
                  raise PcapTimeoutElapsed
          
          try:
              pkt = cls(pkt)
          except KeyboardInterrupt:
              raise
          except:
              if conf.debug_dissector:
                  raise
              pkt = conf.raw_layer(pkt)
          pkt.time = ts
          return pkt
  
      def send(self, x):
          raise Scapy_Exception("Can't send anything with L2pcapListenSocket")
  

  conf.L2listen = L2pcapListenSocket
    
if conf.use_winpcapy and conf.use_dnet:
    class L3dnetSocket(SuperSocket):
        desc = "read/write packets at layer 3 using libdnet and libpcap"
        def __init__(self, type = ETH_P_ALL, filter=None, promisc=None, iface=None, nofilter=0):
            self.iflist = {}
            self.intf = dnet_intf()
            if iface is None:
                iface = conf.iface
            self.iface = iface
            self.ins = open_pcap(iface, 1600, 0, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            if nofilter:
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    filter = "ether proto %i" % type
                else:
                    filter = None
            else:
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    if filter:
                        filter = "(ether proto %i) and (%s)" % (type,filter)
                    else:
                        filter = "ether proto %i" % type
            if filter:
                self.ins.setfilter(filter)
        def send(self, x):
            iff,a,gw  = x.route()
            if iff is None:
                iff = conf.iface
            ifs,cls = self.iflist.get(iff,(None,None))
            if ifs is None:
                iftype = self.intf.get(iff)["type"]
                if iftype == INTF_TYPE_ETH:
                    try:
                        cls = conf.l2types[1]
                    except KeyError:
                        warning("Unable to find Ethernet class. Using nothing")
                    ifs = dnet_eth(iff)
                else:
                    ifs = dnet_ip()
                self.iflist[iff] = ifs,cls
            if cls is None:
                #sx = str(x)
                sx = x.bytes()
            else:
                sx = (cls()/x).bytes()
            x.sent_time = time.time()
            ifs.send(sx)
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
    
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
    
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt.payload
    
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv()
            self.ins.setnonblock(0)
            return p
    
        def close(self):
            if hasattr(self, "ins"):
                self.ins.close()
            if hasattr(self, "outs"):
                self.outs.close()
    
    class L2dnetSocket(SuperSocket):
        desc = "read/write packets at layer 2 using libdnet and libpcap"
        def __init__(self, iface = None, type = ETH_P_ALL, filter=None, nofilter=0):
            if iface is None:
                iface = conf.iface
            self.iface = iface
            self.ins = open_pcap(iface, 1600, 0, 100)
            try:
                ioctl(self.ins.fileno(),BIOCIMMEDIATE,struct.pack("I",1))
            except:
                pass
            if nofilter:
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    filter = "ether proto %i" % type
                else:
                    filter = None
            else:
                if conf.except_filter:
                    if filter:
                        filter = "(%s) and not (%s)" % (filter, conf.except_filter)
                    else:
                        filter = "not (%s)" % conf.except_filter
                if type != ETH_P_ALL:  # PF_PACKET stuff. Need to emulate this for pcap
                    if filter:
                        filter = "(ether proto %i) and (%s)" % (type,filter)
                    else:
                        filter = "ether proto %i" % type
            if filter:
                self.ins.setfilter(filter)
            self.outs = dnet_eth(iface)
        def recv(self,x=MTU):
            ll = self.ins.datalink()
            if ll in conf.l2types:
                cls = conf.l2types[ll]
            else:
                cls = conf.default_l2
                warning("Unable to guess datalink type (interface=%s linktype=%i). Using %s" % (self.iface, ll, cls.name))
    
            pkt = self.ins.next()
            if pkt is not None:
                ts,pkt = pkt
            if pkt is None:
                return
            
            try:
                pkt = cls(pkt)
            except KeyboardInterrupt:
                raise
            except:
                if conf.debug_dissector:
                    raise
                pkt = conf.raw_layer(pkt)
            pkt.time = ts
            return pkt
    
        def nonblock_recv(self):
            self.ins.setnonblock(1)
            p = self.recv(MTU)
            self.ins.setnonblock(0)
            return p
    
        def close(self):
            if hasattr(self, "ins"):
                self.ins.close()
            if hasattr(self, "outs"):
                self.outs.close()

    conf.L3socket=L3dnetSocket
    conf.L2socket=L2dnetSocket

        

