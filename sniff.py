#########################
#This file sniffs the given interface and analyzes the packets 
#By: Jonah Stegman
#########################

from scapy.all import *
import threading
from time import sleep
import json
import argparse
import queue
import psutil
from flow import flow

# holds all the flows
flows = []
#holds a dictionary list of all the network protocols
protocols = []
#sets timeout for a flow
global_timeout = 60

BUF_SIZE = 100
q = queue.Queue(BUF_SIZE)

class Sniffer(threading.Thread):
  def __init__(self, interface = None):
    super(Sniffer,self).__init__()
    self.interface = interface
    self.soceket = None
    self.stop_sniffer = threading.Event()

  def run(self):
    try:
      self.socket = conf.L2listen(
        type=ETH_P_ALL,
        iface=self.interface,
        filter="ip"
      )
    except OSError:
      print("Error opening adapter")
      os.abort()

    sniff(
      opened_socket=self.socket,
      prn=self.set_packets,
      stop_filter=self.should_stop_sniffer
    )

  def join(self, timeout=None):
    self.stop_sniffer.set()
    super().join(timeout)

  def should_stop_sniffer(self, packet):
    return self.stop_sniffer.isSet()

  def set_packets(self, packet):
    src_port = ''
    dst_port = ''
    proto = ''
    flag = False
    fin_flag = False
    ip_layer = packet.getlayer('IP')
    if 'TCP' in packet:
      dst_port = packet['TCP'].dport
      src_port = packet['TCP'].sport
      proto = 'TCP'
      if packet['TCP'].flags.S:
        flag = True
      elif packet['TCP'].flags.F or packet['TCP'].flags.R:
        fin_flag = True
    elif 'UDP' in packet:
      dst_port = packet['UDP'].dport
      src_port = packet['UDP'].sport
      proto = 'UDP'
    elif 'ARP' in packet:
      dst_port = packet['ARP'].dport
      src_port = packet['ARP'].sport
      proto = 'ARP'
    else:
      proto = get_proto(ip_layer.proto)
 
    f = flow(ip_layer.src, ip_layer.dst,src_port,dst_port,proto,packet.time,len(packet))
    if (not flag and 'TCP' in packet) or ('TCP' not in packet) or (fin_flag and 'TCP' in packet):
      if fin_flag:
        f.fin = True
        q.put(f)
    else:
      f.source_bytes(len(packet))
      f.direction_forward()
      flows.append(f)


def close_timeout_flows(flow):
  global global_timeout
  if (time.time() - flow.last_seen)/60 % 60 >=  global_timeout:
    flow.fin = True
    if flow.proto == 'TCP':
      if len(flow.dir)>1:
        flow.dir = flow.dir[:1] + "?" + flow.dir[1:]
      else:
        flow.dir = "?" + flow.dir[:1]



def get_proto(proto):
  try:
    return protocols[str(proto)]
  except KeyError:
    return proto

def write_closed_flows(file):
  keys ='StartTime,Dur,Proto,SrcAddr,Dir,DstAddr,TotPkts,TotBytes,SrcBytes\n'
  with open(file, 'w', newline='') as output_file:
    output_file.write(keys)
    for data in flows:
      if not data.fin and data.proto == 'TCP':
        if len(data.dir)>1:
          data.dir = data.dir[:1] + "?" + data.dir[1:]
        else:
          data.dir = "?" + data.dir[:1]
      else:
        if len(data.dir)>1:
          data.dir = data.dir[:1] + "-" + data.dir[1:]
        else:
          data.dir = "-" + data.dir[:1]
      output_file.write(str(data.print_flow()))

class AnalyzeThread(threading.Thread):
  def __init__(self):
    super(AnalyzeThread,self).__init__()
    self.stop_sniffer = threading.Event()
    self.item = None
    return

  def run(self):
    while True:
      if not q.empty():
        self.item = q.get()
        self.in_flow
    return

  def in_flow(self):
    flag = False
    for flow in flows:
      if not flow.fin:
        close_timeout_flows(flow)
        if flow.proto == self.item.proto and flow.src == self.item.src and flow.dst == self.item.dst and flow.src_port == self.item.src_port and flow.dst_port == self.item.dst_port:
          flow.total_packets()
          flow.direction_forward()
          flow.total_bytes(self.item.tot_bytes)
          flow.source_bytes(self.item.tot_bytes)
          flow.duration(self.item.start)
          flow.last_seen = self.item.start
          flag = True
          if self.item.fin:
            flow.fin = True
          break
        elif flow.proto == self.item.proto and flow.src == self.item.dst and flow.dst == self.item.src and flow.dst_port == self.item.src_port and flow.dst_port == self.item.src_port:
          flow.total_packets()
          flow.direction_backward()
          flow.total_bytes(self.item.tot_bytes)
          flow.duration(self.item.start)
          flow.last_seen = self.item.start
          flag = True
          if self.item.fin:
            flow.fin = True
          break
    if not flag and not self.item.fin:
      self.item.source_bytes(self.item.tot_bytes)
      self.item.direction_forward()
      flows.append(self.item)


def main():
  global global_timeout
  global protocols
  with open('./protocols.json') as f:
    protocols = json.load(f)
  parser = argparse.ArgumentParser()
  parser.add_argument("--interface", help="select the network interface to sniff")
  parser.add_argument("--file", help="Enter the filename and path of where the flows will be stored", default="flows.csv")
  parser.add_argument("--timeout", help="set the timeout in Minutes for network connections", type=int, default=60)
  args = parser.parse_args()
  global_timeout = args.timeout
  
  if args.interface:
    sniffer = Sniffer(interface=args.interface)
  else:
    addrs = psutil.net_if_addrs()
    print("Please select a network interface:")
    for key in addrs.keys():
      print(key)
    interface =input('>')
    sniffer = Sniffer(interface=interface)

  analyze = AnalyzeThread()
  try:
    print("[*] Start sniffing...")
    sniffer.start()
    analyze.start()
    while True:
      sleep(100)
  except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join()
    analyze.join()
    write_closed_flows(args.file)


if __name__ == "__main__":
  main()