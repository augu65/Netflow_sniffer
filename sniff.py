#########################
#This file sniffs the given interface and analyzes the packets 
#By: Jonah Stegman
#########################

from scapy.all import *
from threading import Thread, Event
from time import sleep
import json
import argparse
from flow import flow

# holds all the flows
flows = []

#sets timeout for a flow
global_timeout = 60

class Sniffer(Thread):
  def  __init__(self, interface="eth0"):
    super().__init__()

    self.daemon = True

    self.socket = None
    self.interface = interface
    self.stop_sniffer = Event()

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
      new_thread = Thread(target = in_flow,args= (f,))
      new_thread.start()
      new_thread.join()
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

def in_flow(flow_temp):
  flag = False
  for flow in flows:
    if not flow.fin:
      close_timeout_flows(flow)
      if flow.proto == flow_temp.proto and flow.src == flow_temp.src and flow.dst == flow_temp.dst and flow.src_port == flow_temp.src_port and flow.dst_port == flow_temp.dst_port:
        flow.total_packets()
        flow.direction_forward()
        flow.total_bytes(flow_temp.tot_bytes)
        flow.source_bytes(flow_temp.tot_bytes)
        flow.duration(flow_temp.start)
        flow.last_seen = flow_temp.start
        flag = True
        if flow_temp.fin:
          flow.fin = True
        break
      elif flow.proto == flow_temp.proto and flow.src == flow_temp.dst and flow.dst == flow_temp.src and flow.dst_port == flow_temp.src_port and flow.dst_port == flow_temp.src_port:
        flow.total_packets()
        flow.direction_backward()
        flow.total_bytes(flow_temp.tot_bytes)
        flow.duration(flow_temp.start)
        flow.last_seen = flow_temp.start
        flag = True
        if flow_temp.fin:
          flow.fin = True
        break
  if not flag and not flow_temp.fin:
    flow_temp.source_bytes(flow_temp.tot_bytes)
    flow_temp.direction_forward()
    flows.append(flow_temp)

def get_proto(proto):
  with open('Netflow_sniffer/protocols.json') as f:
    data = json.load(f)
    try:
      return data[str(proto)]
    except KeyError:
      return proto

def write_closed_flows():
  keys ='StartTime,Dur,Proto,SrcAddr,Dir,DstAddr,TotPkts,TotBytes,SrcBytes\n'
  with open('flows.csv', 'w', newline='') as output_file:
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

def main():
  global global_timeout
  parser = argparse.ArgumentParser()
  parser.add_argument("--interface", help="select the network interface to sniff", default="eth0")
  parser.add_argument("--file", help="Enter the filename and path of where the flows will be stored", default="flows.csv")
  parser.add_argument("--timeout", help="set the timeout in Minutes for network connections", type=int, default=60)
  args = parser.parse_args()
  global_timeout =args.timeout
  if(args.interface):
    sniffer = Sniffer(interface=args.interface)
  else:
    print("No Interface provided using default eth0")
    sniffer = Sniffer()
  print("[*] Start sniffing...")
  sniffer.start()
  try:
    while True:
      sleep(100)
  except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join()
    write_closed_flows()

if __name__ == "__main__":
  main()