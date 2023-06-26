#########################
# This file sniffs the given interface and analyzes the packets
# By: Jonah Stegman
#########################

from scapy.all import *
import threading
from time import sleep
import json
import argparse
import queue
import psutil
from flow import Flow

# holds all the flows
flows = []
# holds a dictionary list of all the network protocols
protocols = []
# sets timeout for a flow
global_timeout = 60

BUF_SIZE = 100
q = queue.Queue(BUF_SIZE)


class Sniffer(threading.Thread):
    def __init__(self, interface=None, labels=False):
        super(Sniffer, self).__init__()
        self.interface = interface
        self.socket = None
        self.labels = labels
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

    def should_stop_sniffer(self, pkt):
        return self.stop_sniffer.isSet()

    def set_packets(self, pkt):
        src_port = ''
        dst_port = ''
        proto = ''
        flag = False
        fin_flag = False
        ip_layer = pkt.getlayer('IP')
        if 'TCP' in pkt:
            dst_port = pkt['TCP'].dport
            src_port = pkt['TCP'].sport
            proto = 'TCP'
            if pkt['TCP'].flags.S:
                flag = True
            elif pkt['TCP'].flags.F or pkt['TCP'].flags.R:
                fin_flag = True
        elif 'UDP' in pkt:
            dst_port = pkt['UDP'].dport
            src_port = pkt['UDP'].sport
            proto = 'UDP'
        elif 'ARP' in pkt:
            dst_port = pkt['ARP'].dport
            src_port = pkt['ARP'].sport
            proto = 'ARP'
        else:
            proto = get_proto(ip_layer.proto)
        f = Flow(ip_layer.src, ip_layer.dst, src_port, dst_port, proto, pkt.time, len(pkt))
        if self.labels:
            f.labels()
        if (not flag and 'TCP' in pkt) or ('TCP' not in pkt) or (fin_flag and 'TCP' in pkt):
            if fin_flag:
                f.fin = True
            q.put(f)
        else:
            f.source_bytes(len(pkt))
            f.direction_forward()
            flows.append(f)


def close_timeout_flows(pkt_flow):
    global global_timeout
    if (time.time() - pkt_flow.last_seen) / 60 % 60 >= global_timeout:
        pkt_flow.fin = True
        if pkt_flow.proto == 'TCP':
            if len(pkt_flow.dir) > 1:
                pkt_flow.dir = pkt_flow.dir[:1] + "?" + pkt_flow.dir[1:]
            else:
                pkt_flow.dir = "?" + pkt_flow.dir[:1]


def get_proto(proto):
    try:
        return protocols[str(proto)]
    except KeyError:
        return proto


def write_closed_flows(file):
    k_flag = True
    keys = 'StartTime,Dur,Proto,SrcAddr,Dir,DstAddr,TotPkts,TotBytes,SrcBytes,Label\n'
    if os.path.isfile(file):
        k_flag = False
    with open(file, 'a', newline='') as output_file:
        if k_flag:
            output_file.write(keys)
        for data in flows:
            if not data.fin and data.proto == 'TCP':
                if len(data.dir) > 1:
                    data.dir = data.dir[:1] + "?" + data.dir[1:]
                else:
                    data.dir = "?" + data.dir[:1]
            else:
                if len(data.dir) > 1:
                    data.dir = data.dir[:1] + "-" + data.dir[1:]
                else:
                    data.dir = "-" + data.dir[:1]
            output_file.write(str(data.print_flow()))


class AnalyzeThread(threading.Thread):
    def __init__(self):
        super(AnalyzeThread, self).__init__()
        self.stop_sniffer = threading.Event()
        self.item = None
        return

    def run(self):
        analyze = threading.currentThread()
        while getattr(analyze, "do_run", True) or not q.empty():
            if not q.empty():
                self.item = q.get()
                self.in_flow()
        return

    def in_flow(self):
        flag = False
        for flow in flows:
            if not flow.fin:
                close_timeout_flows(flow)
                if flow.proto == self.item.proto and flow.src == self.item.src and flow.dst == self.item.dst and \
                        flow.src_port == self.item.src_port and flow.dst_port == self.item.dst_port:
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
                elif flow.proto == self.item.proto and flow.src == self.item.dst and flow.dst == self.item.src and \
                        flow.dst_port == self.item.src_port and flow.dst_port == self.item.src_port:
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
    parser.add_argument("--file", help="Enter the filename and path of where the flows will be stored",
                        default="flows.csv")
    parser.add_argument("--timeout", help="set the timeout in Minutes for network connections", type=int, default=60)
    parser.add_argument("--label", help="if provided will try to label flows to applications", action='store_true')
    arguments = parser.parse_args()
    global_timeout = arguments.timeout
    if arguments.interface:
        sniffer = Sniffer(interface=arguments.interface, labels=arguments.label)
    else:
        addrs = psutil.net_if_addrs()
        print("Please select a network interface:")
        for key in addrs.keys():
            print(key)
        interface = None
        while interface not in addrs.keys():
            interface = input('>')
            if interface not in addrs.keys():
                print("Invalid Interface")
        sniffer = Sniffer(interface=interface, labels=arguments.label)
    analyze = AnalyzeThread()
    print("[*] Start sniffing...")
    sniffer.start()
    analyze.start()
    try:
        while True:
            sleep(100)
    except KeyboardInterrupt:
        print("[*] Stop sniffing")
        sniffer.join()
        analyze.do_run = False
        analyze.join()
        write_closed_flows(arguments.file)


if __name__ == "__main__":
    main()
