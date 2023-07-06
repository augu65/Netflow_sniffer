from flask import Flask, render_template, request
import psutil
from sniff import Sniffer, AnalyzeThread, write_closed_flows, read_protocols
import socket

app = Flask(__name__)
address = psutil.net_if_addrs()
hostname = socket.gethostname()
IPAddr = socket.gethostbyname(hostname)
data = []
for x in address.keys():
    for y in address[x]:
        if IPAddr in y[1]:
            data.append(x)
read_protocols()
@app.route("/")
def home():
    return render_template('index.html', data=data, error_message="")


@app.route('/', methods=['POST'])
def my_form_post():
    print(request.form)

    if "interface" in request.form:
        interface = request.form['interface']
        if interface in data:
            global sniffer
            global analyze
            sniffer = Sniffer(interface="", labels="store_true")
            analyze = AnalyzeThread()
            sniffer.interface = interface
            print("[*] Start sniffing...")
            sniffer.start()
            analyze.start()
            return render_template('interface.html', interface=interface)
        else:
            error = 'Invalid Network Interface. Please try again'
            return render_template('index.html', data=data, error_message=error)

    elif "sniffing_stop" in request.form:
        interface = request.form['sniffing_stop']
        sniffer.join()
        analyze.do_run = False
        analyze.join()
        file = interface+".csv"
        write_closed_flows(file)
        flow_data = read_data(file)
        headers = flow_data[0].split(',')
        flow_data.pop(0)
        flows = []
        for flow in flow_data:
            flow = flow.replace("\n", "")
            flows.append(flow.split(','))
        return render_template('results.html', interface=interface, headers=headers, flows=flows)



def read_data(file):
    fp = open(file, "r")
    flows = fp.readlines()
    fp.close()
    return flows


if __name__ == "__main__":
    app.debug = True
    app.run()
