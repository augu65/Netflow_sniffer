from flask import Flask, render_template, request
import psutil
from sniff import Sniffer, AnalyzeThread, write_closed_flows, read_protocols
import signal
app = Flask(__name__)
address = psutil.net_if_addrs()
data = address.keys()
read_protocols()
sniffer =Sniffer(interface="", labels="store_true")
analyze = AnalyzeThread()
@app.route("/")
def home():

    return render_template('index.html', data=data, error_message="")

@app.route('/', methods=['POST'])
def my_form_post():
    if "interface" in request.form:
        interface = request.form['interface']
        if interface in data:
            sniffer.interface = interface
            print("[*] Start sniffing...")
            sniffer.start()
            analyze.start()
            return render_template('interface.html', interface=interface)
        else:
            error = 'Invalid Network Interface. Please try again'
            return render_template('index.html',  data=data, error_message=error)
    elif "sniffing_stop" in request.form:
        sniffer.join()
        analyze.do_run = False
        analyze.join()
        write_closed_flows("flow2.csv")
        flows = read_data()
        return render_template('results.html', flows=flows)


def read_data():
    fp = open("flow2.csv", "r")
    flows = fp.readlines()
    fp.close()
    return flows
if __name__ == "__main__":
    app.debug = True
    app.run()
