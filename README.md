# Netflow_sniffer

Some code was used from [skyplabs](https://blog.skyplabs.net/2018/03/01/python-sniffing-inside-a-thread-with-scapy/)

The netflow sniffer uses scapy to sniff all of the packets on the given interface and convert them into netflows.
These flows are then written to a csv file for more analysis

## Run
python sniff.py [args]

## Command line paramaters
* --interface : Allows for the selection of which network interface to sniff on 
* --file : Allows for the file/filepath to be specified
* --timeout : Allows for the timeout of a flow to be specified

### NOTE: The sniff.py file must be run with administrator permissions.
