from scapy.all import *


interface = raw_input("Desired Interface: ")

print 'Starting sniff'

packets = sniff(filter='port telnet', iface=interface,  prn = lambda x:x.summary())
wrpcap('results.pcap', packets)

