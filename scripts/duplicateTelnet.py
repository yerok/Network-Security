from scapy.all import *


interface = raw_input("Desired Interface: ")

print 'Starting sniff'

def packet_callback(packet):
    print '[*] %s' %packet.payload

sniff(filter="port telnet", prn=packet_callback, store=0)	x