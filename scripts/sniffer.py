from scapy.all import *

packet_count = raw_input("numer of packets : ")
interface = raw_input("Desired Interface: ")
victimIP = raw_input("Victim IP: ")

print 'Starting sniffer for %d packets' %packet_count
bpf_filter = 'IP host ' + victimIP

packets = sniff(iface='interface', timeout=10, count=packet_count,  prn = lambda x:x.summary())
wrpcap('results.pcap', packets)

