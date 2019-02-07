from scapy.all import *

#I used this command to check the attack first
#tcpdump -i eth0 -n host 185.174.168.47

victimIP = raw_input("Victim IP: ")

print 'Starting sniffer for DNS queries'
bpf_filter = 'udp and port 53 and ip host '+ victimIP

packets = sniff(filter=bpf_filter, timeout=30,  prn = lambda x:x.summary())
wrpcap('resultsDNS.pcap', packets)
