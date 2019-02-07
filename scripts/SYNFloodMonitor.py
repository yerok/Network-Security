from scapy.all import *

#I used this command to check the attack first
# netstat -antp
#his command will show you all the connections on your system
#-a all
#-n show ip instead of host names
#-t show only tcp connections
#-p show process id/name

victimIP = raw_input("Victim IP: ")

print 'Starting sniffer for TCP/SYN packets'
bpf_filter = 'tcp and ip host ' + victimIP

packets = sniff(filter=bpf_filter, timeout=30,  prn = lambda x:x.summary())
wrpcap('resultsSYNFlood.pcap', packets)

