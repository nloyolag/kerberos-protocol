import sys
import scapy.all as scapy
from pprint import pprint

pkts = scapy.rdpcap("package.pcap")

seq = []
for p in pkts:
	# scapy.ls(p)
	if p.haslayer(scapy.TCP)==1:
		p[scapy.TCP].fields.update({'src':p[scapy.IP].fields['src']})
		p[scapy.TCP].fields.update({'dst':p[scapy.IP].fields['dst']})

		seq.append(p[scapy.TCP].fields)
	# if p.haslayer(scapy.UDP)==1:
		# p[scapy.UDP].fields.update({'src':p[scapy.IP].fields['src']})
		# p[scapy.UDP].fields.update({'dst':p[scapy.IP].fields['dst']})
		# seq.append(p[scapy.UDP].fields)
		# print p[scapy.UDP].show()
# seq = sorted(seq, key=lambda paq: paq['seq'])
# pprint(seq[:20])
for pak in seq:
	print 48752 in pak.values()