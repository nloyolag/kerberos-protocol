import sys
import scapy.all as scapy
from pprint import pprint

pkts = scapy.rdpcap("pcap_examples/test7.pcap")

seq = []
for p in pkts:
	if p.haslayer(scapy.UDP)==1:
		p[scapy.UDP].fields.update({'src':p[scapy.IP].fields['src']})
  		p[scapy.UDP].fields.update({'dst':p[scapy.IP].fields['dst']})
  		if p.haslayer(scapy.Raw)==1:
  			p[scapy.UDP].fields.update({'Raw':(p[scapy.Raw].load)})
  		seq.append(p[scapy.UDP].fields)
pprint(seq[:20])