import sys
import scapy.all as scapy
from pprint import pprint

def read_intructions(filename):
    rules = {}
    send = []
    recv = []
    ignorable_chars = ['\n', '\r\n']
    f = open(filename, 'r')

    for line in f:
        row = []
        if line[0] in ignorable_chars:
            continue
        else:
            row = line.split('=', 1)
            row[1] = row[1].replace('\n', '')
            if row[0] == 'send':
                send.append(row[1])
            elif row[0] == 'recv':
                recv.append(row[1])
            else:
                rules[row[0]] = row[1]

    rules['send'] = send
    rules['recv'] = recv
    return rules

def read_capture(filename):
    packets = scapy.rdpcap(filename)
    #Hold the TCP packet fields
    tcp = []
    #Hold the UDP packet fields
    udp = []
    for p in packets:
        if p.haslayer(scapy.TCP)==1:
            p[scapy.TCP].fields.update({'src':p[scapy.IP].fields['src']})
            p[scapy.TCP].fields.update({'dst':p[scapy.IP].fields['dst']})
            tcp.append(p[scapy.TCP].fields)
        elif p.haslayer(scapy.UDP)==1:
            # p[scapy.UDP].fields.update({'src':p[scapy.IP].fields['src']})
            # p[scapy.UDP].fields.update({'dst':p[scapy.IP].fields['dst']})
            udp.append(p[scapy.UDP].fields)
    #Order the packets by sequence in case the stream needs to be reconstructed
    tcp = sorted(tcp, key=lambda paq: paq['seq'])
    udp = sorted(udp, key=lambda paq: paq['dport'])
    packets = {}
    packets['tcp'] = tcp
    packets['udp'] = udp

    return packets

def read_tcp_rules(rules,packets):
    for packet in packets['tcp']:
        for rule in rules:
            if rule.proto.lower() == 'tcp':
                if rule.src_port not 'any':
                    if rule.src_port == packet['sport']


if __name__ == "__main__":

    if len(sys.argv) != 3:
        print "Incorrect number of input parameters (2 are required)"
        sys.exit()

    script, rules_file, pcap_file = sys.argv
    rules = read_intructions(rules_file)
    packets = read_capture(pcap_file)
    pprint(rules)