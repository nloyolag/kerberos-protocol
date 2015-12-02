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

def read_packets_rules(rules,packets):
    for packet in packets['tcp']:
        for rule in rules:
            printer = False
            #Means the packet is TCP or UDP but not stream
            if check_type(rule):
                #Is a TCP packet
                if rule['proto'].lower == 'tcp':
                    if check_src_ip(rule,packet):
                        if check_dst_ip(rule,packet):
                            if check_src_port(rule,packet):   
                                if check_dst_port(rule,packet):
                                    #Check if the evil message exists in the packet
                                    print "TCP Packet complies with rule characteristics"

                #Is a UDP packet
                else:
                    if check_src_ip(rule,packet):
                        if check_dst_ip(rule,packet):
                            if check_src_port(rule,packet):   
                                if check_dst_port(rule,packet):
                                    #Check if the evil message exists in the packet
                                    print "UDP Packet complies with rule characteristics"
                                    
            #Checks for stream packets(conversation reconstruction)
            #Check rule:host = packet:src rule:ip = packet:dst
            elif rule['type'] == 'tcp_stream':
                if check_src_ip(rule,packet):
                    if check_dst_ip(rule,packet):
                        if check_src_port(rule,packet):   
                            if check_dst_port(rule,packet):
                                #Check if the evil message exists in the packet
                

def check_type(rule):
    if rule['type'] == 'protocol':
        return True
    return False

def check_src_port(rule,packet):
    if rule['src_port'] != 'any':
        if rule['src_port'] == packet['sport']:
            return True
        else:
            return False
    else:
        return True

def check_dst_port(rule,packet):
    if rule['dst_port'] != 'any':
        if rule['dst_port'] == packet['dport']:
            return True
        else:
            return False
    else:
        return True

def check_src_ip(rule, packet):
    if rule['host'] != 'any':
        if rule['host'] == packet['src']:
            return True
        else:
            return False
    else:
        return True

def check_dst_ip(rule, packet):
    if rule['ip'] != 'any':
        if rule['ip'] == packet['dst']:
            return True
        else:
            return False
    else:
        return True




def print_alert(rule):
    print "MATCHED RULE : %s\nPROTO:%s\nSRCPORT:%s\nDSTPORT:%s\nIP%s"%(rule['name'],rule['proto'],rule['src_port'],rule['dst_port'],rule['ip'])

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print "Incorrect number of input parameters (2 are required)"
        sys.exit()

    script, rules_file, pcap_file = sys.argv
    rules = read_intructions(rules_file)
    packets = read_capture(pcap_file)
    pprint(rules)
    read_packets_rules(rules,packets)