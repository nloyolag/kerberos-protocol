import sys

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

if __name__ == "__main__":

    if len(sys.argv) != 3:
        print "Incorrect number of input parameters (2 are required)"
        sys.exit()

    script, rules_file, pcap_file = sys.argv
    rules = read_intructions(rules_file)
