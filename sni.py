import socket
from struct import *
import datetime
import pcapy
import sys
#import core.types as types

"""TODO
    -add pcapy library check function
    -add exceptions where it proceeds .. :)
    -add methods for get/set in types lib [TO CHECK HOW IT WORKS FIRST!]
    -separate modules not to look like crap..
    -use/create some logging tool to log events, no IP traffic, etc
"""

#classes and variables
class Packet:
    def __init__(self, epoch, direction, data):
        self.epoch = epoch
        self.direction = direction
        self.data = data

_flows = {}

#check if root is executing this
def check_permissions():
    print "Make sure you are root!"


def pick_device():
    #list all devices
    devices = pcapy.findalldevs()

    print "Available devices are :"
    for d in devices :
        print d

    dev = raw_input("Enter device name to sniff : ")

    print "Sniffing device chosen: " + dev
    return dev

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

#function to parse a packet
def parse_packet(packet) :

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == 8 :
        #Parse IP header
        #Strip from the ethernet offset + 20 Bytes (IP Header contains 160bit)
        ip_header = packet[eth_length:(eth_length+20)]
        
        #Here we unpack the data into "iph" buffer according to the IP header
        #fields
        #https://en.wikipedia.org/wiki/IPv4#Header
        #https://docs.python.org/2/library/struct.html
        iph = unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        #For transport offset calculation
        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);

        print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

        #TCP protocol
        if protocol == 6 :
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]

            #now unpack them :)
            tcph = unpack('!HHLLBBHHH' , tcp_header)

            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            tcph_flags = tcph[5]

            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + 'Acknowledgement : ' + str(acknowledgement) + ' TCP header length :' + str(tcph_length) + ' TCP Flags : ' + str(tcph_flags)

            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print 'Data : ' + data

        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]

            print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size

            #Data layer
            data = packet[h_size:]

            print 'Data : ' + data
            print 'Data hex: ' + ':'.join(x.encode('hex') for x in data)
            #print 'data es de tipo %s' % type(data)

        #UDP packets
        elif protocol == 17 :
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size

            #Data layer
            data = packet[h_size:]
            print 'Data : ' + data

        #some other IP packet like IGMP
        else :
            print 'Protocol other than TCP/UDP/ICMP'

        print

def main(argv):

    check_permissions()
    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscious mode (1 for true)
    #   timeout (in milliseconds)
    '''
    cap = pcapy.open_live(pick_device() , 65000 , 1 , 100)

    #start sniffing packets
    while(1) :
        try:
                (header, packet) = cap.next()
                parse_packet(packet)
        except socket.timeout:
                continue
        print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))


if __name__ == "__main__":
    main(sys.argv)
