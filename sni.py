import datetime
import pcapy
import sys
import signal
import socket
from struct import *

import pdb


import core.types as types
import core.const as const
from core.aux import *
from cityhash import CityHash64

"""TODO
    -add pcapy library check function
    -add non-crypo hash functs
    -define constants for IP(8), TCP flags(SYN==2) etc
    -add exceptions where it proceeds 
    -add methods for get/set in types lib [TO CHECK HOW IT WORKS FIRST!]
    -use/create some logging tool to log events, no IP traffic, etc
"""

#Constants definition
const.IP_PROTO = 0x08
const.ETHER_HEAD_LENGTH = 14

#Debug variables switches
debug_showdata = False

#classes and variables
count = 0
_connNum = 0
_flows = {}
#Packet_info type declaration example:

def ip_class(ipclass_in):
    if ipclass_in == 1:
        ipclass_out = 'icmp'
    elif ipclass_in == 6:
        ipclass_out = 'tcp'
    elif ipclass_in == 17:
        ipclass_out = 'udp'
    elif ipclass_in == 50:
        ipclass_out = 'esp'
    elif ipclass_in == 51:
        ipclass_out = 'ah'
    elif ipclass_in == 89:
        ipclass_out = 'ospf'
    else:
        ipclass_out = 'unknown'

def proto_class(proto_in):
    if proto_in == 80:
        proto_out = 'http'
    elif proto_in == 443:
        proto_out = 'https'
    elif proto_in == 21 or proto_in == 20:
        proto_out = 'ftp'
    elif proto_in == 53:
        proto_out = 'dns'
    elif proto_in == 22:
        proto_out = 'ssh'
    elif proto_in == 23:
        proto_out = 'telnet'
    elif proto_in == 25:
        proto_out = 'smtp'
    elif proto_in == 110 or proto_in == 995:
        proto_out = 'pop3'
    elif proto_in == 143 or proto_in == 220 or proto_in == 993:
        proto_out = 'imap'
    elif proto_in == 123:
        proto_out = 'ntp'
    elif proto_in == 194:
        proto_out = 'irc'
    elif proto_in == 88:
        proto_out = 'kerberos'
    else:
        proto_out = 'unknown'
    return proto_out

def pick_device():
    #list all devices
    devices = pcapy.findalldevs()

    print "Available devices are :"
    for d in devices :
        print d
    dev = raw_input("Enter device name to sniff : ")
    print "Sniffing device chosen: " + dev
    return dev

#Signal capture for ctrl-c
def signal_handler(signal, frame):
    print 'Total number of packets captured: ' + str(count)
    print
    print 'ProgramFlows captured info:'
    global _flows
    """
    for k,v in _flows.iteritems():
        print "Connection ID: " + str(k) + " | connId: " + str(v[0]) + " | \
        npackets: " + str(v[1]) + " | proto: " + v[2]
    """
    for k,v in _flows.iteritems():
        print "Connection ID: " + str(k) + " | npackets: " + str(v[0])
        for i in range(1,len(v)):
            print 'Packet n#' + str(i)
            print 'Src IP address: %s' % (v[i].getSrc_ip())
            print 'Dst IP address: %s' % (v[i].getDst_ip())
            print 'Src Port: %d' % (v[i].getSrc_port())
            print 'Dst Port: %d' % (v[i].getDst_port())
            print 'Protocol: %s' % (v[i].getProto())
            print 'Timestamp: %s' % (v[i].getTimestamp())
            print 'Length: %d' % (v[i].getPktlength())
    sys.exit(0)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

#Inspect packet to find out if new connection or existing based on 5tuple
#def inspect_packet(proto, s_addr, d_addr, s_port, d_port):
def inspect_packet(p):
    aux_id = str(p.src_ip) + str(p.dst_ip) + str(p.src_port) + str(p.dst_port)
    aux_id_revr = str(p.dst_ip) + str(p.src_ip) + str(p.dst_port) + str(p.src_port)
    connId = CityHash64(aux_id)
    connId_revr = CityHash64(aux_id_revr)
    
    if debug_showdata == True:
        print 'ConnId:  ' + str(connId)
        print 'ConnId_r:  ' + str(connId_revr)
    
    global _flows
    global _connNum

    print p.getTimestamp()


    #Check if the connection already exists
    #pdb.set_trace()
    if connId not in _flows:
        if connId_revr in _flows:
        #not new, existing conn packet
            _flows[connId_revr][0]+=1
            _flows[connId_revr].append(p)
            return False
        else:
            #proto = proto_class(d_port)
            _flows.update({connId : [1,p]})
            print "New connection established. ConnId: %i" % (connId)
            return True
    else:
        if debug_showdata == True:
            print "Connection not new"
        #Since this connection already exists we update the number of packets
        #counter for this flow
        _flows[connId][0]+=1
        _flows[connId].append(p)
        return False

#function to parse a packet
def parse_packet(packet, ptimestamp) :
    #parse ethernet header
    eth_header = packet[:const.ETHER_HEAD_LENGTH]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    #print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    #Parse IP packets, IP Protocol number = 8
    if eth_protocol == const.IP_PROTO :
        #Parse IP header
        #Strip from the ethernet offset + 20 Bytes (IP Header contains 160bit)
        ip_header = packet[const.ETHER_HEAD_LENGTH:(const.ETHER_HEAD_LENGTH+20)]
        
        #Here we unpack the data into "iph" buffer tuple according to the IP header
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

        if debug_showdata:
            print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

        #TCP protocol
        if protocol == socket.IPPROTO_TCP :
            t = iph_length + const.ETHER_HEAD_LENGTH
            tcp_header = packet[t:t+20]
            #Unpack TCP header. Returned object is a tuple
            tcph = unpack('!HHLLBBHHH' , tcp_header)
            #the objects within the TCP tuple are integer
            s_port = tcph[0]
            d_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            tcph_flags = tcph[5]
            #print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + 'Acknowledgement : ' + str(acknowledgement) + ' TCP header length :' + str(tcph_length) + ' TCP Flags : ' + str(tcph_flags)
            h_size = const.ETHER_HEAD_LENGTH + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
            #dirty fix to avoid ethernet 6 bytes  padding frames size
            #which size is smaller than 60 bytes (typically TCP ACKs)
            if data_size == 6:
                data_size = 0
            #get data from the packet
            payload = packet[h_size:]
            
            #Capture new connections
            #+-+-+-+-+-+-+
            #|U|A|P|R|S|F|
            #|R|C|S|S|Y|I|
            #|G|K|H|T|N|N|
            #+-+-+-+-+-+-+
            # 3 1 8 4 2 1
            global count
            count+=1
            #Construction of packet object
            p = types.Packet(s_addr,d_addr,s_port,d_port,protocol,ptimestamp,data_size,payload)
            
            #Sustituir por un logging event
            
            #if tcph_flags == 2 :
            #        print 'ALERT - SYN received for an already existing connection'
            
            #inspect_packet('tcp', s_addr,d_addr,s_port,d_port)
            inspect_packet(p)
            #print 'Data hex: ' + ':'.join(x.encode('hex') for x in data)

        #UDP packets
        elif protocol == socket.IPPROTO_UDP :
            u = iph_length + const.ETHER_HEAD_LENGTH
            udph_length = 8
            udp_header = packet[u:u+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)

            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            
            if debug_showdata:
                print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

            h_size = const.ETHER_HEAD_LENGTH + iph_length + udph_length
            data_size = len(packet) - h_size

            #Data layer
            data = packet[h_size:]
            if debug_showdata:
                print 'Data : ' + data
        
        #ICMP Packets
        elif protocol == 1 :
            u = iph_length + const.ETHER_HEAD_LENGTH
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #now unpack them :)
            icmph = unpack('!BBH' , icmp_header)

            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            if debug_showdata:
                print 'Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum)

            h_size = const.ETHER_HEAD_LENGTH + iph_length + icmph_length
            data_size = len(packet) - h_size

            #Data layer
            data = packet[h_size:]
            if debug_showdata:
                print 'Data : ' + data
                print 'Data hex: ' + ':'.join(x.encode('hex') for x in data)

        #some other transport protocol like SCTP
        else :
            print 'Protocol other than TCP/UDP/ICMP'

def main(argv):
    
    #Check if program is being executed by root
    if check_sudo() is False:
            exit("[!] please run '%s' with sudo/Administrator privileges" % \
            __file__)
    '''
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscous mode (1 for true)
    #   timeout (in milliseconds)
    '''
    #Ctrl-c signal capture handler
    signal.signal(signal.SIGINT, signal_handler)
    
    cap = pcapy.open_live(pick_device() , 65000 , 1 , 100)
    #start sniffing packets
    while(1) :
        try:
                (header, packet) = cap.next()
                #print str(header.getts()[0]) + ' ||| ' + str(header.getts()[1])
                #header.getts() returns tuple with number of seconds since the
                #Epoch, and the amount of microseconds past the current second
                parse_packet(packet, header.getts())
        except socket.timeout:
                continue
        if debug_showdata:
            print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))


if __name__ == "__main__":
    main(sys.argv)
