#General porpuse import library
import datetime
import pcapy
import sys
import signal
import socket
import operator
#Scikit-learn libraries related
import numpy as np
from sklearn import metrics
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
#Library for python debugging
import pdb
#Argument parsing lib
from optparse import OptionParser
#Internal libraries
import core.types as types
import core.const as const
from core.packet_checks import *
from core.aux import *
from struct import *
#Library for conn hashing
from cityhash import CityHash64

"""TODO
    -add pcapy library check function
    -add non-crypo hash functs
    -define constants for IP(8), TCP flags(SYN==2) etc
    -add exceptions where it proceeds 
    -add methods for get/set in types lib [TO CHECK HOW IT WORKS FIRST!]
    -pass the sniffing iface as parameter/config file
    -use/create some logging tool to log events, no IP traffic, etc
"""

#Constants definition
const.IP_PROTO = 0x08
const.ETHER_HEAD_LENGTH = 14
#constants for inbound/outbound mapping (traffic direction)
const.INBOUND = 0
const.OUTBOUND = 1
#Number of traffic packets required to create a sample
const.N_SAMPLES = 15
#Number of samples required to classify a flow (custom value may be given by param)
const.N_CLASSIF_ATTEMPTS = 4
#definition of default category for unknown/uncategorized traffic
const.DEFAULT_CATEGORY = 99
#This constant defines how many samples are taken for category when learning a
#protocol. When this number is reached the program exists
const.MAX_SAMPLES_CATEGORY = 150
#Debug variables ones
debug_showdata = False
#########################
#   Global Variables    #
#########################
VERSION = "0.1"
count = 0
connNum = 0
flows = {}
macaddr = None

#Accumulator for line counting when creating dataset
lines_to_dataset = 0
#Filename for dataset write
dataset_file = None
#global variable for sckit-learn object
model = None
#One of the variables simply boolean to learn active
#Othe indicates if active the type of protocol to learn
learn_protocol_on = False
learn_protocol_type = None
#Same funcionality than previous for detecting
detect_protocol_on = False
classification_attempts = const.N_CLASSIF_ATTEMPTS
#Number of attributes in the current dataset (based on CSV files)
num_attributes = None
#Dictionary with supported protocol - matched value for dataset
supported_protocols = {'whatsapp':1,\
    'ssh':2,\
    'ftp':3,\
    'bittorrent':4,\
    'tor-browser':5,\
    'skype':6,\
    'default':99}
supported_protocols_revr = {1:'whatsapp',\
    2:'ssh',\
    3:'ftp',\
    4:'bittorrent',\
    5:'tor-browser',\
    6:'skype',\
    99:'default'}

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
    while True:
        dev = raw_input("Enter device name to sniff : ")
        if dev not in devices: print "ERROR: The selected interface is not valid"
        else:break
    print "Sniffing device chosen: " + dev
    return dev

#Signal capture for ctrl-c
def signal_handler(signal, frame):
    #TBD distinguir el handler entre learning y detecting!
    print 'Total number of packets captured: ' + str(count)
    print
    print 'ProgramFlows captured info:'
    #global flows
    #Just a local counter for summing up the number of flows classified when
    #displaying results
    flows_local_counter = 0
    #We do some pre-sorting by values for better representation
    sorted_flows = {}
    for k,v in flows.iteritems():
        #print "Connection ID: " + str(k) + ' : ' + str(v.protocol[0])
        sorted_flows.update({k:str(v.protocol[0])})
    print '#############################'
    print '## Classified connections: ##'
    print '#############################\n\n'
    #Here we do some preprocessing converting this new dict to a list
    sorted_flows = sorted(sorted_flows.items(), key=operator.itemgetter(1))
    for k in range(len(sorted_flows)):
        connId=sorted_flows[k][0]
        protocol = sorted_flows[k][1]
        #protocol = supported_protocols_revr[protocol]
        #Use 4500 bytes as good reference
        if (flows[connId].size_payload_total) > 400:
            print "Connection ID: " + str(connId) + ' :\t'+ str(protocol) +\
            ' (srcIP: '+ str(flows[connId].tuple5[0]) + ', dstIP: ' + str(flows[connId].tuple5[1]) +')'+\
            '\tbytes: ' + str(flows[connId].size_payload_total)
            flows_local_counter+=1
        """
        else:
            print "(low size) Connection ID: " + str(connId) + ' :\t'+ str(protocol) +\
            ' (srcIP: '+ str(flows[connId].tuple5[0]) + ', dstIP: ' + str(flows[connId].tuple5[1]) +')'+\
            '\tbytes: ' + str(flows[connId].size_payload_total)
        """
    
    """
    for k,v in flows.iteritems():
        print "Connection ID: " + str(k)\
        + " | npackets: " + str(v.getNpack())\
        + " | >500: " + str(v.npack_gt500) + " | <500: " + str(v.npack_lt500)\
        + " | npackets in: " + str(v.npack_inbound)\
        + " | npackets out: " + str(v.npack_outbound)\
        + " | npackets w/payload : " + str(v.npack_payload)\
        + " | packets avg. size : " + str(v.npack_avgsize)
    """

    """
    for k,v in flows.iteritems():
        print "Connection ID: " + str(k) + " | connId: " + str(v[0]) + " | \
        npackets: " + str(v[1]) + " | proto: " + v[2]
    """
    
    """
    for k,v in flows.iteritems():
        print "Connection ID: " + str(k) + " | npackets: " + str(v.getNpack())
        for i in range(1,len(v)):
            print 'Packet n#' + str(i)
            print 'Src IP address: %s' % (v[i].getSrc_ip())
            print 'Dst IP address: %s' % (v[i].getDst_ip())
            print 'Src Port: %d' % (v[i].getSrc_port())
            print 'Dst Port: %d' % (v[i].getDst_port())
            print 'Protocol: %s' % (v[i].getProto())
            print 'Timestamp: %s' % (v[i].getTimestamp())
            print 'Length: %d' % (v[i].getPktlength())
    """
    print 'Total number of flows shown: ' + str(flows_local_counter)
    sys.exit(0)

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b

def dataset_print_arff(f):
    """
    This function simply creates a file with a new line using a similar ARFF
    format by using the flow parameter 'f'
    """
    dataset_line = ""
    dataset_line = str(f.npack_small) + ',' + str(f.npack_small_in) + ',' + str(f.npack_small_out) + ',' +\
    str(f.npack_med) + ',' + str(f.npack_med_in) + ',' + str(f.npack_med_out) + ',' +\
    str(f.npack_large) + ',' + str(f.npack_large_in) + ',' + str(f.npack_large_out) + ',' +\
    str(f.npack_inbound) + ',' + str(f.npack_outbound) + ',' +\
    str(f.npack_payload) + ',' + str(f.npack_payload_in) + ',' +str(f.npack_payload_out) + ',' +\
    str(f.npack_avgsize) + ',' + str(f.npack_avgsize_in) + ',' + str(f.npack_avgsize_out) + ',' +\
    str(learn_protocol_type) + '\n'
    #str(f.tdelta_sample)+ ',' +\
    #str(learn_protocol_type) + '\n'
    print dataset_line

    #Open file descriptor for writing or appending new line to dataset
    #file_descriptor = open_dataset(learn_protocol_type)
    file_descriptor = open_dataset(dataset_file)
    file_descriptor.write(dataset_line)
    file_descriptor.close()

def learning(f):
    #This variable contains the type of protocol to learn
    global learn_protocol_type
    flow_npack = f.getNpack()
    if flow_npack % const.N_SAMPLES == 0:
        #By checking nreset value we ignore the first 15 packets of each new
        #flow
        if f.nreset >= 1:
            dataset_print_arff(f)
            global lines_to_dataset
            lines_to_dataset+=1
            if lines_to_dataset == const.MAX_SAMPLES_CATEGORY:
                print 'Lines limit per application reached.. exiting'
                exit()
        f.reset()

def check_flow_classification(f):
    """
    This function verifies if an existing flow has been already classified
    and therefore the rest of the flow should not be re-classificated in 
    order to improve performance. Bear in mind that an initial
    misclassification may lead to the whole flow to be wrongly evaluated
    """
    #global classification_attempts
    if f.protocol[1]>=classification_attempts:
        #Obtain the most common classification value for this protocol
        prediction = most_common_list(f.predictions)
        #Now we just retrieve the classified protocol in text format
        for proto,keymap in supported_protocols.iteritems():
            if prediction == keymap:
                f.protocol[0]=proto

def inspect_flow(f):
    """
    This function takes the values of arbitrary flow samples and analyze them
    by using scikit-learning machine learning methods to classify the
    information received against a dataset for service classification
    """
    if f.protocol[0] is 'default':
        flow_npack = f.getNpack()
        if flow_npack % const.N_SAMPLES == 0:
            #By checking nreset value we ignore the first sample of each new flow
            if f.nreset >= 1:
                global model
                sample = [[(f.npack_small) , (f.npack_small_in) , (f.npack_small_out) ,\
                (f.npack_med) , (f.npack_med_in) , (f.npack_med_out) ,\
                (f.npack_large) , (f.npack_large_in) , (f.npack_large_out) ,\
                (f.npack_inbound) , (f.npack_outbound) ,\
                (f.npack_payload) , (f.npack_payload_in) ,(f.npack_payload_out) ,\
                (f.npack_avgsize) , (f.npack_avgsize_in) ,(f.npack_avgsize_out)]]\
                #(f.tdelta_sample)]]
                print 'Sample_input: ' + str(sample) + ' bps: ' + str(f.bps_sample)
                prediction = model.predict(sample)
                pred_str = supported_protocols_revr[int(prediction)]
                print 'Prediction of protocol :' + str(pred_str)

                #probability = model.predict_proba(sample)
                #print 'Probability of protocol :' + str(prediction)
                
                #Add up the prediction for this sample. Once the limit of
                #samples (classification_attemps) is reached then the most
                #common value in the array will be the category of the flow
                f.predictions.append(int(prediction))
                #Increase the classification counter for this flow
                f.protocol[1]+=1
                check_flow_classification(f)
            f.reset()

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
        if p.direction == const.INBOUND:
            print "packet inbound"
        else:
            print "packet outbound"
    
    #Access to these global variables
    global flows
    global connNum
    global learn_protocol_on
    global detect_protocol_on

    #pdb.set_trace()
    if connId in flows:
        update_flow(flows[connId],p)
        if learn_protocol_on:
            learning(flows[connId])
        elif detect_protocol_on:
            inspect_flow(flows[connId])
        return False
    elif connId not in flows and connId_revr in flows:
        update_flow(flows[connId_revr],p)
        if learn_protocol_on:
            learning(flows[connId_revr])
        elif detect_protocol_on:
            inspect_flow(flows[connId_revr])
        return False
    else:
        #New connection - We add first packet (p) to new flow (flow)
        flow = types.Flow()
        update_flow(flow,p)
        flows.update({connId : flow})
        #Adding 5tuple info to the flow
        add_5tuple_info(flows[connId],p)
        print "New connection established. ConnId: %i" % (connId)
        return True
    
    """
    if connId in flows:
        flows[connId][0]+=1
        flows[connId].append(p)
        return False
    elif connId not in flows and connId_revr in flows:
        flows[connId_revr][0]+=1
        flows[connId_revr].append(p)
        return False
    else:
        flows.update({connId : [1,p]})
        print "New connection established. ConnId: %i" % (connId)
        return True
    """

#TBD sacar esta fucnion a un modulo
def add_5tuple_info(f,p):
    f.tuple5[0]=p.src_ip
    f.tuple5[1]=p.dst_ip
    f.tuple5[2]=p.src_port
    f.tuple5[3]=p.dst_port

#function to parse a packet
def parse_packet(packet, ptimestamp) :
    #parse ethernet header
    eth_header = packet[:const.ETHER_HEAD_LENGTH]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    #print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

    direction = packet_direction(eth_addr(packet[6:12]),macaddr)

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
        #global count variable to check number of total packets.. for debugg
        global count

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
            #global count
            count+=1
            #Construction of packet object
            p = types.Packet(s_addr,d_addr,s_port,d_port,protocol,direction,ptimestamp,data_size,payload)
            
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

            s_port = udph[0]
            d_port = udph[1]
            length = udph[2]
            checksum = udph[3]
            
            if debug_showdata:
                print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)

            h_size = const.ETHER_HEAD_LENGTH + iph_length + udph_length
            data_size = len(packet) - h_size

            #Data layer
            payload = packet[h_size:]
            if debug_showdata:
                print 'Data : ' + data
            #global count
            count+=1
            #Construction of packet object
            p = types.Packet(s_addr,d_addr,s_port,d_port,protocol,direction,ptimestamp,data_size,payload)
            inspect_packet(p)
        
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

        #some other non-supported transport protocol like SCTP
        else :
            print 'Protocol other than TCP/UDP/ICMP'

def main(argv):
    #Check if program is being executed by root
    if check_sudo() is False:
            exit("[!] please run '%s' with sudo/Administrator privileges" % \
            __file__)
    """
    open device
    # Arguments here are:
    #   device
    #   snaplen (maximum number of bytes to capture _per_packet_)
    #   promiscous mode (1 for true)
    #   timeout (in milliseconds)
    """
    #Ctrl-c signal capture handler
    signal.signal(signal.SIGINT, signal_handler)

    #Parsing options stuff
    parser = OptionParser(usage="%prog [-l protocol-to-learn] [-d result]", version="%prog"+VERSION)
    parser.add_option("-l", "--learn", dest="learn_protocol",help="Create dataset for learning")
    parser.add_option("-f", "--file", dest="file_learn",help="File for dataset storage")
    parser.add_option("-d", "--detect", dest="dataset_load",help="Start detection and write to an output file")
    parser.add_option("-a", "--attempts", dest="class_attempts", help="Number of classification attempts before a protocol is classified")
    (options, args) = parser.parse_args()

    if options.learn_protocol and options.dataset_load:
        parser.error("ERROR: Not possible to learn and detect yet")
        exit()
    elif options.learn_protocol and options.file_learn == None:
        parser.error("If learning you must specify the file to write the \
        dataset - Use option -f [file]")
        exit()
    elif options.learn_protocol and options.file_learn:
        global learn_protocol_type
        global learn_protocol_on
        learn_protocol_on = True
        #TBD check that protocol is supported...
        learn_protocol_type = supported_protocols[options.learn_protocol]
        global dataset_file
        dataset_file = options.file_learn
        print 'Learning for protocol: ' +str(options.learn_protocol)+' ('+str(learn_protocol_type)+')'
        print 'File to create dataset: ' + str(options.file_learn)
    elif options.dataset_load:
        global detect_protocol_on
        detect_protocol_on = True
        print "Detecting protocols: " #TBD show list of currently supported
        #TBD to check possible exceptions, file not found, etc
        global model
        dataset_path = options.dataset_load
        data = np.genfromtxt(dataset_path, skip_header=True, delimiter=',')
        model = DecisionTreeClassifier()
        #get number of attributes in selected dataset
        num_attributes = getNumAttributes(dataset_path)
        features = data[:, :num_attributes]
        targets = data[:, num_attributes]
        model.fit(features,targets)
    else:
        print 'Invalid arguments. Either you need to learn or detect'
        parser.print_help()
        exit()

    if options.class_attempts!= None and options.class_attempts!=const.N_CLASSIF_ATTEMPTS:
        global classification_attempts
        classification_attempts = options.class_attempts

    #Capture the DPI NIC MAC address
    global macaddr
    macaddr = getHwAddr('eth1')
    print "Current MAC address for listening interface: " + macaddr

    #Start of uDPI stuff
    cap = pcapy.open_live(pick_device(),65000,1,100)
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
