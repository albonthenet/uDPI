#!/usr/bin/python
import const

"""
    PACKET
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto,\
    direction ,timestamp, pktlength, payload):

    FLOW
    def __init__(self, npack_inbound, npack_outbound, npack_gt500,\
    npack_lt500, app):
"""

def packet_size_lt50(f,p):
    if p.pktlength <= 50 and packet_direction_check(p) is True:
        f.npack_lt50+=1
        f.npack_lt50_in+=1
    elif p.pktlength <= 50 and packet_direction_check(p) is False:
        f.npack_lt50+=1
        f.npack_lt50_out+=1

def packet_size_gt1300(f,p):
    if p.pktlength >= 1300 and packet_direction_check(p) is True :
        f.npack_gt1300+=1
        f.npack_gt1300_in+=1
    elif p.pktlength >= 1300 and packet_direction_check(p) is False :
        f.npack_gt1300+=1
        f.npack_gt1300_out+=1

def packet_direction_check(p):
    """Returns TRUE if packet is inbound
    and FALSE if packet is outbound"""
    if p.direction is const.INBOUND:
        return True
    else:
        return False

def packet_direction_count(f,p):
    if p.direction == const.INBOUND:
        f.npack_inbound+=1
    else:
        f.npack_outbound+=1

def packet_payload_check(f,p):
    if p.pktlength > 0:
        #total payload packets
        f.npack_payload+=1
        #total inbound payload packets
        if packet_direction_check(p) is True:
            f.npack_payload_in+=1
        else:
            f.npack_payload_out+=1
        #Calculate averge payload size (total, in, out)
        packet_payload_avgsize_check(f,p)

#Packets average size
def packet_payload_avgsize_check(f,p):
    #Here we may want to only check packets with >0 payload...
    if p.pktlength > 0:
        f.npack_avgsize=((p.pktlength+f.npack_avgsize)/f.npack_payload)
        #Check the average for inbound/outbound packets
        if packet_direction_check(p) == True:
            f.npack_avgsize_in=((p.pktlength+f.npack_avgsize_in)/f.npack_payload_in)
        else:
            f.npack_avgsize_out=((p.pktlength+f.npack_avgsize_out)/f.npack_payload_out)
        
def update_flow(f,p):
    """@brief Input parameter is the flow object
    """
    #Check packet direction and increase its counter
    packet_direction_count(f,p)
    #Check packet size and increase its counter
    packet_size_lt50(f,p)
    packet_size_gt1300(f,p)
    #Check if packet has payload
    packet_payload_check(f,p)
