#!/usr/bin/python
import const
from math import fabs, floor, log10

"""
    PACKET
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto,\
    direction ,timestamp, pktlength, payload):

    FLOW
    def __init__(self, npack_inbound, npack_outbound, npack_gtconst.SMALL_SIZE0,\
    npack_ltconst.SMALL_SIZE0, app):
"""

const.SMALL_SIZE = 50
const.LARGE_SIZE = 1300

def packet_size_small(f,p):
    if p.pktlength <= const.SMALL_SIZE and packet_direction_check(p) is True:
        f.npack_small+=1
        f.npack_small_in+=1
    elif p.pktlength <= const.SMALL_SIZE and packet_direction_check(p) is False:
        f.npack_small+=1
        f.npack_small_out+=1

def packet_size_med(f,p):
    if p.pktlength > const.SMALL_SIZE and p.pktlength < const.LARGE_SIZE and packet_direction_check(p) is True:
        f.npack_med+=1
        f.npack_med_in+=1
    elif p.pktlength > const.SMALL_SIZE and p.pktlength < const.LARGE_SIZE and packet_direction_check(p) is False:
        f.npack_med+=1
        f.npack_med_out+=1

def packet_size_large(f,p):
    if p.pktlength >= const.LARGE_SIZE and packet_direction_check(p) is True :
        f.npack_large+=1
        f.npack_large_in+=1
    elif p.pktlength >= const.LARGE_SIZE and packet_direction_check(p) is False :
        f.npack_large+=1
        f.npack_large_out+=1

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


def join_int_to_float(a,b):
    if b == 0:
        return a
    return a+b*10**-(floor(log10(b))+1)

#prueba para mostrar segundos
def packet_time(f,p):
    """
    This function takes the time of the first and the 
    last packet in the sample and calculates the time.
    With this then we can obtain the bps ratio

    print 'time1 :' + str(p.timestamp[0])
    print 'time2 :' + str(p.timestamp[1])
    """
    #Sum of total inbound/outbound packets
    if f.getNpack is 0:
        #Grab the time of first packet
        epoch = p.timestamp[0]
        delta_epoch = p.timestamp[1]
        f.time_first = (epoch,delta_epoch)
    elif f.getNpack is const.N_SAMPLES:
        #Grab the time of last packet
        epoch = p.timestamp[0]
        delta_epoch = p.timestamp[1]
        f.time_last = (epoch,delta_epoch)
        #We calculate the delta since first/last
        seconds_diff = f.time_last[0]-f.time_first[0]
        useconds_diff = f.time_last[1]-f.time_first[1]
        #If the useconds negative, then we got to adjust
        if useconds_diff < 0:
            useconds_diff = abs(f.time_last[0]-f.time_first[0])
            seconds_diff-=1
        #Now we join both int into a float
        f.tdelta_sample=join_int_to_float(seconds_diff,useconds_diff)

def update_flow(f,p):
    """@brief Input parameter is the flow object
    """
    #Check packet direction and increase its counter
    packet_direction_count(f,p)
    #Check packet time
    packet_time(f,p)
    #Check packet size and increase its counter
    packet_size_small(f,p)
    packet_size_med(f,p)
    packet_size_large(f,p)
    #Check if packet has payload
    packet_payload_check(f,p)
