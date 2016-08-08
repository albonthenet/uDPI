#!/usr/bin/python

import socket

class Packet(object):
    """@brief Packet class definition
    """
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto,\
    direction ,timestamp, pktlength, payload):
        super(Packet, self).__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.direction = direction
        self.timestamp = timestamp
        self.pktlength = pktlength
        self.payload = payload
        if proto == socket.IPPROTO_TCP:
            self.proto = "tcp"
        elif proto == socket.IPPROTO_UDP:
            self.proto = "udp"
        elif proto == socket.IPPROTO_ICMP:
            self.proto = "icmp"
        else:
            self.proto = "unknown"
    def getSrc_ip(self):
        return self.src_ip
    def getDst_ip(self):
        return self.dst_ip
    def getSrc_port(self):
        return self.src_port
    def getDst_port(self):
        return self.dst_port
    def getProto(self):
        return self.proto
    def getDirection(self):
        return self.direction
    def getTimestamp(self):
        #_t = __timeproc(self.timestamp)
        #return _t
        epoch = self.timestamp[0]
        milisec = self.timestamp[1]
        return (str(epoch) + '.' + str(milisec))
    def getPktlength(self):
        return self.pktlength
    def getPayload(self):
        return self.payload

    #Process the time tuple provided by pcapy to merge it
    #it may require some processing ...
    def __timeproc(ts):
        epoch = ts[0]
        milisec = ts[1]
        return (str(epoch) + '.' + str(milisec))

class Flow(object):
    """@brief Flow attributes class definition:
    npack_inbound/outbound > n packets upload/download from user
    npack_gt50 > n packets size greater than 50Bytes payload
    npack_lt50 > n packets size less than 50Bytes payload
    """
    #def __init__(self, npack_inbound, npack_outbound, npack_gt500,\
    #npack_lt500, app):
    def __init__(self):
        super(Flow, self).__init__()
        """
        self.npack_inbound = npack_inbound
        self.npack_outbound = npack_outbound
        self.npack_gt500 = npack_gt500
        self.npack_lt500 = npack_lt500
        self.app = app
        """
        self.npack_inbound = 0
        self.npack_outbound = 0
        #Average of inbound/outbound packets
        self.npack_avg_inout = 0

        self.npack_gt1300 = 0
        self.npack_gt1300_in = 0
        self.npack_gt1300_out = 0
        
        self.npack_lt50 = 0
        self.npack_lt50_in = 0
        self.npack_lt50_out = 0
        
        self.npack_payload = 0
        self.npack_payload_in = 0
        self.npack_payload_out = 0
        self.npack_avgsize = 0
        self.npack_avgsize_in = 0
        self.npack_avgsize_out = 0
        #Counts the number of resets (samples)
        self.nreset = 0
        self.app = 'unknown'

    def reset(self):
        self.npack_inbound = 0
        self.npack_outbound = 0
        self.npack_gt1300 = 0
        self.npack_gt1300_in = 0
        self.npack_gt1300_out = 0
        self.npack_lt50 = 0
        self.npack_lt50_in = 0
        self.npack_lt50_out = 0
        self.npack_payload = 0
        self.npack_payload_in = 0
        self.npack_payload_out = 0
        self.npack_avgsize = 0
        self.npack_avgsize_in = 0
        self.npack_avgsize_out = 0
        self.nreset+=1
    
    def getNpack_inbound(self):
        return self.npack_inbound
    def setNpack_inbound(self, n):
        self.npack_inbound = n
    def getNpack_outbound(self):
        return self.npack_outbound
    def setNpack_outbound(self, n):
        self.npack_outbound = n
    def getNpack(self):
        return (self.npack_inbound + self.npack_outbound)
    def getNpack_gt500(self):
        return self.npack_gt500
    def setNpack_gt500(self, n):
        self.npack_gt500 = n
    def getNpack_lt500(self):
        return self.npack_lt500
    def setNpack_lt500(self, n):
        self.npack_lt500 = n
    def getApp(self):
        return self.app
    def setNpack_lt500(self, app):
        self.app = app
