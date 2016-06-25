#!/usr/bin/python

import socket

class Packet(object):
    """@brief Packet class definition
    """
    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto,\
    timestamp, pktlength, payload):
        super(Packet, self).__init__()
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
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
