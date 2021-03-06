#!/usr/bin/python
import os
import fcntl, socket, struct
import const as const
import csv

def check_sudo():
    """
    Checks for sudo/Administrator privileges
    """
    check = None
    if getattr(os, "geteuid"):
        check = os.geteuid() == 0
    else:
        print 'Error when reading permissions. Check you are running as root'

    return check

def getHwAddr(ifname):
    """@brief Returns the MAC address of an interface
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

def packet_direction(mac1, mac2):
    """@brief Determine the direction (inbound/outbound) of the packet based on L2
    """
    if (mac1 == mac2):
        return const.OUTBOUND
    else:
        return const.INBOUND

def open_dataset(protocol_name):
    filename = str(protocol_name) + '.ds'
    #if os.path.isfile(filename) is True:
        #print filename + ' dataset file exits. Appending'
    fo = open(filename, "a+")
    return fo

def getNumAttributes(file):
    """@brief returns the number of attributes located in a CSV file (param)
    """
    r= csv.reader(open(file))
    l1=r.next()
    return (len(l1)-1)
