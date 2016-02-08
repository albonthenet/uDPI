#!/usr/bin/env python
import socket
from struct import *
import datetime
import pcapy
import sys

def main(argv):
    #list all devices
    devices = pcapy.findalldevs()
    print devices





if __name__ == "__main__":
  main(sys.argv)
