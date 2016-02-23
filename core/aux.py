#!/usr/bin/python
import os

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
