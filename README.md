# uDPI
uDPI is a network application discovery tool that uses machine learning algorithms to classify traffic. It does not require access to the application layer data so encrypted protocols can be also detected. 
In order to detect applications it uses a combination of different packet/flow parameters and behaviour to determine the protocol after comparing to previously protocol analysis.

A number of protocols/applications were tested:
 - Internet browsing (Regular Firefox browsing)
 - Tor browser
 - BitTorrent (Transmission)
 - WhatsApp (over WiFi)
 - FTP
 - SSH

### miscellaneous ####
Opened project on 08/02/16

#Necessary packages
-python-dev (apt-get install python-dev)
-python-pip (apt-get install python-pip)
-pip install cityhash
-scikit-learn
