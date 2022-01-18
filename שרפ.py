from scapy.all import *
scapy.all.send(scapy.all.ARP(hwdst="10.0.0.138", hwsrc="aa:aa:aa:aa:aa:aa"))