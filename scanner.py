import scapy.all as scapy
import Project_Mitm.arp_spoofer
import threading
connected_ip={}
threads_counter = 0
threads_counter_mac = 0
ip_address = []

def binary_to_string(binstr):
    c=0
    for i,val in enumerate(binstr[::-1]):
        c+=2**i*int(val)
    return c

def binaryString_binary(binstr):
    return bin(binary_to_string(binstr))

def scanner():
    Project_Mitm.arp_spoofer.update_globals()
    mask_split = ''.join([bin(int(x))[2::] for x in Project_Mitm.arp_spoofer.subnet.split(".")])
    mask_split = mask_split
    subnet_gateway = ''.join([(8-len(bin(int(x))[2::]))*'0' + bin(int(x))[2::] for x in Project_Mitm.arp_spoofer.gateway_ip.split(".")])[0:len(mask_split)]
    counter = '0'

    while counter!=str(binary_to_string('1'*(32-len(mask_split)))):
        add = (32-len(mask_split)-len(bin(int(counter))[2::]))*'0'+ bin(int(counter))[2::]
        ip_binary = subnet_gateway+add
        ip = '.'.join([str(binary_to_string(ip_binary[c:c+8])) for c in range(0,32,8)])
        globals()['ip_address'].append(ip)
        counter = str(int(counter) + 1)

    for ip in ip_address:
        sender = threading.Thread(target=send_packets,args=(ip,))
        while threads_counter_mac>7:
            pass
        globals()['threads_counter_mac'] += 1
        sender.start()


def send_packets(ip):
    send_packet = threading.Thread(target=updater, args=(ip,))
    send_packet.start()
    globals()['threads_counter_mac'] -= 1

def updater(ip: str)->str:
    '''The following function returns the MAC from ip (layer 3 -> layer 2)'''
    try:
        mac_list = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip, op = 'who-has'), timeout=3, verbose=False)[0]
        globals()['connected_ip'][ip] = mac_list[0][1].hwsrc
    except Exception as e:
        pass
