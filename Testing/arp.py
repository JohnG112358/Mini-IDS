'''
John Guerrerio
CS 60 Final Project

Functions to send ARP packets to test the ARP poisioning module
'''

from scapy.all import ARP, Ether, sendp

# send an arp request
def send_arp_request(target_ip, interface='bridge100'):
    # Create Ethernet and ARP packets
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Ethernet frame with broadcast MAC as destination
    arp = ARP(pdst=target_ip)  

    packet = ether / arp

    sendp(packet, iface=interface)

# send an arp reply
def send_arp_reply(sender_ip, sender_mac, target_ip="192.168.64.4", target_mac="52:54:00:0a:f5:ac", interface='bridge100'):
    # Create Ethernet and ARP packets
    ether = Ether(dst=target_mac)  # Ethernet frame with target MAC as destination
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=sender_ip, hwsrc=sender_mac)  # ARP reply packet

    packet = ether / arp

    sendp(packet, iface=interface)
