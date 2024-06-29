'''
John Guerrerio
CS 60 Final Project

Functions to send TCP packets to test the syn flooding module
'''

from scapy.layers.inet import TCP, IP
from scapy.sendrecv import send

# send a SYN packet
def send_syn_packet(src_ip, dst_ip, dst_port, iface="bridge100"):
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(dport= dst_port, flags='S')
    packet = ip_layer / tcp_layer
    send(packet, iface=iface)
