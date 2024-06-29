'''
CS 60 Final Project
John Guerrerio

Class to detect fixed signatures in various protocols
'''

from scapy.all import sniff, raw, TCP, UDP, DNS
from scapy.layers.http import HTTPRequest
import logging

class SignatureDetector:
    """
    A class to detect specific signatures in network packets for various protocols (TCP, UDP, HTTP, DNS).

    Attributes:
        tcp_signatures (list): A list of byte signatures to search for in TCP packets.
        udp_signatures (list): A list of byte signatures to search for in UDP packets.
        http_signatures (list): A list of byte signatures to search for in HTTP packets.
        dns_signatures (list): A list of byte signatures to search for in DNS packets.
    """

    def __init__(self, tcp_signatures=None, udp_signatures=None, http_signatures=None, dns_signatures=None):
        """
        Initializes the SignatureDetector with optional lists of signatures for each protocol.

        Args:
            tcp_signatures (list, optional): A list of byte signatures to search for in TCP packets. Defaults to an empty list.
            udp_signatures (list, optional): A list of byte signatures to search for in UDP packets. Defaults to an empty list.
            http_signatures (list, optional): A list of byte signatures to search for in HTTP packets. Defaults to an empty list.
            dns_signatures (list, optional): A list of byte signatures to search for in DNS packets. Defaults to an empty list.
        """
        self.tcp_signatures = tcp_signatures if tcp_signatures is not None else []
        self.udp_signatures = udp_signatures if udp_signatures is not None else []
        self.http_signatures = http_signatures if http_signatures is not None else []
        self.dns_signatures = dns_signatures if dns_signatures is not None else []
        
        # Configure logging to file and console
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("signature_detector.log"),
                                logging.StreamHandler()
                            ])

    def search_for_signatures(self, signatures, bytes, protocol):
        """
        Searches for specified byte signatures in the given packet bytes and logs detection.

        Args:
            signatures (list): A list of byte signatures to search for.
            bytes (bytes): The raw bytes of the packet to search within.
            protocol (str): The protocol of the packet being searched (for logging purposes).
        """
        for sig in signatures:
            if sig in bytes:
                logging.info(f"Detected signature {sig.hex()} for protocol {protocol} in a packet.")

    def handle_pkt(self, pkt):
        """
        Processes incoming packets, searches for signatures, and logs any detections.

        Args:
            pkt: The packet to handle.
        """
        bytes = raw(pkt)  # Extract raw bytes from the packet

        if TCP in pkt:
            self.search_for_signatures(self.tcp_signatures, bytes, "TCP")

        if UDP in pkt:
            self.search_for_signatures(self.udp_signatures, bytes, "UDP")

        if DNS in pkt:
            self.search_for_signatures(self.dns_signatures, bytes, "DNS")

        if HTTPRequest in pkt:
            self.search_for_signatures(self.http_signatures, bytes, "HTTP")

    def start(self):
        """
        Starts the packet sniffing and signature detection process.
        """

        logging.info("Starting signature-based detector")

        try:
            sniff(prn=self.handle_pkt, store=False)  # Start sniffing packets and process each with handle_pkt
        except KeyboardInterrupt:
            logging.info("Exiting signature-based detector")

if __name__ == "__main__":
    tcp_signatures = [b'\x16\x03\x01', b'findme']  # Example: SSL/TLS Client Hello
    udp_signatures = [b'\x17\x03\x01', b'findme']  # Example: SSL/TLS Application Data
    http_signatures = [b'GET /', b'POST /']  # Example: HTTP methods
    dns_signatures = [b'\x00\x01\x00\x00\x00\x00\x00\x00']  # Example: DNS query

    detector = SignatureDetector(
        tcp_signatures=tcp_signatures,
        udp_signatures=udp_signatures,
        http_signatures=http_signatures,
        dns_signatures=dns_signatures
    )
    detector.start()
