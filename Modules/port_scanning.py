'''
CS 60 Final Project
John Guerrerio

Class to detect port scanning
'''

from scapy.all import IP, TCP, UDP, Ether
from collections import defaultdict, deque
import subprocess
import re
import socket
import sys
import logging

class PortScannerDetector:
    """
    A class to detect potential port scanning activities by monitoring network traffic on specified ports.

    Attributes:
        interface_name (str): The name of the network interface to monitor.
        local_ip (str): The local IP address to monitor.
        ignore_ports (list): A list of ports to ignore during detection.
        open_ports (set): A set of currently open ports on the local system.
        connection_tracker (defaultdict): A dictionary to track connections per source IP.
        raw_socket (socket): A raw socket for capturing network packets.
    """

    def __init__(self, interface_name, local_ip, ignore_ports=None):
        """
        Initializes the PortScannerDetector with the network interface, local IP, and optional ignore ports.

        Args:
            interface_name (str): The name of the network interface to monitor.
            local_ip (str): The local IP address to monitor.
            ignore_ports (list, optional): A list of ports to ignore during detection. Defaults to None.
        """
        self.interface_name = interface_name
        self.local_ip = local_ip
        self.ignore_ports = ignore_ports if ignore_ports is not None else []
        self.open_ports = self.get_open_ports()  # Fetch open ports on the system
        self.connection_tracker = defaultdict(lambda: deque(maxlen=3))  # Track last 3 connections per source IP
        self.raw_socket = self.create_raw_socket()  # Create a raw socket for packet capture
        
        # Configure logging to file and console
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("port_scanner_detector.log"),
                                logging.StreamHandler()
                            ])

    def get_open_ports(self):
        """
        Retrieves the set of currently open ports on the local system.

        Returns:
            set: A set of open ports.
        
        Errors:
            Logs errors if fetching open ports fails.
        """
        try:
            result = subprocess.run(['netstat', '-plntu'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.stderr:
                logging.error("Error fetching open ports: %s", result.stderr)
                return set()

            open_ports = set()
            # Regex patterns for IPv4 and IPv6 addresses for both TCP and UDP
            patterns = {
                'ipv4_tcp_udp': re.compile(r'^(tcp|udp)\s+\d+\s+\d+\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+\d+\.\d+\.\d+\.\d+:\*\s+LISTEN'),
                'ipv6_tcp_udp': re.compile(r'^(tcp6|udp6)\s+\d+\s+\d+\s+\[?([:a-fA-F0-9]+(?:%[\w]+)?)\]?:(\d+)\s+\[?[:a-fA-F0-9]*\]?::\*\s+LISTEN'),
            }

            lines = result.stdout.split('\n')
            for line in lines:
                for pattern in patterns.values():
                    match = pattern.match(line)
                    if match:
                        protocol, ip, port = match.groups()
                        open_ports.add(int(port))

            return open_ports
        except subprocess.SubprocessError as e:
            logging.error("Error executing netstat: %s", e)
            return set()
        except Exception as e:
            logging.error("Unexpected error: %s", e)
            return set()

    def create_raw_socket(self):
        """
        Creates a raw socket bound to the specified network interface.

        Returns:
            socket: The created raw socket.

        Errors:
            Logs and exits the program if socket creation fails.
        """
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            s.bind((self.interface_name, 0))  # Bind the socket to the network interface
            return s
        except socket.error as e:
            logging.critical("Socket error: %s", e)
            sys.exit(1)
        except Exception as e:
            logging.critical("Unexpected error while creating raw socket: %s", e)
            sys.exit(1)

    def handle_pkt(self, packet):
        """
        Handles incoming packets and updates connection statistics for port scanning detection.

        Args:
            packet: The captured network packet.
        """
        if IP in packet and packet[IP].dst == self.local_ip:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = None
            dst_port = None

            if TCP in packet:
                protocol = "TCP"
                dst_port = packet[TCP].dport
            elif UDP in packet:
                protocol = "UDP"
                dst_port = packet[UDP].dport

            if dst_port in self.ignore_ports:  # Ignore specified ports
                return

            if protocol and dst_port:
                # Check if the destination port is open
                if dst_port not in self.open_ports:
                    logging.info(f"{protocol} packet from {src_ip} to {dst_ip}:{dst_port} querying closed port {dst_port}")

                # Track connections per source IP
                if dst_port not in self.connection_tracker[src_ip]:
                    self.connection_tracker[src_ip].append(dst_port)

                # Detect potential port scan
                if len(self.connection_tracker[src_ip]) == 3:
                    ports = list(self.connection_tracker[src_ip])
                    if (ports[1] == ports[0] + 1 and ports[2] == ports[1] + 1) or (ports[1] == ports[0] - 1 and ports[2] == ports[1] - 1):
                        logging.warning(f"Possible port scan detected from {src_ip} to consecutive ports {ports}")

    def sniff_raw_socket(self):
        """
        Captures packets from the raw socket and processes them.

        Errors:
            Logs errors if packet capture fails or is interrupted.
        """
        try:
            while True:
                packet_data, addr = self.raw_socket.recvfrom(65535)  # Receive packet data from the raw socket
                packet = Ether(packet_data)  # Convert bytes to a Scapy Ether packet
                self.handle_pkt(packet)  # Process the packet with Scapy
        except KeyboardInterrupt:
            logging.info("Stopping packet capture")
        except Exception as e:
            logging.error("Unexpected error during packet capture: %s", e)
        finally:
            self.raw_socket.close()  # Close the raw socket

    def start(self):
        """
        Starts the port scanner detection by capturing and processing packets.

        Errors:
            Logs an informational message upon exit due to KeyboardInterrupt.
        """
        logging.info("Starting port scanning detector")
        logging.info("Listening ports: %s", self.open_ports)
        self.sniff_raw_socket()

if __name__ == "__main__":
    local_ip = "192.168.64.4"
    iface = "enp0s1"
    ignore_ports = [22]

    detector = PortScannerDetector(iface, local_ip, ignore_ports)
    detector.start()
