'''
CS 60 Final Project
John Guerrerio

Class to detect SYN flood attacks
'''

from scapy.all import sniff, TCP, IP
from collections import defaultdict
from threading import Thread, Lock
import time
import logging

class SYNFloodDetector:
    """
    A class to detect potential SYN flood attacks by monitoring TCP SYN and ACK packets.

    Attributes:
        connection_attempts (defaultdict): A dictionary to track SYN packets per source IP.
        completed_connections (defaultdict): A dictionary to track completed connections (ACK packets) per source IP.
        connections_lock (Lock): A lock to synchronize access to the connection dictionaries.
        threshold (int): The number of incomplete connections to trigger a flood warning.
    """

    def __init__(self, threshold=3):
        """
        Initializes the SYNFloodDetector with an optional threshold.

        Args:
            threshold (int): The number of incomplete connections to trigger a flood warning. Defaults to 3.
        """
        self.connection_attempts = defaultdict(int)  # Track SYN packets per source IP
        self.completed_connections = defaultdict(int)  # Track ACK packets per source IP
        self.connections_lock = Lock()  # Lock for synchronizing access to connection dictionaries
        self.threshold = threshold  # Threshold for detecting SYN flood
        
        # Configure logging to file and console
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("syn_flood_detector.log"),
                                logging.StreamHandler()
                            ])

    def handle_pkt(self, pkt):
        """
        Handles incoming packets and updates connection statistics.

        Args:
            pkt: The packet to handle.
        """
        if IP not in pkt or TCP not in pkt or not pkt[TCP].flags:
            return

        src_ip = pkt[IP].src  # Source IP address
        tcp_flags = pkt[TCP].flags  # TCP flags

        with self.connections_lock:
            if 'S' in tcp_flags and 'A' not in tcp_flags:  # SYN packet without ACK
                self.connection_attempts[src_ip] += 1
            elif 'A' in tcp_flags:  # ACK packet
                self.completed_connections[src_ip] += 1

    def monitor_syns(self):
        """
        Periodically checks for incomplete connections to detect SYN flood attacks.
        """
        while True:
            time.sleep(3)  # Sleep for 3 seconds before checking connections
            with self.connections_lock:
                incomplete_connections = 0
                for ip in self.connection_attempts:
                    extra_syns = max(self.connection_attempts[ip] - self.completed_connections[ip], 0)  # Count SYNs without corresponding ACKs
                    incomplete_connections += extra_syns
                if incomplete_connections > self.threshold:
                    logging.warning(f"Received {incomplete_connections} SYNs without ACKs in the last 3 seconds. This could be indicative of a SYN flood.")

            self.connection_attempts.clear()  # Clear connection attempts
            self.completed_connections.clear()  # Clear completed connections

    def start(self):
        """
        Starts the SYN flood detection, including the monitoring thread,
        and begins sniffing TCP packets.
        """
        monitor = Thread(target=self.monitor_syns)
        monitor.daemon = True  # Set thread as daemon
        monitor.start()  # Start monitoring thread
        
        logging.info("Starting SYN flood detector")

        try:
            sniff(prn=self.handle_pkt, filter="tcp", store=False)  # Start sniffing TCP packets
        except KeyboardInterrupt:
            logging.info("Exiting SYN flood detector")

if __name__ == "__main__":
    detector = SYNFloodDetector(threshold=3)
    detector.start()
    