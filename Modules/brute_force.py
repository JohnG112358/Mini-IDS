'''
Class to detect potential brute force attacks via TCP
'''

from scapy.all import sniff, IP, TCP
from collections import defaultdict
from threading import Thread, Lock
import time
import logging

class BruteForceDetection:
    """
    A class to detect potential brute force attacks by monitoring TCP traffic.

    Attributes:
        services (list): A list of service ports to monitor for brute force attempts.
        threshold (int): The number of attempts to trigger a brute force alert.
        attempts (defaultdict): A dictionary to track the number of attempts per (IP, port) pair.
        attempts_lock (Lock): A lock to synchronize access to the attempts dictionary.
    """

    def __init__(self, services, threshold=10):
        """
        Initializes the TCPGeneralDetection with the services to monitor and optional threshold.

        Args:
            services (list): A list of service ports to monitor.
            threshold (int): The number of attempts to trigger a brute force alert. Defaults to 10.
        """
        self.services = services
        self.threshold = threshold
        self.attempts = defaultdict(int)  # Dictionary to track attempt counts
        self.attempts_lock = Lock()  # Lock for synchronizing access to attempts

        # Configure logging to file and console
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("brute_force_detection.log"),
                                logging.StreamHandler()
                            ])

    def handle_pkt(self, pkt):
        """
        Handles incoming packets and updates attempt statistics.

        Args:
            pkt: The packet to handle.
        """
        if IP in pkt:
            ip_layer = pkt[IP]
            src_ip = pkt[IP].src  # Source IP address

            if TCP in pkt:
                dport = pkt[TCP].dport  # Destination port
                if dport in self.services:
                    with self.attempts_lock:
                        self.attempts[(src_ip, dport)] += 1  # Increment attempt count for the (IP, port) pair
        
    def monitor_brute_force(self):
        """
        Periodically checks attempt counts against the threshold to detect brute force attacks.
        """
        while True:
            time.sleep(3)  # Sleep for 3 seconds before checking attempts
            with self.attempts_lock:
                for pair, amount in self.attempts.items():
                    if amount > self.threshold:
                        logging.warning(f"Potential brute force attack detected from {pair[0]} - sent {amount} TCP packets to port {pair[1]}")
            self.attempts.clear()  # Clear attempts after checking

    def start(self):
        """
        Starts the TCP brute force detection, including the monitoring thread,
        and begins sniffing TCP packets.

        Errors:
            Logs an informational message upon exit due to KeyboardInterrupt.
        """
        monitor = Thread(target=self.monitor_brute_force)
        monitor.daemon = True  # Set thread as daemon
        monitor.start()  # Start monitoring thread
        
        logging.info("Starting TCP brute force detector")

        try:
            sniff(prn=self.handle_pkt, filter="tcp", store=False)  # Start sniffing TCP packets
        except KeyboardInterrupt:
            logging.info("Exiting TCP detection module")

if __name__ == "__main__":
    services = [22, 78]  # Port numbers we want to detect brute forcing for
    detector = BruteForceDetection(services)
    detector.start()
