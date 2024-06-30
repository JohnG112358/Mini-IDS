'''
Class to detect ARP poisioning
'''

from scapy.all import ARP, sniff
import subprocess
import re
from threading import Thread, Lock
import time
import logging

class ARPPoisoningDetector:
    """
    A class to detect ARP poisoning attacks by monitoring ARP traffic and maintaining an ARP cache.

    Attributes:
        static_pairs (dict): A dictionary of IP to MAC address mappings for static checking.
        alpha (float): Smoothing factor for the exponential moving average of ARP requests.
        arp_cache (dict): A dictionary to store the current ARP cache.
        arp_requests (dict): A dictionary to store ARP requests.
        request_volume (dict): A dictionary to store the volume of ARP requests.
        moving_averages (dict): A dictionary to store the moving averages of ARP requests.
        cache_lock (Lock): A lock to synchronize access to the ARP cache.
        requests_lock (Lock): A lock to synchronize access to the request volume and moving averages.
    """

    def __init__(self, static_pairs, alpha=0.6):
        """
        Initializes the ARPPoisoningDetector with static IP-MAC pairs and optional smoothing factor.

        Args:
            static_pairs (dict): A dictionary mapping IP addresses to their static MAC addresses.
            alpha (float): Smoothing factor for the exponential moving average. Defaults to 0.6.
        """
        self.arp_cache = self.read_arp_cache()
        self.arp_requests = {}
        self.static_pairs = static_pairs
        self.request_volume = {}
        self.moving_averages = {}
        self.alpha = alpha
        self.cache_lock = Lock()
        self.requests_lock = Lock()

        # Configure logging to file and console
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("arp_poisoning_detector.log"),
                                logging.StreamHandler()
                            ])
        
        logging.info("Initial ARP cache: %s", self.arp_cache)

    def read_arp_cache(self):
        """
        Reads the current ARP cache from the system and parses it into a dictionary.

        Returns:
            dict: A dictionary with IP addresses as keys and sets of MAC addresses as values.

        Errors:
            Logs an error if the ARP cache cannot be read.
        """
        command = "arp -n"
        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+.*?(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)") # regex to parse command output
        arp_dict = {}

        try:
            result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = result.stdout
        except subprocess.CalledProcessError as e:
            logging.error("Failed to read ARP cache: %s", e)
            return {}

        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip, mac = match.groups()
                if ip not in arp_dict:
                    arp_dict[ip] = {mac}
                else:
                    arp_dict[ip].add(mac)
                    logging.warning(f"IP {ip} has multiple MACs: {arp_dict[ip]}. THIS IS A SIGN OF MAC SPOOFING")
            
        return arp_dict

    def handle_pkt(self, pkt):
        """
        Handles incoming ARP packets, updating the ARP cache and tracking request volumes.

        Args:
            pkt: The packet to handle.
        """
        if ARP in pkt:
            if pkt[ARP].op == 1:
                with self.cache_lock:
                    self.arp_requests[pkt[ARP].psrc] = pkt[ARP].pdst
                    
            if pkt[ARP].op == 2:
                src_ip = pkt[ARP].psrc  
                dst_ip = pkt[ARP].pdst
                mac = pkt[ARP].hwsrc  

                with self.cache_lock:
                    if dst_ip in self.arp_requests and self.arp_requests[dst_ip] == src_ip:
                        logging.info(f"Valid ARP response received from {src_ip} to {dst_ip}")
                    else:
                        logging.warning(f"Unsolicited ARP response detected from {src_ip} to {dst_ip}")

                    if src_ip in self.arp_cache:
                        self.arp_cache[src_ip].add(mac)
                        if len(self.arp_cache[src_ip]) >= 2:
                            logging.warning(f"IP {src_ip} has multiple MACs: {self.arp_cache[src_ip]}")
                    else:
                        self.arp_cache[src_ip] = {mac}
            
                with self.requests_lock:
                    if src_ip not in self.request_volume:
                        self.request_volume[src_ip] = 0
                    if src_ip not in self.moving_averages:
                        self.moving_averages[src_ip] = 1 # set to 1 to avoid a false positive on the first legitimate request
                    self.request_volume[src_ip] += 1

    def static_pair_checking(self):
        """
        Periodically checks the ARP cache against static IP-MAC pairs to detect inconsistencies.
        """
        while True:
            time.sleep(5)
            for ip, mac in self.static_pairs.items():
                with self.cache_lock:
                    if ip in self.arp_cache:
                        if len(self.arp_cache[ip]) > 1:
                            logging.warning(f"Fixed IP {ip} has multiple MACs: {self.arp_cache[ip]}. Something is wrong")
                        if mac not in self.arp_cache[ip]:
                            logging.warning(f"Fixed IP {ip} is not associated with its fixed MAC address: {mac}. Something is wrong")

    def update_ema(self):
        """
        Updates the exponential moving average of ARP request volumes.
        """
        for ip, past_average in self.moving_averages.items(): # only called from within scope that has "self.requests_lock"
            count = 0
            if ip in self.request_volume:
                count = self.request_volume[ip]
            self.moving_averages[ip] = self.alpha * count + (1 - self.alpha) * past_average

    def check_volume(self):
        """
        Periodically checks ARP request volumes against their moving averages to detect anomalies.
        """
        while True:
            time.sleep(3)
            above_vol = False
            with self.requests_lock:
                for ip, num in self.request_volume.items():
                    if num > self.moving_averages[ip]:
                        logging.warning(f"{ip} has sent {num} ARP replies in the last second. This is above the exponential moving average {self.moving_averages[ip]} of ARP replies it has sent")
                        above_vol = True
                if not above_vol:
                    logging.info("All ARP replies below historical moving averages")
                self.update_ema()
                self.request_volume = {}

    def start(self):
        """
        Starts the ARP poisoning detector, including the static pair checking and volume checking threads,
        and begins sniffing ARP packets.

        Errors:
            Logs an informational message upon exit due to KeyboardInterrupt.
        """
        self.static_pair_thread = Thread(target=self.static_pair_checking)
        self.static_pair_thread.daemon = True
        self.static_pair_thread.start()

        self.volume_thread = Thread(target=self.check_volume)
        self.volume_thread.daemon = True 
        self.volume_thread.start()

        logging.info("Starting ARP poisoning detector")

        try:
            sniff(prn=self.handle_pkt, filter="arp", store=False)
        except KeyboardInterrupt:
            logging.info("Exiting ARP poisoning detector")

if __name__ == "__main__":
    static_pairs = {'ip': 'mac'}  # MAC addresses of important machines we know and don't want changed
    detector = ARPPoisoningDetector(static_pairs)
    detector.start()
    