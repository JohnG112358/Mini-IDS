'''
CS 60 Final Project
John Guerrerio

Class to detect potential data exfiltration via TCP
'''

import socket
from threading import Thread, Lock
import time
from scapy.all import IP, TCP, sniff
import datetime
import logging

class ExfiltrationDetector:
    """
    A class to detect potential data exfiltration by monitoring outgoing TCP traffic.

    Attributes:
        local_ip (str): The local IP address to monitor.
        known_hosts (list): A list of known host IPs to ignore.
        alpha (float): Smoothing factor for the exponential moving average of outgoing packets.
        outgoing_volume (dict): A dictionary to store the volume of outgoing packets.
        moving_averages_day (dict): A dictionary to store the moving averages of outgoing packets during the day.
        moving_averages_night (dict): A dictionary to store the moving averages of outgoing packets during the night.
        morning (datetime.time): The start time of the day period.
        night (datetime.time): The start time of the night period.
        outgoing_lock (Lock): A lock to synchronize access to the outgoing volume.
    """

    def __init__(self, local_ip, known_hosts, alpha=0.6):
        """
        Initializes the ExfiltrationDetector with the local IP, known hosts, and optional smoothing factor.

        Args:
            local_ip (str): The local IP address to monitor.
            known_hosts (list): A list of known host IP addresses to ignore.
            alpha (float): Smoothing factor for the exponential moving average. Defaults to 0.6.
        """
        self.local_ip = local_ip
        self.known_hosts = known_hosts
        self.alpha = alpha
        self.outgoing_volume = {}  # Dictionary to track outgoing packet volume
        self.moving_averages_day = {}  # Moving averages for daytime traffic
        self.moving_averages_night = {}  # Moving averages for nighttime traffic
        self.morning = datetime.time(8, 0)  # Start time of the day period
        self.night = datetime.time(20, 0)  # Start time of the night period
        self.outgoing_lock = Lock()  # Lock for synchronizing access to outgoing volume

        # Configure logging to file and console
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("exfiltration_detector.log"),
                                logging.StreamHandler()
                            ])

    def get_hostname_from_ip(self, ip_address):
        """
        Resolves the hostname from an IP address.

        Args:
            ip_address (str): The IP address to resolve.

        Returns:
            str: The resolved hostname or an error message if resolution fails.

        Errors:
            Logs errors for various DNS resolution issues.
        """
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except socket.herror as e:
            logging.error(f"No DNS entry found for IP {ip_address}: {e}")
            return f"No DNS entry found for IP {ip_address}"
        except socket.gaierror as e:
            logging.error(f"DNS resolution failed for IP {ip_address}: {e}")
            return f"DNS resolution failed for IP {ip_address}"
        except Exception as e:
            logging.error(f"An unexpected error occurred while resolving IP {ip_address}: {e}")
            return f"An unexpected error occurred"

    def update_ema(self, moving_averages):
        """
        Updates the exponential moving average of outgoing packet volumes.

        Args:
            moving_averages (dict): The dictionary of moving averages to update.
        """
        for ip, past_average in moving_averages.items():
            count = 0
            if ip in self.outgoing_volume:
                count = self.outgoing_volume[ip]
            moving_averages[ip] = self.alpha * count + (1 - self.alpha) * past_average

    def check_volume(self):
        """
        Periodically checks outgoing packet volumes against their moving averages to detect anomalies.
        """
        while True:
            current_time = datetime.datetime.now().time()
            if current_time > self.morning and current_time < self.night:
                moving_averages = self.moving_averages_day  # Use daytime moving averages
            else:
                moving_averages = self.moving_averages_night  # Use nighttime moving averages

            time.sleep(3)  # Sleep for 3 seconds before checking volume
            above_vol = False
            with self.outgoing_lock:
                for ip, num in self.outgoing_volume.items():
                    if num > moving_averages[ip]:
                        logging.warning(f"We have sent {num} TCP packets to {ip} (domain name: {self.get_hostname_from_ip(ip)}) - this is above the historical average of {moving_averages[ip]} and could be indicative of exfiltration")
                        above_vol = True
                if not above_vol:
                    logging.info("All outgoing TCP packet levels below historical averages")
                self.update_ema(moving_averages)  # Update exponential moving averages
                self.outgoing_volume = {}  # Reset outgoing volume

    def handle_pkt(self, pkt):
        """
        Handles incoming packets and updates outgoing volume statistics.

        Args:
            pkt: The packet to handle.
        """
        if IP not in pkt or TCP not in pkt:
            return  # Ignore non-IP/TCP packets

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if src_ip != self.local_ip or dst_ip in self.known_hosts:
            return  # Ignore packets not from local IP or to known hosts

        current_time = datetime.datetime.now().time()
        if current_time > self.morning and current_time < self.night:
            moving_averages = self.moving_averages_day  # Use daytime moving averages
        else:
            moving_averages = self.moving_averages_night  # Use nighttime moving averages

        with self.outgoing_lock:
            if dst_ip not in self.outgoing_volume:
                self.outgoing_volume[dst_ip] = 0
            if dst_ip not in moving_averages:
                moving_averages[dst_ip] = 1  # Initialize moving average to 1 to avoid false positives
            self.outgoing_volume[dst_ip] += 1  # Increment outgoing volume for the destination IP

    def start(self):
        """
        Starts the exfiltration detector, including the volume checking thread,
        and begins sniffing TCP packets.

        Errors:
            Logs an informational message upon exit due to KeyboardInterrupt.
        """
        self.vol_thread = Thread(target=self.check_volume)
        self.vol_thread.daemon = True  # Set thread as daemon
        self.vol_thread.start()  # Start volume checking thread

        logging.info("Starting exfiltration detector")

        try:
            sniff(prn=self.handle_pkt, filter="tcp", store=False)  # Start sniffing TCP packets
        except KeyboardInterrupt:
            logging.info("Exiting exfiltration detector")

if __name__ == "__main__":
    known_hosts = ["192.168.64.1"]  # Servers we know we are going to upload data to (e.g. Google Drive) - this is the ip of my actual machine the multipass VM is running on
    local_ip = "192.168.64.4"
    detector = ExfiltrationDetector(local_ip, known_hosts)
    detector.start()
    