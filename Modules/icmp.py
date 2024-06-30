'''
Class to detect icmp ping of death attacks and icmp-based denial of service attacks
'''

import time
from threading import Thread, Lock
from scapy.all import ICMP, IP, sniff
import logging

class ICMPDetector:
    """
    A class to detect potential ICMP-based attacks by monitoring ICMP traffic.

    Attributes:
        local_ip (str): The local IP address to monitor.
        alpha (float): Smoothing factor for the exponential moving average of ICMP requests.
        request_volume (dict): A dictionary to store the volume of ICMP requests per source IP.
        moving_averages (dict): A dictionary to store the moving averages of ICMP requests per source IP.
        fragments (dict): A dictionary to store information about fragmented ICMP packets.
        requests_lock (Lock): A lock to synchronize access to the request volume and moving averages.
    """

    def __init__(self, local_ip, alpha=0.6):
        """
        Initializes the ICMPDetector with the local IP and optional smoothing factor.

        Args:
            local_ip (str): The local IP address to monitor.
            alpha (float): Smoothing factor for the exponential moving average. Defaults to 0.6.
        """
        self.local_ip = local_ip
        self.alpha = alpha
        self.request_volume = {}  # Dictionary to track ICMP request counts
        self.moving_averages = {}  # Dictionary to store moving averages of ICMP requests
        self.fragments = {}  # Dictionary to store fragmented packet information
        self.requests_lock = Lock()  # Lock for synchronizing access to request volume and moving averages

        # Configure logging to file and console
        logging.basicConfig(level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s',
                            handlers=[
                                logging.FileHandler("icmp_detector.log"),
                                logging.StreamHandler()
                            ])

    def update_ema(self):
        """
        Updates the exponential moving average of ICMP request volumes.
        """
        for ip, past_average in self.moving_averages.items():
            count = 0
            if ip in self.request_volume:
                count = self.request_volume[ip]  # Get the request count for the IP
            self.moving_averages[ip] = self.alpha * count + (1 - self.alpha) * past_average  # Update moving average

    def check_volume(self):
        """
        Periodically checks ICMP request volumes against their moving averages to detect anomalies.
        """
        while True:
            time.sleep(3)  # Sleep for 3 seconds before checking volumes
            above_vol = False
            with self.requests_lock:
                for ip, num in self.request_volume.items():
                    if num > self.moving_averages[ip]:
                        logging.warning(f"{ip} has sent {num} ICMP echo requests in the last second. This is above the exponential moving average {self.moving_averages[ip]} of ICMP echo requests it has sent")
                        above_vol = True
                if not above_vol:
                    logging.info("All ICMP echo requests below historical moving averages")
                self.update_ema()  # Update exponential moving averages
                self.request_volume = {}  # Reset request volume

    def handle_pkt(self, pkt):
        """
        Handles incoming packets and updates request statistics and fragmentation info.

        Args:
            pkt: The packet to handle.
        """
        if IP not in pkt:
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        packet_id = pkt[IP].id
        frag_offset = pkt[IP].frag
        mf_flag = pkt[IP].flags.MF  # More Fragments flag

        if pkt.haslayer(ICMP) and dst_ip:
            ICMP_type = pkt[ICMP].type
            ICMP_code = pkt[ICMP].code

            # Handle fragmented packets
            if (src_ip, dst_ip, packet_id) not in self.fragments:
                self.fragments[(src_ip, dst_ip, packet_id)] = {'fragments': [], 'total_len': 0, 'max_offset': None}

            fragment_entry = self.fragments[(src_ip, dst_ip, packet_id)]
            fragment_entry['fragments'].append((frag_offset, len(pkt)))
            fragment_entry['total_len'] += len(pkt)

            if mf_flag == 0 or (fragment_entry['max_offset'] is None or frag_offset > fragment_entry['max_offset']):
                fragment_entry['max_offset'] = frag_offset

            # reassemble fragments
            expected_total_length = sum(frag[1] for frag in fragment_entry['fragments'])
            if fragment_entry['max_offset'] is not None and expected_total_length == fragment_entry['total_len']:
                if fragment_entry['total_len'] > 65507:
                    logging.warning(f"Potential fragmented Ping of Death attack detected from {src_ip}. Total size: {fragment_entry['total_len']} bytes")

                del self.fragments[(src_ip, dst_ip, packet_id)]

            # Handle ICMP echo requests
            if int(ICMP_type) == 8 and int(ICMP_code) == 0:
                with self.requests_lock:
                    if src_ip not in self.request_volume:
                        self.request_volume[src_ip] = 0
                    if src_ip not in self.moving_averages:
                        self.moving_averages[src_ip] = 1  # Initialize moving average to 1 to avoid false positives
                    self.request_volume[src_ip] += 1  # Increment request volume for the source IP

    def start(self):
        """
        Starts the ICMP detection, including the monitoring thread,
        and begins sniffing ICMP packets.

        Errors:
            Logs an informational message upon exit due to KeyboardInterrupt.
        """
        monitor_thread = Thread(target=self.check_volume)
        monitor_thread.daemon = True  # Set thread as daemon
        monitor_thread.start()  # Start monitoring thread

        logging.info("Starting ICMP detector")

        try:
            sniff(prn=self.handle_pkt, filter="icmp", store=False)  # Start sniffing ICMP packets
        except KeyboardInterrupt:
            logging.info("Exiting ICMP detector")

if __name__ == "__main__":
    local_ip = "ip"
    detector = ICMPDetector(local_ip)
    detector.start()
