# Mini IDS

This repository contains my code a mini intrusion detection system (IDS). To simplify testing, this IDS is designed to detect attacks against the machine on which it is running. However, if one wanted to use this code as a true IDS for a network, they could sniff in promiscuous mode and the vast majority of the code would still function.\
\
The functionality of the IDS is split into discrete modules, which are defined below. This allows for maximum user customization, much like a real IDS.\
\
I aimed to achieve detection-in-breadth and detection-in-depth. To achieve detection-in-breadth, I developed modules to detect many different kinds of attacks. To achieve detection-in-depth, each module uses multiple mechanisms to detect an attack when possible. The specific attacks we detect are defined in the Modules section.

## File Structure

The directories in this project are as follows:

- **Modules**: The different IDS modules, each of which detects a different kind of attack.
- **Testing**: Modules to send custom packets to test different IDS modules. Many modules can be tested with tools like netcat or nmap; however, some require specialized packets that can't be easily sent with standard networking tools.
- **Sample Logs**: Sample logs from each IDS module. These constitute the output of my working tests.

## Modules

- **ARP Poisoning**: This module detects ARP poisoning attacks.
  - We get the initial ARP cache for this program by running and parsing the `arp -n` command.
  - We ensure each ARP response was solicited via a corresponding ARP request.
  - If we see any IP with more than one MAC address, we trigger an alert.
  - We monitor the volume of ARP responses, and if we see a spike (tracked via the exponential moving average of ARP replies by IP), we trigger an alert.
  - We allow users to define machines that should have fixed MAC addresses (e.g., important resources like the gateway). If we ever see a MAC address for those IPs that is different from the fixed value, we trigger an alert.
- **Brute Force**: This module detects brute force attacks via TCP (e.g., someone attempting to crack a password).
  - We monitor TCP traffic corresponding to each IP address and trigger an alert if traffic exceeds a fixed user-defined threshold.
  - We allow the user to define specific ports they want to monitor (e.g., SSH).
- **Exfiltration**: This module is designed to detect potential exfiltration of data over TCP from the local machine.
  - We monitor outgoing TCP traffic by destination IP and trigger an alert if it exceeds the historical moving average.
  - Network behavior likely changes significantly depending on the time of day. Therefore, we keep a set of moving averages for the day and another for the night and switch between them depending on the time of day.
  - This module has the potential to trigger false positives for legitimate user behavior (e.g., uploading a file to Google Drive). Therefore, whenever we trigger an alert, we make a DNS query for the destination IP to make a more informative log entry.
- **ICMP**: This module detects ICMP-based attacks, including the ping of death and denial of service attacks that use ICMP.
  - We store and reassemble fragmented ICMP packets. If any reassembled packets have a size greater than the maximum IP packet size, we trigger an alert.
  - We monitor the volume of ICMP echo request traffic, and trigger an alert if it exceeds the historical moving average.
- **Port Scanning**: This module is designed to detect port scans against our local machine for both IPv4 and IPv6. We use raw sockets to sniff instead of scapy to get practice working with raw sockets directly.
  - We get a list of open ports by running and parsing the `netstat -plntu` command.
  - We monitor the ports each IP address connects to. If a single IP attempts to connect to three ports in ascending or descending order, we trigger an alert.
  - If an IP attempts to connect to a port that isn't open, we trigger an alert.
- **Signatures**: This module detects fixed signatures defined by the user for UDP, TCP, DNS, and HTTP.
  - We read in a custom signature list for each protocol, and if we see a packet containing a match we trigger an alert.
- **Syn Flood**: This module detects a syn flood attack.
  - We monitor the number of half-open connections, and if it exceeds a user-defined threshold we trigger an alert.

## Testing

We tested this project by running it on a Multipass VM and sending packets to that VM from my main machine.  Sample testing outputs for each module can be found in the Sample Logs directory. We aimed to keep the logs as concise as possible while still testing the full functionality of each module.

- **ARP Poisoning**: This module was tested via the ARP-related functions in the Testing directory. We used different combinations of these functions to trigger different detection conditions.
- **Brute Force**: This code was developed on a Multipass VM with the VSCode SSH extension, so we could effectively test it by instructing it to observe port 22.
- **Exfiltration**: Similar to the brute force module, we could effectively test this code by telling it to ignore communications with the machine the VM was running on and observing all other outgoing traffic.
- **ICMP**: This code was tested with the ping command and the functions in the ICMP testing module.
- **Port Scanning**: This code was tested with the netcat command on closed ports and attempting to connect to sequential ports. However, nmap would also be a good way to test this code.
- **Signatures**: This code was tested with command-line utilities like netcat.
- **Syn Flood**: This code was tested with the functions in the TCP testing module
