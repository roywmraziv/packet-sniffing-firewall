### Network Packet Sniffer and Monitor ###
A cybersecurity project by Roy!

A simple network packet sniffer and monitor built using Python's Scapy library. This tool allows you to monitor, log, and analyze network traffic based on specific IP addresses. It supports TCP, UDP, and ICMP protocols, providing detailed information about each captured packet.

## Features ##
Packet Sniffing: Capture live network packets in real-time.
Protocol Support: Analyze TCP, UDP, and ICMP packets.
IP Filtering: Monitor specific IP addresses of interest.
Detailed Logging: Display source and destination IPs, ports, and ICMP types.
Extensible: Easily add more IPs or extend functionality as needed.

## Prerequisites ##
Python 3.6
Scapy Library

## Installation ##

1. Clone the Repository

   ```bash
   git clone https://github.com/yourusername/packet-sniffing-firewall.git
   cd network-packet-sniffer
   ```

2. Create a Virtual Environment (Optional but Recommended)

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install Dependencies

   ```bash
   pip install scapy
   ```

   *Note: Depending on your operating system, you might need additional permissions or libraries for Scapy to function correctly.*

## Usage ##

1. Configure Watched IPs

   Open the script and modify the `watched_ips` list to include the IP addresses you want to monitor or block.

   ```python
   watched_ips = ['192.168.1.75']
   ```

2. Run the Sniffer

   Execute the script with appropriate permissions (root/admin may be required to sniff network packets).

   ```bash
   sudo python sniff_packets.py
   ```
3. View Output
   The script will start capturing packets and display information based on the protocol and specified IPs.

   ```
   Starting the firewall...
   TCP Packet: 192.168.1.75:443 -> 10.0.0.5:53214
   UDP Packet: 10.0.0.5:53 -> 192.168.1.75:5353
   ICMP Packet: 192.168.1.75 -> 8.8.8.8 (Type 8)
   ```

## Configuration ##

Watched IPs
  Modify the `watched_ips` list in the script to include the IP addresses you want to monitor.
  ```python
  watched_ips = ['192.168.1.75', '10.0.0.1']
  ```

Filtering and Blocking

  Currently, the script logs packets related to the watched IPs. To extend functionality for blocking packets, additional logic can be implemented using Scapy's packet manipulation capabilities or integrating with firewall rules.

## Examples ##

Monitor Multiple IPs:
  ```python
  watched_ips = ['192.168.1.75', '10.0.0.1', '172.16.0.5']
  ```

Logging to a File:
Modify the `packet_callback` function to write logs to a file instead of printing to the console.

  ```python
  def packet_callback(packet):
      # existing code...
      with open('packet_logs.txt', 'a') as log_file:
          log_file.write(log_message + '\n')
  ```

## Contributing ##

Contributions are welcome! Please follow these steps:

1. Fork the Repository
2. Create a Feature Branch

   ```bash
   git checkout -b feature/YourFeature
   ```

3. Commit Your Changes

   ```bash
   git commit -m "Add your feature"
   ```

4. Push to the Branch

   ```bash
   git push origin feature/YourFeature
   ```

5. Open a Pull Request

Please ensure your code follows the project's coding standards and includes appropriate documentation.

## License ##

This project is licensed under the MIT License.

## Acknowledgments ##

- [Scapy](https://scapy.net/) - Powerful Python-based interactive packet manipulation tool.
- Inspired by various network monitoring tools and tutorials.
- Special thanks to Kaitlyn who always pushes me to be the best version of myself.
