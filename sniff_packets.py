from scapy.all import sniff, IP, TCP, UDP, ICMP

# list of IPs to block/sniff
watched_ips = ['192.168.1.75']

def packet_callback(packet):
    # check if hte packet has an IP layer
    if IP in packet: # checks if the packet has an IP layer
        # extracts the source and destination IPs from the packet
        src_ip = packet[IP].src 
        dst_ip = packet[IP].dst

        if TCP in packet: #checks if the packet contains a TCP layer
            # extracts the source TCP and destination TCP 
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif UDP in packet: #checks if the packet has UDP layer
            # extracts the source UDP and destination UDP
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        elif ICMP in packet: #checks if the packet has IMCP layer
            icmp_type = packet[ICMP].type # extracts the type of ICMP message
            print(f"ICMP Packet: {src_ip} -> {dst_ip} (Type {icmp_type})")

        else:
            print(f"IP Packet: {src_ip} -> {dst_ip}")

    else: # handle the packets without IP layer
        print(f"Non-IP packet: {packet.summary()}")

print("Starting the firewall...")

# start sniffing packets using scapy sniff method
# the 'prn' parameter represents the method to be ran on each packet sniffed
# store = 0 tells the program to not save any packets in memory 
sniff(prn=packet_callback, store = 0)