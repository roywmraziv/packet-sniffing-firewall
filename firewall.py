from scapy.all import sniff, IP

# list of IPs to block/sniff
blocked_ips = ['192.168.1.75']

def packet_callback(packet):
    # check if hte packet has an IP layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # check if the source or destination IP is in the blocked list
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            print(f"Blocked packet: {packet.summary()}")
        else:
            print(f"Allowed packet: {packet.summary()}")
    else:
        print(f"Non-IP packet: {packet.summary()}")

print("Starting the firewall...")

# start sniffing packets
sniff(prn=packet_callback, store = 0)