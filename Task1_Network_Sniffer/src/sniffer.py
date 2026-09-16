from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    # Check if the packet contains an IPv4 layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        print(f"\n[+] IP Packet: {src_ip} -> {dst_ip}")

        # Check if the packet contains a TCP layer
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"    Protocol: TCP | Ports: {src_port} -> {dst_port} | Flags: {flags}")

        # Check if the packet contains a UDP layer
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"    Protocol: UDP | Ports: {src_port} -> {dst_port}")

        # Check if the packet contains an ICMP layer (e.g., ping)
        elif packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"    Protocol: ICMP | Type: {icmp_type} | Code: {icmp_code}")

if __name__ == "__main__":
    print("Starting sniffer... capturing 10 packets on wlp0s20f3:")
    sniff(iface="wlp0s20f3", prn=packet_callback, count=10)
    print("\nCapture complete!")
