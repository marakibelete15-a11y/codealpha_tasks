from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

if __name__ == "__main__":
    print("Starting sniffer... capturing 3 packets on wlp0s20f3:")
    sniff(iface="wlp0s20f3", prn=packet_callback, count=3)
    print("Capture complete!")
