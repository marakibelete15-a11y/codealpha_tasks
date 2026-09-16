import argparse
import csv
from datetime import datetime
import os
import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Global capture statistics
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "other": 0,
}

CSV_FILE = os.path.join("results", "capture.csv")


def init_csv(filepath):
    """Ensure the target directory exists and initialize the CSV file with headers."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    headers = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "source_port",
        "destination_port",
        "tcp_flags",
        "packet_length",
        "payload_length",
    ]
    with open(filepath, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)


def save_record_to_csv(filepath, record):
    """Append a single parsed packet record to the CSV file."""
    with open(filepath, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(record)


def get_safe_payload_preview(payload_bytes, max_bytes=32):
    """
    Produce a safe, truncated ASCII preview of the payload bytes.
    Non-printable characters are sanitized to '.' to prevent terminal distortion.
    """
    if not payload_bytes:
        return "None"

    preview_slice = payload_bytes[:max_bytes]
    safe_chars = [chr(b) if 32 <= b <= 126 else "." for b in preview_slice]
    preview_str = "".join(safe_chars)
    if len(payload_bytes) > max_bytes:
        preview_str += "..."
    return preview_str


def packet_callback(packet):
    """
    Process each captured packet: analyze protocol headers, evaluate payloads,
    update statistics, print formatted summary, and log to CSV.
    """
    stats["total"] += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    packet_len = len(packet)

    # Step 14: Evaluate payload
    payload_len = 0
    payload_preview = "None"
    if packet.haslayer(Raw):
        payload_bytes = bytes(packet[Raw].load)
        payload_len = len(payload_bytes)
        payload_preview = get_safe_payload_preview(payload_bytes)

    # Analyze IP Layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # TCP Analysis
        if packet.haslayer(TCP):
            stats["tcp"] += 1
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = str(packet[TCP].flags)
            print(f"\n[+] [{timestamp}] IP Packet: {src_ip} -> {dst_ip}")
            print(f"    Protocol: TCP | Ports: {src_port} -> {dst_port} | Flags: {flags}")

        # UDP Analysis
        elif packet.haslayer(UDP):
            stats["udp"] += 1
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            flags = "N/A"
            print(f"\n[+] [{timestamp}] IP Packet: {src_ip} -> {dst_ip}")
            print(f"    Protocol: UDP | Ports: {src_port} -> {dst_port}")

        # ICMP Analysis
        elif packet.haslayer(ICMP):
            stats["icmp"] += 1
            proto = "ICMP"
            src_port = "N/A"
            dst_port = "N/A"
            flags = "N/A"
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            print(f"\n[+] [{timestamp}] IP Packet: {src_ip} -> {dst_ip}")
            print(f"    Protocol: ICMP | Type: {icmp_type} | Code: {icmp_code}")

        # Other IP-based protocols (e.g. IGMP, OSPF, GRE)
        else:
            stats["other"] += 1
            proto = f"IP-Other ({packet[IP].proto})"
            src_port = "N/A"
            dst_port = "N/A"
            flags = "N/A"
            print(f"\n[+] [{timestamp}] IP Packet: {src_ip} -> {dst_ip} (Proto: {packet[IP].proto})")

        # Step 14: Display lengths & safe preview
        print(f"    Lengths: Total Packet = {packet_len} bytes | Payload = {payload_len} bytes")
        if payload_len > 0:
            print(f"    Payload Preview: {payload_preview}")

        # Step 17: Log to CSV
        save_record_to_csv(CSV_FILE, [
            timestamp,
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
            flags,
            packet_len,
            payload_len,
        ])

    else:
        # Non-IPv4 packets (ARP, IPv6, STP, etc.)
        stats["other"] += 1


def print_statistics(stats, protocol_filter):
    """Display final summary of captured packets and filter interaction."""
    total = stats["total"]
    print("\n" + "=" * 55)
    print("                TRAFFIC CAPTURE STATISTICS")
    print("=" * 55)
    print(f"  Active Filter   : {protocol_filter.upper()}")
    print(f"  Total Packets   : {total}")
    if total > 0:
        tcp_pct = (stats["tcp"] / total) * 100
        udp_pct = (stats["udp"] / total) * 100
        icmp_pct = (stats["icmp"] / total) * 100
        other_pct = (stats["other"] / total) * 100
        print(f"  - TCP Packets   : {stats['tcp']} ({tcp_pct:.1f}%)")
        print(f"  - UDP Packets   : {stats['udp']} ({udp_pct:.1f}%)")
        print(f"  - ICMP Packets  : {stats['icmp']} ({icmp_pct:.1f}%)")
        print(f"  - Other/Unknown : {stats['other']} ({other_pct:.1f}%)")
    else:
        print("  - No packets captured.")

    if protocol_filter != "all":
        print("-" * 55)
        print(f"  [i] Note: Kernel capture filter '{protocol_filter}' was active.")
        print(f"      Non-{protocol_filter.upper()} traffic was dropped before capture.")
    print("=" * 55)
    print(f"Results saved to: {CSV_FILE}\n")


def parse_arguments():
    """Configure command-line arguments using argparse."""
    parser = argparse.ArgumentParser(
        description="Educational Network Packet Sniffer and Analyzer (Authorized Monitoring Only)"
    )
    parser.add_argument(
        "--protocol",
        choices=["all", "tcp", "udp", "icmp"],
        default="all",
        help="Protocol filter to apply (choices: all, tcp, udp, icmp; default: all)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=10,
        help="Number of packets to capture (0 for continuous capture until Ctrl+C; default: 10)",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default="wlp0s20f3",
        help="Network interface to monitor (default: wlp0s20f3)",
    )
    return parser.parse_args()


def main():
    args = parse_arguments()

    # Determine BPF filter string based on selected protocol
    bpf_filter = None if args.protocol == "all" else args.protocol

    # Initialize CSV file with headers
    init_csv(CSV_FILE)

    count_label = f"{args.count} packets" if args.count > 0 else "unlimited packets (press Ctrl+C to stop)"
    print("=" * 55)
    print("       EDUCATIONAL PACKET SNIFFER & ANALYZER")
    print("=" * 55)
    print(f"Interface : {args.iface}")
    print(f"Filter    : {args.protocol.upper()}")
    print(f"Target    : {count_label}")
    print(f"Output CSV: {CSV_FILE}")
    print("=" * 55)
    print("[*] Starting packet capture... Press Ctrl+C to stop anytime.\n")

    try:
        sniff(
            iface=args.iface,
            prn=packet_callback,
            count=args.count,
            filter=bpf_filter,
            store=False,
        )
    except KeyboardInterrupt:
        print("\n\n[!] Capture interrupted by user.")
    except Exception as e:
        print(f"\n[!] Error during packet capture: {e}")

    # Display final statistics
    print_statistics(stats, args.protocol)


if __name__ == "__main__":
    main()
