import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

from engine import DetectionEngine
from output import handle_alert


engine = DetectionEngine()


def parse_packet(packet):
    if not packet.haslayer(IP):
        return

    ip = packet[IP]
    packet_info = {"src": ip.src, "dst": ip.dst}

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        packet_info.update({
            "proto": "TCP",
            "sport": tcp.sport,
            "dport": tcp.dport,
            "flags": str(tcp.flags),
        })

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        packet_info.update({
            "proto": "UDP",
            "sport": udp.sport,
            "dport": udp.dport,
        })

    elif packet.haslayer(ICMP):
        packet_info.update({
            "proto": "ICMP",
            "icmp_type": packet[ICMP].type,
        })

    else:
        packet_info["proto"] = "OTHER"

    alerts = engine.analyze(packet_info)
    for alert in alerts:
        handle_alert(alert)


def main():
    parser = argparse.ArgumentParser(description="Lightweight Network Intrusion Detection System")
    parser.add_argument("-i", "--interface", default=None, help="Network interface to sniff on (e.g. eth0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    args = parser.parse_args()

    print("\n  NIDS - Lightweight Network Intrusion Detection System")
    print("  -------------------------------------------------------")
    if args.interface:
        print(f"  Interface : {args.interface}")
    else:
        print("  Interface : default")
    print(f"  Log file  : alerts.json")
    print("  Press Ctrl+C to stop.\n")

    sniff(iface=args.interface, prn=parse_packet, count=args.count, store=False)


if __name__ == "__main__":
    main()
