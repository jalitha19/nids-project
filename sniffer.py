from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


def parse_packet(packet):
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src = ip_layer.src
    dst = ip_layer.dst
    proto = ip_layer.proto
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = tcp.flags
        sport = tcp.sport
        dport = tcp.dport
        print(f"[{timestamp}] TCP  {src}:{sport} -> {dst}:{dport}  flags={flags}")

    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"[{timestamp}] UDP  {src}:{udp.sport} -> {dst}:{udp.dport}")

    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print(f"[{timestamp}] ICMP {src} -> {dst}  type={icmp.type}")

    else:
        print(f"[{timestamp}] IP   {src} -> {dst}  proto={proto}")


def start_sniffer(interface=None, packet_count=0):
    print("[*] Starting packet sniffer...")
    print("[*] Press Ctrl+C to stop.\n")
    sniff(iface=interface, prn=parse_packet, count=packet_count, store=False)


if __name__ == "__main__":
    start_sniffer()