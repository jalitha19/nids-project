from collections import defaultdict
from datetime import datetime
import time


THRESHOLDS = {
    "port_scan": {"count": 15, "window": 10},
    "syn_flood": {"count": 100, "window": 5},
    "icmp_sweep": {"count": 10, "window": 5},
    "ssh_brute": {"count": 5, "window": 30},
}


class DetectionEngine:
    def __init__(self):
        self.syn_tracker = defaultdict(list)
        self.icmp_tracker = defaultdict(list)
        self.ssh_tracker = defaultdict(list)
        self.scan_ports_tracker = defaultdict(lambda: defaultdict(set))

    def _prune(self, event_list, window):
        cutoff = time.time() - window
        return [t for t in event_list if t > cutoff]

    def _prune_ports(self, port_set_dict, window):
        cutoff = time.time() - window
        return {ts: ports for ts, ports in port_set_dict.items() if ts > cutoff}

    def check_port_scan(self, src_ip, dst_port):
        cfg = THRESHOLDS["port_scan"]
        now = time.time()

        bucket = int(now)
        self.scan_ports_tracker[src_ip][bucket].add(dst_port)
        self.scan_ports_tracker[src_ip] = self._prune_ports(
            self.scan_ports_tracker[src_ip], cfg["window"]
        )

        unique_ports = set()
        for ports in self.scan_ports_tracker[src_ip].values():
            unique_ports.update(ports)

        if len(unique_ports) >= cfg["count"]:
            return self._make_alert("PORT_SCAN", src_ip, "high",
                                    f"Scanned {len(unique_ports)} unique ports in {cfg['window']}s")
        return None

    def check_syn_flood(self, src_ip):
        cfg = THRESHOLDS["syn_flood"]
        now = time.time()

        self.syn_tracker[src_ip].append(now)
        self.syn_tracker[src_ip] = self._prune(self.syn_tracker[src_ip], cfg["window"])

        if len(self.syn_tracker[src_ip]) >= cfg["count"]:
            return self._make_alert("SYN_FLOOD", src_ip, "critical",
                                    f"{len(self.syn_tracker[src_ip])} SYN packets in {cfg['window']}s")
        return None


    def analyze(self, packet_info):
        alerts = []

        src_ip = packet_info.get("src")
        proto = packet_info.get("proto")
        dport = packet_info.get("dport")
        flags = packet_info.get("flags", "")

        if proto == "TCP":
            is_syn_only = "S" in str(flags) and "A" not in str(flags)

            if is_syn_only:
                alert = self.check_syn_flood(src_ip)
                if alert:
                    alerts.append(alert)

                alert = self.check_port_scan(src_ip, dport)
                if alert:
                    alerts.append(alert)

                if dport == 22:
                    alert = self.check_ssh_brute(src_ip)
                    if alert:
                        alerts.append(alert)

        elif proto == "ICMP":
            alert = self.check_icmp_sweep(src_ip)
            if alert:
                alerts.append(alert)

        return alerts

    def _make_alert(self, alert_type, src_ip, severity, detail):
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "alert_type": alert_type,
            "src_ip": src_ip,
            "severity": severity,
            "detail": detail,
        }
