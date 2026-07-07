#!/usr/bin/env python3
"""
Network Packet Analyzer
------------------------
A command-line tool to capture, parse, and log live network traffic.
Decodes Ethernet, IP, TCP/UDP, and ICMP headers, supports filtering by
IP/port/protocol, logs results to CSV, and flags simple SYN-scan style
anomalies for basic security monitoring.

Author: Pragati Sharma
"""

import argparse
import csv
import socket
import struct
import time
from collections import defaultdict, deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether
except ImportError:
    print("This tool requires scapy. Install it with: pip install scapy")
    raise SystemExit(1)


class PacketAnalyzer:
    def __init__(self, args):
        self.args = args
        self.log_rows = []
        self.syn_tracker = defaultdict(lambda: deque(maxlen=50))
        self.packet_count = 0

    # ---------- Filtering ----------
    def passes_filter(self, pkt):
        if IP not in pkt:
            return False
        ip_layer = pkt[IP]

        if self.args.src_ip and ip_layer.src != self.args.src_ip:
            return False
        if self.args.dst_ip and ip_layer.dst != self.args.dst_ip:
            return False

        if self.args.protocol:
            proto = self.args.protocol.upper()
            if proto == "TCP" and TCP not in pkt:
                return False
            if proto == "UDP" and UDP not in pkt:
                return False
            if proto == "ICMP" and ICMP not in pkt:
                return False

        if self.args.port:
            port = int(self.args.port)
            sport = pkt.sport if hasattr(pkt, "sport") else None
            dport = pkt.dport if hasattr(pkt, "dport") else None
            if port not in (sport, dport):
                return False

        return True

    # ---------- Parsing ----------
    def parse_packet(self, pkt):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        ip_layer = pkt[IP]
        proto_name = "OTHER"
        sport = dport = flags = seq = ack = ""

        if TCP in pkt:
            proto_name = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
            seq, ack = pkt[TCP].seq, pkt[TCP].ack
        elif UDP in pkt:
            proto_name = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto_name = "ICMP"

        row = {
            "timestamp": timestamp,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": proto_name,
            "src_port": sport,
            "dst_port": dport,
            "flags": flags,
            "seq": seq,
            "ack": ack,
            "length": len(pkt),
        }
        return row

    # ---------- Simple anomaly detection ----------
    def check_syn_scan(self, row):
        """Flag repeated SYN packets from same source to many ports quickly."""
        if row["protocol"] != "TCP" or "S" not in row["flags"] or "A" in row["flags"]:
            return
        key = row["src_ip"]
        self.syn_tracker[key].append((row["dst_port"], time.time()))

        recent = [p for p, t in self.syn_tracker[key] if time.time() - t < 5]
        unique_ports = set(recent)
        if len(unique_ports) >= 8:
            print(f"[ALERT] Possible port scan from {key} -> {len(unique_ports)} ports in <5s")

    # ---------- Output ----------
    def print_packet(self, row):
        print(
            f"{row['timestamp']} | {row['protocol']:5} | "
            f"{row['src_ip']}:{row['src_port']} -> {row['dst_ip']}:{row['dst_port']} "
            f"| flags={row['flags']} | len={row['length']}"
        )

    def handle_packet(self, pkt):
        if not self.passes_filter(pkt):
            return
        row = self.parse_packet(pkt)
        self.print_packet(row)
        self.log_rows.append(row)
        self.check_syn_scan(row)
        self.packet_count += 1

    def save_csv(self, filename="capture_log.csv"):
        if not self.log_rows:
            print("No packets captured; nothing to save.")
            return
        keys = self.log_rows[0].keys()
        with open(filename, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.log_rows)
        print(f"\nSaved {len(self.log_rows)} packets to {filename}")

    def run(self):
        print("Starting capture... Press Ctrl+C to stop.\n")
        try:
            sniff(prn=self.handle_packet, count=self.args.count or 0, timeout=self.args.timeout)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            print("Permission denied: packet capture requires root/administrator privileges.")
            return
        finally:
            self.save_csv(self.args.output)
            print(f"Total packets processed: {self.packet_count}")


def parse_args():
    parser = argparse.ArgumentParser(description="Python Network Packet Analyzer")
    parser.add_argument("--src-ip", help="Filter by source IP")
    parser.add_argument("--dst-ip", help="Filter by destination IP")
    parser.add_argument("--port", help="Filter by source or destination port")
    parser.add_argument("--protocol", help="Filter by protocol: TCP, UDP, ICMP")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--timeout", type=int, default=None, help="Capture duration in seconds")
    parser.add_argument("--output", default="capture_log.csv", help="CSV output filename")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    analyzer = PacketAnalyzer(args)
    analyzer.run()
