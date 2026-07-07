#!/usr/bin/env python3
"""
Offline analysis of a packet capture CSV log produced by packet_analyzer.py.
Summarizes protocol distribution, top talkers, and potential SYN-flood
patterns using pandas.
"""

import argparse
import pandas as pd


def analyze(csv_file):
    df = pd.read_csv(csv_file)

    print(f"Loaded {len(df)} packets from {csv_file}\n")

    print("Protocol distribution:")
    print(df["protocol"].value_counts().to_string())
    print()

    print("Top 5 source IPs by packet count:")
    print(df["src_ip"].value_counts().head(5).to_string())
    print()

    tcp_df = df[df["protocol"] == "TCP"]
    if not tcp_df.empty:
        syn_only = tcp_df[tcp_df["flags"].astype(str).str.contains("S", na=False) &
                           ~tcp_df["flags"].astype(str).str.contains("A", na=False)]
        print("Top sources sending SYN packets (potential scans):")
        print(syn_only["src_ip"].value_counts().head(5).to_string())
        print()

    print("Average packet length:", round(df["length"].mean(), 2), "bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze packet_analyzer.py CSV logs")
    parser.add_argument("csv_file", help="Path to capture_log.csv")
    args = parser.parse_args()
    analyze(args.csv_file)
