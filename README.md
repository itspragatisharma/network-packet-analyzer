# Network Packet Analyzer

A command-line tool written in Python that captures live network traffic, decodes protocol headers in real time, filters packets by IP/port/protocol, logs everything to CSV, and flags basic port-scan style anomalies.

## Why this project

Built to strengthen hands-on understanding of TCP/IP networking, packet inspection, protocol analysis, and anomaly detection through real-time traffic capture and analysis.

## Features

- **Live packet capture** using Scapy, with real-time console output
- **Protocol decoding** for TCP, UDP, and ICMP over IPv4 (source/destination IP, ports, flags, sequence/ack numbers)
- **Filtering** by source IP, destination IP, port, or protocol type
- **CSV logging** of every captured packet for later analysis
- **Basic anomaly detection**: flags a source IP as a possible port scan if it sends SYN packets to 8+ distinct ports within 5 seconds
- **Offline log analysis** script (`analyze_log.py`) that summarizes protocol distribution, top talkers, and scan-like behavior from a saved CSV using pandas

## How it works

1. `packet_analyzer.py` uses Scapy's `sniff()` to capture live packets on the default interface.
2. Each packet is parsed into a structured row (timestamp, IPs, ports, protocol, TCP flags, sequence/ack numbers, length).
3. Rows are printed to the console in real time and simultaneously appended to an in-memory log.
4. A lightweight tracker keeps a rolling window of SYN packets per source IP; if one source hits 8+ distinct destination ports inside 5 seconds, it prints a `[ALERT]` line — a simple heuristic for scan detection.
5. On exit (Ctrl+C, timeout, or packet-count limit), the full log is written to a CSV file.
6. `analyze_log.py` can then be run separately on that CSV to produce a summary: protocol breakdown, top source IPs, likely scanners, and average packet size.

## Requirements

- Python 3.8+
- Root/administrator privileges (raw packet capture requires elevated permissions)
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Usage

### Capture all traffic for 30 seconds
```bash
sudo python3 packet_analyzer.py --timeout 30
```

### Capture only TCP traffic on port 443
```bash
sudo python3 packet_analyzer.py --protocol TCP --port 443 --timeout 20
```

### Capture 50 packets from a specific source IP
```bash
sudo python3 packet_analyzer.py --src-ip 192.168.1.10 --count 50
```

### Save to a custom filename
```bash
sudo python3 packet_analyzer.py --timeout 30 --output my_capture.csv
```

### Analyze a saved capture
```bash
python3 analyze_log.py capture_log.csv
```

## Sample output

See `sample_output/console_output_sample.txt` for example console output (including a triggered scan alert) and `sample_output/capture_log_sample.csv` for the corresponding CSV log — useful for reviewing tool behavior without needing root access or live traffic.

## Notes on permissions

Raw packet capture needs elevated privileges on every OS:
- **Linux/macOS:** run with `sudo`
- **Windows:** requires [Npcap](https://npcap.com/) installed, and running the terminal as Administrator

## Possible extensions

- Add IPv6 support
- Export alerts to a separate log/alert file
- Add a simple Flask dashboard to visualize live traffic
- Extend anomaly detection with additional heuristics (e.g., ICMP flood detection)

## Tech Stack

- Python
- Scapy
- TCP/IP
- Socket Programming
- argparse
- pandas
- CSV Logging
- Network Packet Analysis
