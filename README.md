Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

Overview

This project is a Python-based packet sniffer built using GitHub Copilot assistance and the scapy library. It captures and analyzes network packets in a controlled environment and applys strict redaction rules to protect sensitive information.

The sniffer is intentionally configured to capture only loopback (local machine) traffic to ensure ethical and authorized use.

Setup Instructions

1. Clone the Repository

  git clone https://github.com/rceasars24-afk/copilot-packet-sniffer.git
  cd copilot-packet-sniffer

2. Install Dependencies

Make sure you have Python 3.10+ installed.

Install required package:

  pip install -r requirements.txt

3. Run with Elevated Privileges

Packet sniffing requires admin/root permissions.

Linux / Kali / WSL:

  sudo python3 sniffer.py

Windows (PowerShell as Administrator):

  python sniffer.py

Run Examples

Default Run (Loopback Capture)

  sudo python3 sniffer.py

What the Script Does

Captures 25 packets

Uses interface: lo (loopback)

No filter (captures all local traffic)

Prints decoded + redacted packet data

Example Output
============================================================
IP Packet: 127.0.0.xxx → 127.0.0.xxx
Protocol: 6
TCP: 54321 → 80
Payload (first 100 chars): GET / HTTP/1.1 Host: localhost

Generating Test Traffic

To see meaningful output, generate local traffic:

  curl http://localhost

or trigger DNS:

  nslookup example.com

Features

Packet Capture
  Interface: lo (safe loopback capture)
  Packet count: 25
  Uses Scapy sniff() function

Protocol Decoding
  IP packets
  TCP / UDP
  DNS queries (domain names)
  Raw payload inspection (HTTP if unencrypted)

Redaction (Ethical Guardrails)

Before displaying any data, the script automatically:

Masks IP addresses → 192.168.1.xxx

Redacts:
  Emails → [REDACTED_EMAIL]
  Passwords → password=[REDACTED]
  Tokens → token=[REDACTED]
  Authorization headers
  Cookies

Ethics & Legal Use

This tool is designed strictly for educational use in controlled environments.

Allowed Use:
  Your own machine (loopback traffic)
  Lab VM or instructor-provided environment

Prohibited Use:
  Sniffing other users' traffic
  Monitoring networks without permission
  Attempting to bypass OS/network restrictions

Unauthorized packet capture may violate privacy laws and cybersecurity policies.

🤖 AI Use Policy (Required)

This project follows responsible AI usage guidelines:

Allowed Use of Copilot:
  Boilerplate code
  Packet parsing logic
  Regex for redaction
  Debugging assistance

Disallowed Use:
  Capturing unauthorized traffic
  Bypassing OS permissions
  Stealth, persistence, or hiding activity

Safeguards Implemented:
  Loopback-only capture (lo)
  Packet count limit (25)
  Sensitive data redaction
  Clear ethical warning in program output

Configuration (From Code)
  iface = "lo"        # Loopback interface (safe)
  packet_count = 25   # Number of packets to capture
  bpf_filter = ""     # No filter (can be modified)

You may modify filters for testing:

  bpf_filter = "tcp port 80 or udp port 53"

Tests

Basic validation can include:
  Verifying IP redaction
  Ensuring emails are removed
  Checking payload sanitization

Project Requirements Coverage

  Packet capture (loopback)
  Protocol decoding (IP, TCP, UDP, DNS)
  Payload inspection (HTTP when available)
  Ethical safeguards (redaction + restrictions)
  Copilot usage with constraints
  Reproducible setup

📊 Future Improvements
Add .pcap file reading mode
CLI arguments for interface/filter selection
Structured logging (JSON output)
Unit test suite

Author
Rommell-Ceasar St. Preux
