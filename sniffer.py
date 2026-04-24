#!/usr/bin/env python3
"""
Copilot-Assisted Packet Sniffer
Captures and redacts network traffic for authorized lab use only.
"""

import re
import sys
from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Raw
from scapy.all import rdpcap

# ===== PCAP FUNCTION =====
def read_pcap(file_path):
    """Read packets from a pcap file."""
    print(f"\nReading packets from {file_path}...\n")
    
    packets = rdpcap(file_path)
    
    for packet in packets:
        packet_callback(packet)

# ===== REDACTION FUNCTIONS =====
def redact_ip(ip_address):
    """Mask last octet of IP address."""
    parts = ip_address.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.xxx"
    return ip_address

def redact_sensitive_data(text):
    """Redact passwords, tokens, emails, cookies."""
    if not isinstance(text, str):
        return text
    
    # Redact email addresses
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', text)
    
    # Redact passwords in query strings
    text = re.sub(r'password=[^\s&]*', 'password=[REDACTED]', text, flags=re.IGNORECASE)
    
    # Redact tokens
    text = re.sub(r'token=[^\s&]*', 'token=[REDACTED]', text, flags=re.IGNORECASE)
    
    # Redact cookies (Authorization headers)
    text = re.sub(r'Authorization:\s*Bearer\s+[^\s]*', 'Authorization: Bearer [REDACTED]', text)
    text = re.sub(r'Cookie:\s*[^\n]*', 'Cookie: [REDACTED]', text)
    
    return text


# ===== PACKET PROCESSING =====
def packet_callback(packet):
    """Process each captured packet."""
    try:
        # Check if packet has IP layer
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Redact IPs
            ip_src_redacted = redact_ip(ip_src)
            ip_dst_redacted = redact_ip(ip_dst)
            
            print(f"\n{'='*60}")
            print(f"IP Packet: {ip_src_redacted} → {ip_dst_redacted}")
            print(f"Protocol: {packet[IP].proto}")
            
            # ===== TCP LAYER =====
            if TCP in packet:
                tcp_sport = packet[TCP].sport
                tcp_dport = packet[TCP].dport
                print(f"TCP: {tcp_sport} → {tcp_dport}")
                
                # Try to decode HTTP
                if Raw in packet:
                    payload = packet[Raw].load
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        payload_str = redact_sensitive_data(payload_str)
                        print(f"Payload (first 100 chars): {payload_str[:100]}")
                    except Exception as e:
                        print(f"Could not decode payload: {e}")
            
            # ===== UDP LAYER =====
            elif UDP in packet:
                udp_sport = packet[UDP].sport
                udp_dport = packet[UDP].dport
                print(f"UDP: {udp_sport} → {udp_dport}")
                
                # Check for DNS (port 53)
                if udp_dport == 53 or udp_sport == 53:
                    if DNS in packet and DNSQR in packet:
                        dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore')
                        print(f"DNS Query: {dns_query}")
    
    except Exception as e:
        print(f"Error processing packet: {e}")


# ===== MAIN FUNCTION =====
def main():
    print("="*60)
    print("Copilot-Assisted Packet Sniffer")
    print("="*60)
    print("⚠️  ETHICAL USE ONLY")
    print("="*60)

    # If user provides a pcap file → safe mode
    if len(sys.argv) > 1:
        read_pcap(sys.argv[1])
        return

    # Default: live capture (loopback only)
    iface = "lo"
    packet_count = 25
    bpf_filter = ""

    print(f"\nCapturing {packet_count} packets on interface: {iface}")

    try:
        sniff(
            iface=iface,
            prn=packet_callback,
            count=packet_count,
            filter=bpf_filter,
            store=False
        )

    except PermissionError:
        print("❌ ERROR: This script needs elevated privileges (sudo)")
        print("Run with: sudo python3 sniffer.py")
        sys.exit(1)

    except Exception as e:
        print(f"❌ ERROR: {e}")
        sys.exit(1)

    print("\n" + "="*60)
    print("Packet capture complete!")
    print("="*60)


if __name__ == "__main__":
    main()
