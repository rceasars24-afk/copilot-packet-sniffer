from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, wrpcap

packets = []

# --- TCP HTTP-like packet ---
pkt1 = Ether() / IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=12345, dport=80) / \
       b"GET /login?username=test&password=secret HTTP/1.1\r\nHost: example.com\r\n\r\n"
packets.append(pkt1)

# --- DNS Query packet ---
pkt2 = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=33333, dport=53) / \
       DNS(rd=1, qd=DNSQR(qname="example.com"))
packets.append(pkt2)

# --- Packet with email + token (to test redaction) ---
pkt3 = Ether() / IP(src="192.168.1.20", dst="192.168.1.30") / TCP(sport=44444, dport=80) / \
       b"POST /api HTTP/1.1\r\nemail=test@example.com&token=abc123\r\n\r\n"
packets.append(pkt3)

# Write to file
wrpcap("test_traffic.pcap", packets)

print("✅ test_traffic.pcap created with sample traffic!")
