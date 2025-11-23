from scapy.all import IP, TCP, Ether, wrpcap

pkt = Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/TCP(sport=12345, dport=53, flags="S")
wrpcap("../data/raw/capture.pcap", [pkt])

print("OK: capture.pcap generated.")
