from scapy.all import *
import base64, time, random, os

OUT = "case_study_large.pcap"
pkts = []

# Adjust multipliers for size
MULT = 5        # 5 is enough for ~300k packets
BIG_MULT = 10   # used only for DNS + ICMP bursts

def tcp_pkt(src, dst, sport, dport, payload):
    return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags='PA') / Raw(load=payload)

print("[+] Generating ICMP Flood...")
for i in range(8000 * BIG_MULT):
    pkts.append(IP(src=f"192.168.{i%30}.{i%200}", dst="8.8.8.8")/ICMP())

print("[+] Generating Normal DNS Traffic...")
for i in range(15000 * MULT):
    domain = f"normal{i%500}.example.com"
    pkts.append(IP(src=f"10.0.{i%20}.{i%254}", dst="8.8.4.4")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=domain)))

print("[+] Generating HTTP GET Flood...")
for i in range(20000 * MULT):
    req = f"GET /page{i%1000}.html HTTP/1.1\r\nHost: site{i%50}.com\r\n\r\n"
    pkts.append(tcp_pkt(f"172.16.{i%10}.{i%254}", "93.184.216.34", 1024+i%4000, 80, req))

print("[+] Generating Credential Leaks...")
for i in range(5000 * MULT):
    cred = base64.b64encode(f"user{i}:pass{i}".encode()).decode()
    req = f"GET /secret HTTP/1.1\r\nHost: leak.example\r\nAuthorization: Basic {cred}\r\n\r\n"
    pkts.append(tcp_pkt(f"192.168.10.{i%254}", "93.184.216.34", 2000+i%5000, 80, req))

print("[+] Generating Malware C2 DNS Beacons...")
c2domains = ["c2bad.net", "evilserver.org", "darkc2.io"]
for i in range(20000 * MULT):
    token = base64.b32encode(f"beacon{i}".encode()).decode().strip("=")[:12].lower()
    qname = f"{token}.{random.choice(c2domains)}"
    pkts.append(IP(src=f"10.10.{i%10}.{i%254}", dst="1.1.1.1")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=qname)))

print("[+] Generating Malware HTTP C2 POST Callbacks...")
c2hosts = ["198.51.100.10", "203.0.113.15"]
for i in range(15000 * MULT):
    body = f"id={i}&data={base64.b64encode(f'data{i}'.encode()).decode()}"
    req = f"POST /cb HTTP/1.1\r\nHost: c2.example\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    pkts.append(tcp_pkt(f"192.0.2.{i%254}", random.choice(c2hosts), 3000+i%4000, 8080, req))

print("[+] Generating Random UDP Traffic...")
for i in range(15000 * MULT):
    pkts.append(
        IP(src=f"10.20.{i%10}.{i%254}", dst=f"104.16.{i%50}.{i%200}") /
        UDP(sport=5000+i%2000, dport=5000+i%2000) /
        Raw(load=os.urandom(120))
    )

print("[+] Shuffling...")
random.shuffle(pkts)

print("[+] Timestamping...")
now = time.time()
for idx, pkt in enumerate(pkts):
    pkt.time = now + idx * 0.00003  # 30 microsecond spacing

print("[+] Saving PCAP (this may take 30–60 seconds)...")
wrpcap(OUT, pkts)

print(f"[+] DONE! Generated {len(pkts)} packets.")
print(f"[+] Saved as: {OUT}")

