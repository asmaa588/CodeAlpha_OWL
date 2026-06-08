from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

log = []

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"
        timestamp = datetime.now().strftime("%H:%M:%S")

        line = f"\n{'='*50}\n"
        line += f"⏰ Time      : {timestamp}\n"
        line += f"🔹 Protocol  : {protocol}\n"
        line += f"🔹 Source IP : {src_ip}\n"
        line += f"🔹 Dest IP   : {dst_ip}\n"

        if TCP in packet:
            line += f"🔹 Src Port  : {packet[TCP].sport}\n"
            line += f"🔹 Dst Port  : {packet[TCP].dport}\n"

        if Raw in packet:
            payload = packet[Raw].load[:50]
            line += f"🔹 Payload   : {payload}\n"

        print(line)
        log.append(line)

print("🚀 Network Sniffer Started... Press CTRL+C to stop\n")
sniff(filter="ip", prn=packet_handler, store=False, count=20)

# to save
with open("sniffer_results.txt", "w") as f:
    f.write("Network Sniffer Results\n")
    f.write(f"Date: {datetime.now()}\n")
    f.writelines(log)

print("\n✅ Done! Results saved to sniffer_results.txt")
