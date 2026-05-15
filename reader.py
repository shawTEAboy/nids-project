import json

# Stats we'll track
stats = {
    "total_packets": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "alerts": 0,
    "services": {},
    "top_talkers": {}
}

print("=== NIDS Packet Analyzer ===\n")

# Read packets.json line by line
with open("packets.json", "r") as f:
    for line in f:
        packet = json.loads(line.strip())
        stats["total_packets"] += 1

        # Count protocols
        proto = packet["protocol"]
        if proto == "TCP":   stats["tcp"] += 1
        elif proto == "UDP": stats["udp"] += 1
        elif proto == "ICMP":stats["icmp"] += 1

        # Count alerts
        if packet["alert"]:
            stats["alerts"] += 1
            print(f"🚨 ALERT: {packet['src_ip']}:{packet['src_port']} → "
                  f"{packet['dst_ip']}:{packet['dst_port']} "
                  f"[{packet['protocol']} SYN]")

        # Count services
        service = packet["service"]
        stats["services"][service] = stats["services"].get(service, 0) + 1

        # Track who is sending the most packets
        src = packet["src_ip"]
        stats["top_talkers"][src] = stats["top_talkers"].get(src, 0) + 1

# Print summary
print("\n=== Summary ===")
print(f"Total packets  : {stats['total_packets']}")
print(f"TCP            : {stats['tcp']}")
print(f"UDP            : {stats['udp']}")
print(f"Alerts         : {stats['alerts']}")

print("\n--- Services seen ---")
for service, count in sorted(stats["services"].items(), 
                              key=lambda x: x[1], reverse=True):
    print(f"  {service:<10} {count} packets")

print("\n--- Top talkers ---")
for ip, count in sorted(stats["top_talkers"].items(), 
                        key=lambda x: x[1], reverse=True):
    print(f"  {ip:<20} {count} packets")

