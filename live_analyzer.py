import json
import sys
from datetime import datetime

print("=== NIDS Live Analyzer ===")
print("Waiting for packets...\n")

syn_tracker = {}  # track SYN packets per IP

try:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        packet = json.loads(line)

        src = packet["src_ip"]
        dst = packet["dst_ip"]
        proto = packet["protocol"]
        service = packet["service"]
        length = packet["length"]
        flags = packet["flags"]
        time = datetime.now().strftime("%H:%M:%S")

        # Track SYN packets per source IP
        if flags["SYN"] and not flags["ACK"]:
            syn_tracker[src] = syn_tracker.get(src, 0) + 1

            # If same IP sends 3+ SYNs it's suspicious
            if syn_tracker[src] >= 3:
                print(f"[{time}] 🚨 PORT SCAN? {src} has sent "
                      f"{syn_tracker[src]} SYN packets!")

        # Print every packet nicely
        flag_str = " ".join([f for f in ["SYN","ACK","FIN","RST","PSH"]
                             if flags.get(f)])

        print(f"[{time}] [{proto}] {src} → {dst}:{packet['dst_port']} "
              f"({service}) {flag_str} | {length}b")

except KeyboardInterrupt:
    print("\n\n=== Session Summary ===")
    if syn_tracker:
        print("SYN counts per IP:")
        for ip, count in sorted(syn_tracker.items(),
                                key=lambda x: x[1], reverse=True):
            print(f"  {ip}: {count} SYNs")
    print("Done.")

