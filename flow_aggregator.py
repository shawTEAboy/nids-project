import json
import sys
from datetime import datetime

flows = {}

def get_flow_key(packet):
    src = (packet["src_ip"], packet["src_port"])
    dst = (packet["dst_ip"], packet["dst_port"])
    proto = packet["protocol"]
    if src > dst:
        src, dst = dst, src
    return (src[0], dst[0], src[1], dst[1], proto)

def update_flow(key, packet):
    if key not in flows:
        flows[key] = {
            "src_ip":       key[0],
            "dst_ip":       key[1],
            "src_port":     key[2],
            "dst_port":     key[3],
            "protocol":     key[4],
            "service":      packet["service"],
            "packet_count": 0,
            "total_bytes":  0,
            "syn_count":    0,
            "ack_count":    0,
            "fin_count":    0,
            "rst_count":    0,
            "psh_count":    0,
            "start_time":   packet["timestamp"],
            "last_time":    packet["timestamp"],
        }

    flow = flows[key]
    flow["packet_count"] += 1
    flow["total_bytes"]  += packet["length"]
    flow["last_time"]     = packet["timestamp"]

    flags = packet["flags"]
    if flags["SYN"]: flow["syn_count"] += 1
    if flags["ACK"]: flow["ack_count"] += 1
    if flags["FIN"]: flow["fin_count"] += 1
    if flags["RST"]: flow["rst_count"] += 1
    if flags["PSH"]: flow["psh_count"] += 1

def analyze_flow(flow):
    duration = max(1, flow["last_time"] - flow["start_time"])
    packet_count = flow["packet_count"]
    total_bytes = flow["total_bytes"]

    packets_per_sec = packet_count / duration
    avg_packet_size = total_bytes / packet_count
    syn_ratio = flow["syn_count"] / packet_count
    rst_ratio = flow["rst_count"] / packet_count

    score = 0
    reasons = []

    if syn_ratio > 0.7 and packet_count > 5:
        score += 3
        reasons.append("high SYN ratio")

    if rst_ratio > 0.5:
        score += 2
        reasons.append("high RST ratio")

    if packets_per_sec > 100:
        score += 3
        reasons.append("high packet rate")

    if avg_packet_size < 60 and packet_count > 10:
        score += 2
        reasons.append("many tiny packets")

    return {
        "flow": flow,
        "features": {
            "duration":        duration,
            "packets_per_sec": round(packets_per_sec, 2),
            "avg_packet_size": round(avg_packet_size, 2),
            "syn_ratio":       round(syn_ratio, 3),
            "rst_ratio":       round(rst_ratio, 3),
            "total_bytes":     total_bytes,
            "packet_count":    packet_count,
        },
        "threat_score": score,
        "reasons": reasons
    }

def print_summary():
    print("\n=== Flow Summary ===")
    print(f"Total flows: {len(flows)}\n")

    analyzed = [analyze_flow(f) for f in flows.values()]
    analyzed.sort(key=lambda x: x["threat_score"], reverse=True)

    for a in analyzed:
        f = a["flow"]
        feat = a["features"]
        score = a["threat_score"]

        alert = "🚨 SUSPICIOUS" if score >= 3 else "✅ normal"

        print(f"{alert} | score:{score} | "
              f"{f['protocol']} {f['src_ip']}:{f['src_port']} ↔ "
              f"{f['dst_ip']}:{f['dst_port']} ({f['service']})")
        print(f"  packets:{feat['packet_count']} | "
              f"bytes:{feat['total_bytes']} | "
              f"avg size:{feat['avg_packet_size']}b | "
              f"syn ratio:{feat['syn_ratio']} | "
              f"pkt/sec:{feat['packets_per_sec']}")

        if a["reasons"]:
            print(f"  ⚠️  Reasons: {', '.join(a['reasons'])}")
        print()

print("=== NIDS Flow Aggregator ===")
print("Reading packets...\n")

try:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        packet = json.loads(line)
        key = get_flow_key(packet)
        update_flow(key, packet)

except KeyboardInterrupt:
    print_summary()
