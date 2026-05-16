import sqlite3
import json
from datetime import datetime

DB_FILE = "nids.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    # Table for individual packets
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   INTEGER,
            protocol    TEXT,
            src_ip      TEXT,
            src_port    INTEGER,
            dst_ip      TEXT,
            dst_port    INTEGER,
            service     TEXT,
            length      INTEGER,
            syn         INTEGER,
            ack         INTEGER,
            fin         INTEGER,
            rst         INTEGER,
            psh         INTEGER,
            alert       INTEGER
        )
    ''')

    # Table for flows
    c.execute('''
        CREATE TABLE IF NOT EXISTS flows (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at     TEXT,
            protocol        TEXT,
            src_ip          TEXT,
            src_port        INTEGER,
            dst_ip          TEXT,
            dst_port        INTEGER,
            service         TEXT,
            packet_count    INTEGER,
            total_bytes     INTEGER,
            avg_packet_size REAL,
            duration        INTEGER,
            packets_per_sec REAL,
            syn_count       INTEGER,
            ack_count       INTEGER,
            fin_count       INTEGER,
            rst_count       INTEGER,
            psh_count       INTEGER,
            syn_ratio       REAL,
            rst_ratio       REAL,
            threat_score    INTEGER,
            reasons         TEXT,
            label           TEXT DEFAULT 'unknown'
        )
    ''')

    conn.commit()
    conn.close()
    print(f"Database initialized: {DB_FILE}")

def save_packet(packet):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    flags = packet["flags"]
    c.execute('''
        INSERT INTO packets
        (timestamp, protocol, src_ip, src_port, dst_ip, dst_port,
         service, length, syn, ack, fin, rst, psh, alert)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        packet["timestamp"],
        packet["protocol"],
        packet["src_ip"],
        packet["src_port"],
        packet["dst_ip"],
        packet["dst_port"],
        packet["service"],
        packet["length"],
        1 if flags["SYN"] else 0,
        1 if flags["ACK"] else 0,
        1 if flags["FIN"] else 0,
        1 if flags["RST"] else 0,
        1 if flags["PSH"] else 0,
        1 if packet["alert"] else 0
    ))
    conn.commit()
    conn.close()

def save_flow(flow, features, threat_score, reasons):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO flows
        (captured_at, protocol, src_ip, src_port, dst_ip, dst_port,
         service, packet_count, total_bytes, avg_packet_size,
         duration, packets_per_sec, syn_count, ack_count, fin_count,
         rst_count, psh_count, syn_ratio, rst_ratio,
         threat_score, reasons)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (
        datetime.now().isoformat(),
        flow["protocol"],
        flow["src_ip"],
        flow["src_port"],
        flow["dst_ip"],
        flow["dst_port"],
        flow["service"],
        flow["packet_count"],
        flow["total_bytes"],
        features["avg_packet_size"],
        features["duration"],
        features["packets_per_sec"],
        flow["syn_count"],
        flow["ack_count"],
        flow["fin_count"],
        flow["rst_count"],
        flow["psh_count"],
        features["syn_ratio"],
        features["rst_ratio"],
        threat_score,
        ", ".join(reasons)
    ))
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM packets")
    total_packets = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM flows")
    total_flows = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM flows WHERE threat_score >= 3")
    suspicious_flows = c.fetchone()[0]

    c.execute('''
        SELECT src_ip, COUNT(*) as cnt
        FROM packets
        GROUP BY src_ip
        ORDER BY cnt DESC
        LIMIT 5
    ''')
    top_talkers = c.fetchall()

    conn.close()
    return {
        "total_packets":   total_packets,
        "total_flows":     total_flows,
        "suspicious_flows": suspicious_flows,
        "top_talkers":     top_talkers
    }

if __name__ == "__main__":
    init_db()
    stats = get_stats()
    print(f"\n=== Database Stats ===")
    print(f"Total packets  : {stats['total_packets']}")
    print(f"Total flows    : {stats['total_flows']}")
    print(f"Suspicious     : {stats['suspicious_flows']}")
    print(f"\nTop talkers:")
    for ip, count in stats["top_talkers"]:
        print(f"  {ip:<20} {count} packets")
