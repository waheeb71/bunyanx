import sqlite3
import os
from datetime import datetime, timedelta, timezone
import random

# Resolve path to data/events.db relative to project root (parent of scripts/)
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
db_path = os.path.join(_PROJECT_ROOT, "data", "events.db")
os.makedirs(os.path.join(_PROJECT_ROOT, "data"), exist_ok=True)



# Schema definition for events table
schema = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    flow_id TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    iface_in TEXT,
    iface_out TEXT,
    bytes INTEGER DEFAULT 0,
    packets INTEGER DEFAULT 0,
    direction TEXT,
    source_path TEXT,
    verdict TEXT,
    reason TEXT,
    policy_id TEXT,
    ml_score REAL,
    ml_label TEXT,
    confidence REAL,
    domain TEXT,
    url TEXT,
    application TEXT,
    user_id TEXT,
    session_id TEXT,
    metadata TEXT,
    ingestion_time TEXT DEFAULT CURRENT_TIMESTAMP
);
"""

def seed_traffic_history():
    print(f"Seeding Traffic History into {db_path}...")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(schema)
    
    # Clear existing traffic events
    cursor.execute("DELETE FROM events;")
    
    now_utc = datetime.now(timezone.utc)
    
    # Insert traffic history for the last 60 minutes
    # We will generate packets and bytes every 10 seconds to align with the frontend polling interval
    total_records = 300
    for i in range(total_records):
        timestamp = now_utc - timedelta(seconds=10 * i)
        
        # Generate semi-random packets and bytes
        packets = random.randint(100, 1500)
        bytes_count = packets * random.randint(500, 1500)  # Average packet size
        
        event_id = f"flow-event-{i}-{random.randint(1000, 9999)}"
        flow_id = f"flow-{i}"
        
        cursor.execute(
            """
            INSERT INTO events (
                event_id, timestamp, flow_id, src_ip, dst_ip, src_port, dst_port,
                protocol, bytes, packets, verdict, direction
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                timestamp.isoformat(),
                flow_id,
                "192.168.1.50",
                "10.0.0.10",
                random.randint(1024, 65535),
                80,
                "TCP",
                bytes_count,
                packets,
                "ALLOW",
                "inbound"
            )
        )
    
    conn.commit()
    conn.close()
    print(f"[OK] Successfully seeded {total_records} traffic records into {db_path}.")

if __name__ == "__main__":
    seed_traffic_history()
