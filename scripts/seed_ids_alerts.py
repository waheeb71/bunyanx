import sys
import os
from datetime import datetime, timedelta
import random

# Adjust path to import system modules
sys.path.append(os.getcwd())

from system.database.database import DatabaseManager, SecurityEvent

def seed_ids_alerts():
    print("Seeding IDS/IPS Alerts (4 Critical, 2 Warning)...")
    
    import asyncio
    db_manager = DatabaseManager()
    asyncio.run(db_manager.initialize())
    
    with db_manager.sync_session() as db:
        # Clear existing IDS alerts if any to ensure exact counts for the demo
        db.query(SecurityEvent).filter(SecurityEvent.event_type.in_(['ids_ips', 'ips', 'ids'])).delete()
        
        alerts = [
            # 4 Critical
            {
                "type": "ids_ips", "severity": "critical", "src": "45.142.120.12", "dst": "192.168.10.15",
                "desc": "SQL Injection: union-based exploitation attempt", "proto": "TCP", "sig": 2010935
            },
            {
                "type": "ids_ips", "severity": "critical", "src": "195.206.12.3", "dst": "192.168.10.1",
                "desc": "SSH Brute Force: multi-socket password guessing", "proto": "TCP", "sig": 2001219
            },
            {
                "type": "ids_ips", "severity": "critical", "src": "5.101.44.18", "dst": "192.168.10.25",
                "desc": "Reverse Shell: Metasploit payload detected (Mettle)", "proto": "TCP", "sig": 2019401
            },
            {
                "type": "ids_ips", "severity": "critical", "src": "91.121.2.55", "dst": "192.168.10.3",
                "desc": "Log4Shell: CVE-2021-44228 JNDI lookup attempt", "proto": "TCP", "sig": 2016025
            },
            
            # 2 Warning
            {
                "type": "ids_ips", "severity": "warning", "src": "89.234.1.22", "dst": "192.168.10.2",
                "desc": "ICMP Flood: unusually high ping volume from single peer", "proto": "ICMP", "sig": 2100498
            },
            {
                "type": "ids_ips", "severity": "warning", "src": "192.168.10.45", "dst": "8.8.8.8",
                "desc": "DNS Exfiltration: rare TLD query pattern detected", "proto": "UDP", "sig": 2013504
            }
        ]
        
        now = datetime.utcnow()
        for i, a in enumerate(alerts):
            # Spread alerts over the last 10 minutes
            event_time = now - timedelta(minutes=random.randint(1, 10))
            
            event = SecurityEvent(
                timestamp=event_time,
                event_type=a["type"],
                severity=a["severity"],
                source_ip=a["src"],
                destination_ip=a["dst"],
                protocol=a["proto"],
                action="BLOCK" if a["severity"] == "critical" else "ALERT",
                description=a["desc"],
                event_metadata={"sig_id": a["sig"]}
            )
            db.add(event)
        
        db.commit()
    
    print("[OK] Successfully seeded 6 IDS/IPS alerts into the database.")

if __name__ == "__main__":
    seed_ids_alerts()
