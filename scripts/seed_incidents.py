import sys
import os
from datetime import datetime, timedelta
import random

# Adjust path to import system modules
sys.path.append(os.getcwd())

from system.database.database import DatabaseManager, Incident

def seed_incidents():
    print("Seeding Security Incidents (2 Critical, 1 High, 1 Medium)...")
    
    import asyncio
    db_manager = DatabaseManager('sqlite:///data/events.db')
    asyncio.run(db_manager.initialize())
    
    with db_manager.sync_session() as db:
        # Clear existing incidents if any to ensure exact counts for demo
        db.query(Incident).delete()
        
        incidents = [
            {
                "title": "WAF: BOLA deception trigger on /api/v1/user/payment",
                "severity": "critical",
                "status": "open",
                "src": "185.220.101.44",
                "dst": "10.10.1.50",
                "module": "waf",
                "events": 12,
                "desc": "High-risk BOLA (Broken Object Level Authorization) attempt flagged by WAAP deception engine on sensitive API endpoints. Attacker attempted to enumerate sequential payment receipt records."
            },
            {
                "title": "IDS/IPS: Metasploit reverse shell payload injection",
                "severity": "critical",
                "status": "investigating",
                "src": "5.101.44.18",
                "dst": "192.168.10.25",
                "module": "ids_ips",
                "events": 4,
                "desc": "C2 communication established. Shellcode matching Metasploit Mettle reverse TCP payload signature detected over port 443 outbound from database segment host."
            },
            {
                "title": "Malware AV: Ransomware encryption behavior detected",
                "severity": "high",
                "status": "contained",
                "src": "192.168.10.104",
                "dst": "172.16.50.2",
                "module": "malware_av",
                "events": 1,
                "desc": "Antivirus verdict engine intercepted bulk entropy file manipulation. Executable ps_lab_w16.exe quarantined after attempting to alter filesystem headers."
            },
            {
                "title": "DLP: Outbound transmission of high-entropy API keys",
                "severity": "medium",
                "status": "closed",
                "src": "192.168.10.15",
                "dst": "195.206.12.3",
                "module": "dlp",
                "events": 3,
                "desc": "Data loss prevention agent matched regex for AWS/GCP credential strings inside outgoing HTTPS request payload. Source device isolated and payload inspected."
            }
        ]
        
        now = datetime.utcnow()
        for i, inc in enumerate(incidents):
            # Spread incidents over the last 2 hours
            inc_time = now - timedelta(minutes=random.randint(15, 120))
            
            new_inc = Incident(
                timestamp=inc_time,
                title=inc["title"],
                severity=inc["severity"],
                status=inc["status"],
                source_ip=inc["src"],
                destination_ip=inc["dst"],
                module=inc["module"],
                events_count=inc["events"],
                description=inc["desc"]
            )
            db.add(new_inc)
        
        db.commit()
    
    print("[OK] Successfully seeded 4 security incidents into the database.")

if __name__ == "__main__":
    seed_incidents()
