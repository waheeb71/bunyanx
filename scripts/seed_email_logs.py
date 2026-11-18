import sys
import os
from datetime import datetime, timedelta
import random

# Adjust path to import system modules
sys.path.append(os.getcwd())

from system.database.database import DatabaseManager
from modules.email_security.models import EmailLog

def seed_email_logs():
    print("Seeding Email Security Logs (3 Blocked, 1 Quarantined, 1 Allowed)...")
    
    import asyncio
    db_manager = DatabaseManager('sqlite:///data/events.db')
    asyncio.run(db_manager.initialize())
    
    with db_manager.sync_session() as db:
        # Clear existing email logs if any to ensure exact counts for demo
        db.query(EmailLog).delete()
        
        logs = [
            {
                "sender": "support-microsoft@login-security-alert.net",
                "subject": "Critical security alert for Office 365 account",
                "src_ip": "185.220.101.99",
                "dst_port": 25,
                "risk_score": 0.945,
                "phishing_score": 0.910,
                "spam_score": 0.420,
                "url_score": 0.880,
                "attachment_score": 0.0,
                "sender_score": 0.720,
                "decision": "block",
                "visual_desync_ratio": 0.0,
                "linguistic_anomaly_score": 0.35,
                "is_phishing": True,
                "is_spam": False,
                "has_malicious_url": True,
                "has_bad_attachment": False,
                "is_ai_mimicry": False,
                "has_visual_desync": False,
                "brand_spoof": "Microsoft",
                "matched_keywords": ["o365", "login", "password reset", "urgency"],
                "flagged_urls": ["http://login-security-alert.net/microsoft/oauth2"],
                "finding_categories": ["phishing", "malicious_url", "brand_spoofing"],
                "latency_ms": 42.5
            },
            {
                "sender": "marketing@newsletter-offers-direct.top",
                "subject": "Get $50,000 cash loans in 24 hours - No credit check",
                "src_ip": "104.244.72.10",
                "dst_port": 587,
                "risk_score": 0.720,
                "phishing_score": 0.150,
                "spam_score": 0.890,
                "url_score": 0.350,
                "attachment_score": 0.0,
                "sender_score": 0.450,
                "decision": "quarantine",
                "visual_desync_ratio": 0.0,
                "linguistic_anomaly_score": 0.12,
                "is_phishing": False,
                "is_spam": True,
                "has_malicious_url": False,
                "has_bad_attachment": False,
                "is_ai_mimicry": False,
                "has_visual_desync": False,
                "brand_spoof": None,
                "matched_keywords": ["loans", "cash", "no credit check"],
                "flagged_urls": [],
                "finding_categories": ["spam"],
                "latency_ms": 28.1
            },
            {
                "sender": "j.doe@partner-enterprise.com",
                "subject": "Project roadmap and contract proposal for Q3",
                "src_ip": "192.168.10.114",
                "dst_port": 465,
                "risk_score": 0.045,
                "phishing_score": 0.010,
                "spam_score": 0.020,
                "url_score": 0.0,
                "attachment_score": 0.010,
                "sender_score": 0.050,
                "decision": "allow",
                "visual_desync_ratio": 0.0,
                "linguistic_anomaly_score": 0.0,
                "is_phishing": False,
                "is_spam": False,
                "has_malicious_url": False,
                "has_bad_attachment": False,
                "is_ai_mimicry": False,
                "has_visual_desync": False,
                "brand_spoof": None,
                "matched_keywords": [],
                "flagged_urls": [],
                "finding_categories": [],
                "latency_ms": 15.4
            },
            {
                "sender": "billing@pay-pal-alert-update.com",
                "subject": "Your account has been restricted - Review billing transaction",
                "src_ip": "91.121.2.145",
                "dst_port": 25,
                "risk_score": 0.880,
                "phishing_score": 0.840,
                "spam_score": 0.200,
                "url_score": 0.750,
                "attachment_score": 0.0,
                "sender_score": 0.800,
                "decision": "block",
                "visual_desync_ratio": 0.720,
                "linguistic_anomaly_score": 0.28,
                "is_phishing": True,
                "is_spam": False,
                "has_malicious_url": True,
                "has_bad_attachment": False,
                "is_ai_mimicry": False,
                "has_visual_desync": True,
                "brand_spoof": "PayPal",
                "matched_keywords": ["paypal", "restricted", "billing", "verify"],
                "flagged_urls": ["https://pay-pal-alert-update.com/signin"],
                "finding_categories": ["phishing", "visual_desynchronization", "brand_spoofing"],
                "latency_ms": 55.2
            },
            {
                "sender": "invoice-department@global-shipping-logistics.cn",
                "subject": "Overdue shipping invoice #CN-920119-DOC",
                "src_ip": "222.186.15.54",
                "dst_port": 25,
                "risk_score": 0.982,
                "phishing_score": 0.350,
                "spam_score": 0.450,
                "url_score": 0.0,
                "attachment_score": 0.995,
                "sender_score": 0.900,
                "decision": "block",
                "visual_desync_ratio": 0.0,
                "linguistic_anomaly_score": 0.15,
                "is_phishing": False,
                "is_spam": False,
                "has_malicious_url": False,
                "has_bad_attachment": True,
                "is_ai_mimicry": False,
                "has_visual_desync": False,
                "brand_spoof": None,
                "matched_keywords": [".vbs", "shipping", "invoice"],
                "flagged_urls": [],
                "finding_categories": ["malicious_attachment"],
                "latency_ms": 35.8
            }
        ]
        
        now = datetime.utcnow()
        for i, log in enumerate(logs):
            log_time = now - timedelta(minutes=random.randint(10, 120))
            
            new_log = EmailLog(
                inspected_at=log_time,
                sender=log["sender"],
                subject=log["subject"],
                src_ip=log["src_ip"],
                dst_port=log["dst_port"],
                risk_score=log["risk_score"],
                phishing_score=log["phishing_score"],
                spam_score=log["spam_score"],
                url_score=log["url_score"],
                attachment_score=log["attachment_score"],
                sender_score=log["sender_score"],
                decision=log["decision"],
                visual_desync_ratio=log["visual_desync_ratio"],
                linguistic_anomaly_score=log["linguistic_anomaly_score"],
                is_phishing=log["is_phishing"],
                is_spam=log["is_spam"],
                has_malicious_url=log["has_malicious_url"],
                has_bad_attachment=log["has_bad_attachment"],
                is_ai_mimicry=log["is_ai_mimicry"],
                has_visual_desync=log["has_visual_desync"],
                matched_keywords=log["matched_keywords"],
                flagged_urls=log["flagged_urls"],
                brand_spoof=log["brand_spoof"],
                finding_categories=log["finding_categories"],
                latency_ms=log["latency_ms"]
            )
            db.add(new_log)
        
        db.commit()
    
    print("[OK] Successfully seeded 5 email logs into the database.")

if __name__ == "__main__":
    seed_email_logs()
