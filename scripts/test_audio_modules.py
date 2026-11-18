#!/usr/bin/env python3
"""
BunyanX NGFW — Audio Alert & Module Defense Verification Suite
================================================================
Run this script from an external device on the network to test
each security module and verify that its specific audio alert fires
on the Firewall machine speakers.

Usage:
  python test_audio_modules.py [FIREWALL_IP]
"""

import sys
import time
import socket
import urllib.request
import urllib.error

# Target Firewall WAN IP
FIREWALL_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.33"
HTTP_PORT = 80
DNS_PORT = 15353
SMTP_PORT = 2525
SSH_PORT = 2222

print("===========================================================================")
print("      ⚔️   BunyanX NGFW — Audio Alert & Defense Verification   ⚔️")
print(f"      Target Firewall IP: {FIREWALL_IP}")
print("===========================================================================\n")

def log_test(module_name, expected_sound, description):
    print(f"\n------------------------------------------------------------")
    print(f"🎯 Testing Module: [{module_name}]")
    print(f"🔊 Expected Sound: [{expected_sound}]")
    print(f"📝 Test Case:      {description}")
    print(f"------------------------------------------------------------")

def pause_for_audio():
    print("  ⏳ Waiting 4 seconds to hear the audio alert on the Firewall...")
    time.sleep(4)

# ── 1. WAF Module Test ────────────────────────────────────────────────────────
log_test("WAF (Web Application Firewall)", "response_block.mp3 / waf.block", "SQL Injection Probe")
url = f"http://{FIREWALL_IP}:{HTTP_PORT}/api/search?q=%27%20UNION%20SELECT%20null,username,password%20FROM%20users%20--"
try:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 WAF-Test"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"  [!] Response: HTTP {resp.status}")
except urllib.error.HTTPError as e:
    print(f"  [✔] WAF Blocked Request: HTTP {e.code}")
except Exception as e:
    print(f"  [✔] WAF Blocked / Connection Reset: {e}")
pause_for_audio()

# ── 2. DLP Module Test ────────────────────────────────────────────────────────
log_test("DLP (Data Loss Prevention)", "dlp_incident.mp3 / dlp.incident", "Downloading Sensitive Credit Cards Response")
url = f"http://{FIREWALL_IP}:{HTTP_PORT}/api/leak-cc?count=150"
try:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 DLP-Test"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        content = resp.read().decode('utf-8', errors='ignore')
        print(f"  [!] Received Content ({len(content)} bytes)")
except urllib.error.HTTPError as e:
    print(f"  [✔] DLP Egress Blocked: HTTP {e.code}")
except Exception as e:
    print(f"  [✔] DLP Egress Blocked / Connection Reset: {e}")
pause_for_audio()

# ── 3. AntiVirus / Malware Module Test ─────────────────────────────────────────
log_test("Malware AV", "malware_detected.mp3 / malware.detected", "Sending EICAR Standard Test File")
eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
url = f"http://{FIREWALL_IP}:{HTTP_PORT}/api/documents/upload"
try:
    req = urllib.request.Request(url, data=eicar_string, headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"  [!] Response: HTTP {resp.status}")
except urllib.error.HTTPError as e:
    print(f"  [✔] Malware AV Blocked: HTTP {e.code}")
except Exception as e:
    print(f"  [✔] Malware AV Blocked / Connection Reset: {e}")
pause_for_audio()

# ── 4. Web Filter Module Test ─────────────────────────────────────────────────
log_test("Web Filter", "response_alert.mp3 / web_filter.block", "Accessing Restricted Category (/category/hacking)")
url = f"http://{FIREWALL_IP}:{HTTP_PORT}/category/hacking"
try:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 WebFilter-Test"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(f"  [!] Response: HTTP {resp.status}")
except urllib.error.HTTPError as e:
    print(f"  [✔] Web Filter Blocked: HTTP {e.code}")
except Exception as e:
    print(f"  [✔] Web Filter Blocked / Connection Reset: {e}")
pause_for_audio()

# ── 5. IDS / IPS Module Test ──────────────────────────────────────────────────
log_test("IDS / IPS (PHANTOM Engine)", "ids_port_scan.mp3 / ids.port_scan", "Port Scan Probe on Port 2222")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((FIREWALL_IP, SSH_PORT))
    s.sendall(b"SSH-2.0-OpenSSH_BruteForce_Test\r\n")
    data = s.recv(1024)
    s.close()
    print(f"  [!] Connected to SSH: {data[:30]}")
except Exception as e:
    print(f"  [✔] IDS/IPS Dropped Connection: {e}")
pause_for_audio()

# ── 6. DNS Security Module Test ───────────────────────────────────────────────
log_test("DNS Security", "dns_suspicious.mp3 / dns.threat", "Sending DGA Query over UDP 15353")
try:
    # Construct raw DNS query packet for a suspicious DGA domain
    dns_query = b'\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
    # domain: qx89v2z119ab3c990a.malicious-dga-domain.com
    labels = [b'qx89v2z119ab3c990a', b'malicious-dga-domain', b'com']
    for label in labels:
        dns_query += bytes([len(label)]) + label
    dns_query += b'\x00\x00\x01\x00\x01'  # TYPE A, CLASS IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(dns_query, (FIREWALL_IP, DNS_PORT))
    resp, _ = sock.recvfrom(1024)
    sock.close()
    print(f"  [!] DNS Response received ({len(resp)} bytes)")
except Exception as e:
    print(f"  [✔] DNS Security Blocked / Dropped Query: {e}")
pause_for_audio()

# ── 7. Email Security Module Test ─────────────────────────────────────────────
log_test("Email Security", "malware_detected.mp3 / email.threat", "Sending SMTP Phishing Test on Port 2525")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((FIREWALL_IP, SMTP_PORT))
    s.recv(1024)
    s.sendall(b"HELO phishing-domain.com\r\n")
    s.sendall(b"MAIL FROM: <attacker@phishing-domain.com>\r\n")
    s.sendall(b"RCPT TO: <victim@bank.internal>\r\n")
    s.sendall(b"DATA\r\n")
    s.sendall(b"Subject: URGENT: Verify Your Bank Account Credentials Immediately!\r\n\r\nClick here: http://fake-login.com\r\n.\r\n")
    s.close()
    print("  [!] SMTP Payload sent")
except Exception as e:
    print(f"  [✔] Email Security Blocked / Connection Dropped: {e}")
pause_for_audio()

print("\n===========================================================================")
print("  ✅ All Module Verification Tests Completed!")
print("===========================================================================")
