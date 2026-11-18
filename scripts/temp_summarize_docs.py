import os
import re

docs_paths = [
    r"modules\firewall\firewall_academic_documentation.md",
    r"modules\ssl_inspection\ssl_inspection_academic_documentation.md",
    r"modules\http_inspection\http_inspection_academic_doc.md",
    r"modules\ids_ips\ids_ips_system_documentation.md",
    r"modules\dlp\dlp_module_documentation.md",
    r"modules\dns_security\dns_security_academic_documentation.md",
    r"modules\email_security\email_security_documentation.md",
    r"modules\malware_av\malware_av_documentation.md",
    r"modules\predictive_ai\predictive_ai_documentation.md",
    r"modules\proxy\proxy_module_documentation.md",
    r"modules\qos\DOCUMENTATION.md",
    r"modules\uba\uba_graduation_documentation.md",
    r"modules\vpn\vpn_module_academic_documentation.md",
    r"modules\waf\waf_enterprise_documentation.md",
    r"modules\web_filter\web_filter_system_documentation.md",
    r"system\system_academic_documentation.md",
    r"acceleration\acceleration_academic_documentation.md"
]

out_file = r"docs_summary.txt"
with open(out_file, "w", encoding="utf-8") as out:
    for path in docs_paths:
        full_path = os.path.join(r"f:\enterprise_ngfw", path)
        if not os.path.exists(full_path):
            out.write(f"=== FILE NOT FOUND: {path} ===\n\n")
            continue
        out.write(f"==================================================\n")
        out.write(f"FILE: {path}\n")
        out.write(f"==================================================\n")
        with open(full_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            # print first 50 lines or scan for key headings
            headers = []
            for i, line in enumerate(lines):
                if line.startswith("#"):
                    headers.append((i+1, line.strip()))
            
            out.write("HEADINGS:\n")
            for h in headers[:30]:
                out.write(f"  Line {h[0]}: {h[1]}\n")
            out.write("\nSUMMARY (First 100 lines):\n")
            out.write("".join(lines[:100]))
            out.write("\n\n")

print("Done writing summary.")
