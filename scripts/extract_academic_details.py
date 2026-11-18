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

out_file = r"academic_details.md"
with open(out_file, "w", encoding="utf-8") as out:
    for path in docs_paths:
        full_path = os.path.join(r"f:\enterprise_ngfw", path)
        if not os.path.exists(full_path):
            out.write(f"# Not Found: {path}\n\n")
            continue
        
        with open(full_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        out.write(f"# MODULE: {os.path.basename(path)}\n\n")
        
        # Look for "المساهمة العلمية", "الابتكار", "Introduction", "Objectives", "Database", "API"
        # Let's extract sections between ## headers that are interesting.
        # We can extract the first 3000 chars of each file to capture the introduction and original contribution
        intro_match = re.search(r"(# 1\..*?)(?=# 2\.)", content, re.DOTALL | re.IGNORECASE)
        if not intro_match:
            intro_match = re.search(r"(## 1\..*?)(?=## 2\.)", content, re.DOTALL | re.IGNORECASE)
        if not intro_match:
            # just take the first 4000 characters
            intro_text = content[:4000]
        else:
            intro_text = intro_match.group(1)
            
        out.write("## Introduction & Innovation:\n")
        out.write(intro_text.strip()[:4000])
        out.write("\n\n")
        
        # Look for Database Tables or ORM models
        db_match = re.search(r"(## (?:17|9|15|Database|قاعدة البيانات).*?)(?=(?:## (?:18|10|16|API|Logging|Testing)|# \d))", content, re.DOTALL | re.IGNORECASE)
        if db_match:
            out.write("## Database Info:\n")
            out.write(db_match.group(1).strip()[:2000])
            out.write("\n\n")
        else:
            # Let's search for "class " or "Table" or "SQLAlchemy" or "Base" or "Table" in the file
            db_mentions = re.findall(r".*(?:class\s+\w+\(|table|model|ORM|schema).*", content, re.IGNORECASE)
            if db_mentions:
                out.write("## Database Mentions:\n")
                out.write("\n".join(db_mentions[:10]))
                out.write("\n\n")
                
        out.write("-" * 80 + "\n\n")

print("Done extracting academic details.")
