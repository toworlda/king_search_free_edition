import os
import re
import subprocess
import requests
import datetime
import json
import hashlib
import logging
from jinja2 import Template
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import pandas as pd
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init()

# Enhanced Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bug_bounty.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("bug_bounty_ai")

# Get the absolute base directory (parent of "modules" folder)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Define the Reports folder correctly
REPORTS_FOLDER = os.path.join(BASE_DIR, "Reports/Data/")
TEMPLATE_FILE = os.path.join(BASE_DIR, "templates/bug_bounty_report_template.html")
OUTPUT_FOLDER = os.path.join(BASE_DIR, "Reports/Bug-Bounty/")
DATABASE_FILE = os.path.join(BASE_DIR, "Reports/Json/vulnerability_database.json")
SCREENSHOTS_FOLDER = os.path.join(BASE_DIR, "Reports/evidence_screenshots/")

# Ensure directories exist
os.makedirs(REPORTS_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(DATABASE_FILE), exist_ok=True)
os.makedirs(SCREENSHOTS_FOLDER, exist_ok=True)

# Advanced AI-powered Training Dataset (Expanded to 15 Vulnerabilities)
training_data = np.array([
    # Critical (P1) vulnerabilities
    [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # API Keys, Secrets, Login URLs, SQL Injection
    [1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0],  # API Keys, SQL Injection, Command Injection, RCE
    [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0],  # Secrets, Credit Cards, RCE, JWT Issues
    
    # High (P2) vulnerabilities
    [0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # Secrets, Login URLs, XSS
    [0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0],  # XSS, Credit Cards, IDOR
    [0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0],  # SSRF, CVE References, JWT Issues
    
    # Medium (P3) vulnerabilities
    [0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],  # Login URLs, SQLi, Command Injection
    [0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0],  # SSRF, CVE References, Open Redirect
    [0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0],  # XSS, IDOR, CSRF
    
    # Low (P4) vulnerabilities
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1],  # Open Redirect, CSRF, Missing Headers
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]   # Only Missing Headers
])

training_labels = ["P1", "P1", "P1", "P2", "P2", "P2", "P3", "P3", "P3", "P4", "P4"]

# Train Enhanced AI Risk Classifier using RandomForest for better accuracy
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(training_data, training_labels)

# 🔥 Advanced AI-Powered Sensitive Data & Vulnerability Patterns (Expanded)
SENSITIVE_PATTERNS = {
    "API Keys": r"(?i)(?:api[_-]?key|apikey|token)[\"':=\s]+([A-Za-z0-9-_]{15,})",
    "Secrets": r"(?i)(?:secret|password|pass|pwd|key|authorization)[\"':=\s]+([A-Za-z0-9!@#$%^&*()_+={}\[\]:;\"',.<>?/\\-]{8,})",
    "Login URLs": r"https?://[^\s]+(?:login|auth|signin|admin|portal|dashboard)[^\s]*",
    "Credit Cards": r"\b(?:\d[ -]*?){13,19}\b|(?:\d{4}[- ]){3}\d{4}|\d{16}",
    "SQL Injection": r"(?i)(?:SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER)\s+.*\s+FROM\s+\w+|(?:\b(?:OR|AND)\b\s+\d+\s*=\s*\d+)|(?:'\s+(?:OR|AND)\s+\w+\s*=\s*\w+)|(?:--\s*$)",
    "XSS": r"(?i)<script>.*</script>|javascript:alert\(|on(?:load|click|mouseover|error)=|<img[^>]+src=[^>]+onerror=",
    "SSRF": r"https?://(?:127\.|localhost|169\.254\.|192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.)|file:///",
    "Command Injection": r"(?i)(;|&&|\|\|)\s*(curl|wget|nc|bash|sh|python|perl|ruby|php)\s+|`[^`]+`|\$\([^)]+\)",
    "Open Redirect": r"(?:url|redirect|redir|next|goto|destination|return_to)=https?://(?:[^\s/]+\.)+[^\s/]+",
    "CVE References": r"CVE-\d{4}-\d{4,7}",
    "Exploit-DB Payloads": r"(exploit-db.com/exploits/\d+)",
    "Remote Code Execution": r"(?:eval|system|exec|shell_exec|passthru|popen)\s*\(|require\s*\(\$|include\s*\(\$",
    "JWT Issues": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*",
    "CSRF": r"(?i)<form[^>]*>(?:(?!csrf).)*</form>|csrf_token|anti-forgery",
    "Missing Security Headers": r"(?i)(?:X-Frame-Options|X-XSS-Protection|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy|Referrer-Policy)",
    "IDOR": r"(?i)(?:id|user_id|account|profile)=\d+|/api/(?:users|accounts|profiles)/\d+"
}

# 🔥 AI-powered severity mapping with CVSS Components
CVSS_SEVERITY = {
    "P1": {
        "score": "9.0 - 10.0 (Critical)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "description": "Critical vulnerability allowing complete system compromise with minimal effort."
    },
    "P2": {
        "score": "7.0 - 8.9 (High)",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
        "description": "High severity issue allowing significant data exposure or system compromise."
    },
    "P3": {
        "score": "4.0 - 6.9 (Medium)",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L",
        "description": "Medium severity issue with limited impact but still requiring attention."
    },
    "P4": {
        "score": "0.1 - 3.9 (Low)",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N",
        "description": "Low severity issue with minimal impact on security posture."
    }
}

# Map vulnerability types to feature indices for the ML model
vuln_to_index = {
    "API Keys": 0,
    "Secrets": 1,
    "Login URLs": 2,
    "SQL Injection": 3,
    "XSS": 4,
    "Credit Cards": 5,
    "Command Injection": 6,
    "SSRF": 7,
    "CVE References": 8,
    "IDOR": 9,
    "Open Redirect": 10,
    "Remote Code Execution": 11,
    "JWT Issues": 12,
    "CSRF": 13,
    "Missing Security Headers": 14
}

# 🔥 AI-Powered PoC Generator with advanced payloads
def generate_poc(vulnerability_type, target_url=None):
    """Generate proof-of-concept payloads for different vulnerability types."""
    
    poc_payloads = {
        "SQL Injection": [
            "' OR '1'='1' --",
            "1'; DROP TABLE users; --",
            "' UNION SELECT username,password FROM users --"
        ],
        "XSS": [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ],
        "SSRF": [
            "http://127.0.0.1:80/",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ],
        "Command Injection": [
            "& cat /etc/passwd",
            "; ping -c 4 attacker.com",
            "| whoami"
        ],
        "Open Redirect": [
            "https://evil.com",
            "javascript:alert(document.cookie)",
            "//evil.com"
        ],
        "JWT Issues": [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        ],
        "CSRF": [
            "<form action='https://target.com/change_email' method='POST'>\n  <input type='hidden' name='email' value='attacker@evil.com'>\n  <input type='submit' value='Click me'>\n</form>"
        ]
    }
    
    if vulnerability_type in poc_payloads:
        payloads = poc_payloads[vulnerability_type]
        selected_payload = payloads[0]  # Default to first payload
        
        # Add target URL to the payload if available
        if target_url and vulnerability_type in ["Open Redirect", "SSRF"]:
            formatted_payload = f"{target_url}?redirect={selected_payload}"
        else:
            formatted_payload = selected_payload
            
        return f"""<div class="poc-section">
    <h4>Proof of Concept</h4>
    <pre class='code'>{formatted_payload}</pre>
    <p><em>Note: Additional payloads available. Customize based on the specific vulnerability details.</em></p>
</div>"""
    
    return "<p>No PoC available for this vulnerability type.</p>"

# 🔍 Extract Sensitive Data & Vulnerabilities with ML confidence scores
def extract_sensitive_data(report_path):
    """Extract sensitive data with confidence scores using ML patterns."""
    extracted_data = {}
    
    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            
            for key, pattern in SENSITIVE_PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    # Calculate a confidence score based on pattern consistency and context
                    confidence_score = min(len(matches) * 15, 95)  # Cap at 95%
                    
                    # Increase confidence for certain high-risk patterns
                    if key in ["API Keys", "Secrets", "SQL Injection", "Remote Code Execution"]:
                        confidence_score = min(confidence_score + 10, 95)
                    
                    # Store unique matches with confidence score
                    extracted_data[key] = {
                        "matches": list(set(matches)),
                        "confidence": confidence_score
                    }
                    
            logger.info(f"Extracted {sum(len(data['matches']) for data in extracted_data.values())} potential vulnerabilities from {report_path}")
    except Exception as e:
        logger.error(f"Error extracting data from {report_path}: {str(e)}")
    
    return extracted_data

# 📌 Advanced AI-Powered Severity Analysis
def determine_severity(extracted_data):
    """Assign severity based on AI-powered classification model with all vulnerability types."""

    # Initialize features vector with zeros
    features = [0] * 15
    
    # Set feature values based on extracted data
    for vuln_type in extracted_data:
        if vuln_type in vuln_to_index:
            features[vuln_to_index[vuln_type]] = 1
    
    # Use AI model to classify risk level
    return classify_risk(features)

def classify_risk(features):
    """AI-powered risk classification with explanation."""
    input_data = np.array([features])
    
    # Get classification probabilities
    probabilities = clf.predict_proba(input_data)[0]
    class_labels = clf.classes_
    
    # Get the prediction
    prediction = clf.predict(input_data)[0]
    
    # Calculate confidence level
    max_prob = max(probabilities)
    confidence = int(max_prob * 100)
    
    # Get contributing factors (highest impact features)
    feature_importances = list(zip(range(len(features)), clf.feature_importances_))
    feature_importances.sort(key=lambda x: x[1], reverse=True)
    
    # Map indices back to vulnerability names
    index_to_vuln = {v: k for k, v in vuln_to_index.items()}
    top_factors = [index_to_vuln[idx] for idx, imp in feature_importances[:3] if features[idx] == 1]
    
    return {
        "severity": prediction,
        "confidence": confidence,
        "contributing_factors": top_factors
    }

# Enhanced target URL extraction
def extract_target_url(report_path):
    """Extract target URL with enhanced pattern matching."""
    
    # Try extracting from filename
    filename = os.path.basename(report_path)
    match = re.search(r"(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?:/[^/\s]*)*", filename)
    if match:
        extracted_url = match.group(0)
        if not extracted_url.startswith(('http://', 'https://')):
            extracted_url = 'https://' + extracted_url
        return extracted_url

    # Try extracting from file content
    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            
            # Look for common URL patterns in content
            url_patterns = [
                r"(?:https?://)?(?:www\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?:/[^/\s]*)*",  # Domain pattern
                r"Target URL:[\s\n]*([^\s\n]+)",  # Target URL label
                r"URL:[\s\n]*([^\s\n]+)",         # URL label
                r"Website:[\s\n]*([^\s\n]+)"      # Website label
            ]
            
            for pattern in url_patterns:
                match = re.search(pattern, content)
                if match:
                    extracted_url = match.group(1)
                    if not extracted_url.startswith(('http://', 'https://')):
                        extracted_url = 'https://' + extracted_url
                    return extracted_url
    except Exception as e:
        logger.error(f"Error extracting target URL from {report_path}: {str(e)}")

    logger.warning(f"Could not extract target URL from {report_path}. Defaulting to example.com.")
    return "https://example.com"  # Default fallback

# 🧠 Enhanced vulnerability database management
def update_vulnerability_database(extracted_data, report_path):
    """Update vulnerability database with new findings and track duplicates."""
    
    database = {}
    if os.path.exists(DATABASE_FILE):
        try:
            with open(DATABASE_FILE, "r") as f:
                database = json.load(f)
        except json.JSONDecodeError:
            logger.error(f"Error reading database file. Creating new database.")
    
    # Generate a report fingerprint for deduplication
    report_name = os.path.basename(report_path)
    report_hash = hashlib.md5(report_name.encode()).hexdigest()
    
    # Extract target from report path
    target_url = extract_target_url(report_path)
    domain = re.sub(r"^https?://(?:www\.)?", "", target_url).split('/')[0]
    
    # Update database with new findings
    if domain not in database:
        database[domain] = {"vulnerabilities": {}, "reports": []}
    
    for vuln_type, data in extracted_data.items():
        if vuln_type not in database[domain]["vulnerabilities"]:
            database[domain]["vulnerabilities"][vuln_type] = []
        
        # Add new unique findings
        existing_findings = set([str(item["value"]) for item in database[domain]["vulnerabilities"][vuln_type]])
        for match in data["matches"]:
            if str(match) not in existing_findings:
                database[domain]["vulnerabilities"][vuln_type].append({
                    "value": match,
                    "confidence": data["confidence"],
                    "first_seen": datetime.datetime.now().isoformat(),
                    "source_report": report_name
                })
    
    # Add report reference if not already tracked
    if report_hash not in [r["hash"] for r in database[domain]["reports"]]:
        database[domain]["reports"].append({
            "name": report_name,
            "hash": report_hash,
            "processed_date": datetime.datetime.now().isoformat()
        })
    
    # Save updated database
    with open(DATABASE_FILE, "w") as f:
        json.dump(database, f, indent=2)
    
    return database

# 📝 Generate Final Bug Bounty Report (Enhanced with visualizations and technical details)
def generate_bug_bounty_report(all_extracted_data):
    """Generate comprehensive AI-powered bug bounty reports with enhanced formatting."""
    import html  # Added import for html.escape

    if not all_extracted_data:
        logger.error("No vulnerabilities detected. No report generated.")
        return

    if not os.path.exists(TEMPLATE_FILE):
        logger.error(f"Report template not found: {TEMPLATE_FILE}")
        return

    try:
        with open(TEMPLATE_FILE, "r", encoding="utf-8") as file:
            template_content = file.read()
        template = Template(template_content)

        # Prepare report data structure
        vulnerabilities_by_severity = {
            "P1": [],
            "P2": [],
            "P3": [],
            "P4": []
        }
        
        all_vulnerabilities = []
        report_stats = {
            "total_vulnerabilities": 0,
            "unique_domains": set(),
            "vulnerability_types": set(),
            "severity_counts": {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        }

        # Process all findings
        for report, data in all_extracted_data.items():
            severity_data = data["severity"]
            severity = severity_data["severity"]
            target_url = extract_target_url(report)
            domain = re.sub(r"^https?://(?:www\.)?", "", target_url).split('/')[0]
            
            report_stats["unique_domains"].add(domain)
            
            for vuln_type, vuln_data in data["vulnerabilities"].items():
                report_stats["vulnerability_types"].add(vuln_type)
                report_stats["total_vulnerabilities"] += len(vuln_data["matches"])
                report_stats["severity_counts"][severity] += len(vuln_data["matches"])
                
                # Create detailed entry for each finding
                for instance in vuln_data["matches"]:
                    vuln_entry = {
                        "type": vuln_type,
                        "value": instance,
                        "confidence": vuln_data["confidence"],
                        "severity": severity,
                        "report": os.path.basename(report),
                        "target_url": target_url,
                        "domain": domain,
                        "poc": generate_poc(vuln_type, target_url) if vuln_type in ["SQL Injection", "XSS", "SSRF", "Command Injection", "Open Redirect", "JWT Issues", "CSRF"] else ""
                    }
                    
                    all_vulnerabilities.append(vuln_entry)
                    vulnerabilities_by_severity[severity].append(vuln_entry)

        # Sort all findings by severity and then by vulnerability type
        all_vulnerabilities.sort(key=lambda x: (list(CVSS_SEVERITY.keys()).index(x["severity"]), x["type"]))
        
        # Generate vulnerability table HTML - Show full URLs/tokens, not truncated
        vulnerability_table = "<table class='vulnerability-table'><thead><tr><th>Type</th><th>Target</th><th>Severity</th><th>Confidence</th><th>Details</th></tr></thead><tbody>"
        
        for vuln in all_vulnerabilities:
            # Display full value without truncation
            vulnerability_table += f"""<tr class='severity-{vuln["severity"].lower()}'>
                <td>{vuln["type"]}</td>
                <td>{vuln["domain"]}</td>
                <td>{vuln["severity"]}</td>
                <td>{vuln["confidence"]}%</td>
                <td><div class='vuln-detail full-content'>{html.escape(str(vuln["value"]))}</div></td>
            </tr>"""
        
        vulnerability_table += "</tbody></table>"
        
        # Generate severity-based findings sections - Show full data, not truncated
        findings_by_severity = ""
        for severity, vulns in vulnerabilities_by_severity.items():
            if vulns:
                findings_by_severity += f"<div class='severity-section severity-{severity.lower()}'>"
                findings_by_severity += f"<h3>{severity} - {CVSS_SEVERITY[severity]['score']}</h3>"
                findings_by_severity += f"<p class='cvss-vector'>{CVSS_SEVERITY[severity]['vector']}</p>"
                findings_by_severity += f"<p>{CVSS_SEVERITY[severity]['description']}</p><ul>"
                
                # Group by vulnerability type
                vulns_by_type = {}
                for vuln in vulns:
                    if vuln["type"] not in vulns_by_type:
                        vulns_by_type[vuln["type"]] = []
                    vulns_by_type[vuln["type"]].append(vuln)
                
                # Create detailed findings by type - Show all instances, not limited to 5
                for vuln_type, type_vulns in vulns_by_type.items():
                    findings_by_severity += f"<li><strong>{vuln_type}</strong> ({len(type_vulns)} instances)<ul>"
                    
                    # Show ALL instances, not just the first 5
                    for vuln in type_vulns:
                        findings_by_severity += f"""<li>
                            <span class='domain-tag'>{vuln['domain']}</span>
                            <div class='full-vulnerability-content'>{html.escape(str(vuln['value']))}</div>
                        </li>"""
                    
                    # Add PoC only once per vulnerability type
                    if type_vulns and type_vulns[0]["poc"]:
                        findings_by_severity += f"<li class='poc-container'>{type_vulns[0]['poc']}</li>"
                    
                    findings_by_severity += "</ul></li>"
                
                findings_by_severity += "</ul></div>"
        
        # Create remediation recommendations based on found vulnerabilities
        remediation_html = "<ul class='remediation-list'>"
        remediation_tips = {
            "API Keys": "Rotate all exposed API keys immediately and move them to secure environment variables or a secrets manager.",
            "Secrets": "Remove hardcoded credentials from code and implement a secrets management solution.",
            "SQL Injection": "Implement prepared statements or parameterized queries. Validate and sanitize all user inputs.",
            "XSS": "Implement proper output encoding and Content-Security-Policy headers. Use frameworks that automatically escape output.",
            "SSRF": "Implement allowlists for external resource requests and avoid sending raw user input to URL fetching functions.",
            "Command Injection": "Avoid using shell commands with user input. If necessary, use allowlists and strict input validation.",
            "Open Redirect": "Implement URL validation against an allowlist of permitted domains or use indirect reference maps.",
            "JWT Issues": "Use strong signing algorithms (RS256), implement proper expiration times, and validate all claims.",
            "CSRF": "Implement anti-CSRF tokens for all state-changing operations and use SameSite cookie attributes.",
            "IDOR": "Implement proper authorization checks for all resource access and avoid using sequential/predictable IDs."
        }
        
        for vuln_type in report_stats["vulnerability_types"]:
            if vuln_type in remediation_tips:
                remediation_html += f"<li><strong>{vuln_type}</strong>: {remediation_tips[vuln_type]}</li>"
        
        remediation_html += "</ul>"
        
        # Generate executive summary
        executive_summary = f"""
        <div class='executive-summary'>
            <p>This AI-powered security analysis identified <strong>{report_stats['total_vulnerabilities']} vulnerabilities</strong> 
            across <strong>{len(report_stats['unique_domains'])} domains</strong>, including 
            <span class='severity-p1'>{report_stats['severity_counts']['P1']} critical</span>, 
            <span class='severity-p2'>{report_stats['severity_counts']['P2']} high</span>, 
            <span class='severity-p3'>{report_stats['severity_counts']['P3']} medium</span>, and 
            <span class='severity-p4'>{report_stats['severity_counts']['P4']} low</span> severity issues.</p>
            <p>The most common vulnerability types identified were: {', '.join(list(report_stats['vulnerability_types'])[:5])}</p>
        </div>
        """
        
        # Generate chart data for visualization
        chart_data = {
            "severity_distribution": [
                report_stats['severity_counts']['P1'],
                report_stats['severity_counts']['P2'],
                report_stats['severity_counts']['P3'],
                report_stats['severity_counts']['P4']
            ],
            "vuln_types": list(report_stats['vulnerability_types'])[:5],  # Top 5 vulnerability types
            "vuln_counts": [len([v for v in all_vulnerabilities if v['type'] == vt]) for vt in list(report_stats['vulnerability_types'])[:5]]
        }
        
        # Add additional CSS for showing full content
        additional_css = """
        <style>
            .full-content, .full-vulnerability-content {
                white-space: pre-wrap;
                word-break: break-all;
                max-height: none;
                overflow: visible;
                font-family: monospace;
                background-color: #f8f8f8;
                padding: 8px;
                border-radius: 4px;
                margin: 5px 0;
            }
            
            .vulnerability-table td {
                max-width: none;
                overflow: visible;
                vertical-align: top;
            }
            
            .vuln-detail {
                max-height: none;
                overflow: visible;
            }
        </style>
        """
        
        # Prepare final report data
        report_data = {
            "report_title": f"AI-Powered Bug Bounty Analysis Report",
            "executive_summary": executive_summary,
            "vulnerability_table": vulnerability_table,
            "findings_by_severity": findings_by_severity,
            "remediation_recommendations": remediation_html,
            "chart_data": json.dumps(chart_data),
            "additional_css": additional_css,
            "references": """
                <ul>
                    <li><a href='https://owasp.org/www-project-top-ten/'>OWASP Top 10</a></li>
                    <li><a href='https://cheatsheetseries.owasp.org/'>OWASP Cheat Sheet Series</a></li>
                    <li><a href='https://portswigger.net/web-security'>PortSwigger Web Security Academy</a></li>
                </ul>
            """,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "total_vulnerabilities": report_stats['total_vulnerabilities']
        }

        # Render template with all data
        output_content = template.render(report_data)
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(OUTPUT_FOLDER, f"bug_bounty_report_{timestamp}.html")

        with open(output_file, "w", encoding="utf-8") as file:
            file.write(output_content)

        logger.info(f"🚀 AI-Powered Bug Bounty Report Generated: {output_file}")
        return output_file
    
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
        return None

# 🔍 Process All Reports with Enhanced Analytics
def process_reports():
    """Process all reports with enhanced analytics, deduplication, and confidence scoring."""
    
    logger.info(f"🔍 Scanning for reports in {REPORTS_FOLDER}...")
    report_files = [os.path.join(REPORTS_FOLDER, f) for f in os.listdir(REPORTS_FOLDER) 
                   if f.endswith((".html", ".txt", ".md", ".xml", ".json"))]

    if not report_files:
        logger.warning("❌ No valid report files found!")
        return {}

    logger.info(f"📂 Found {len(report_files)} report files to process.")
    all_extracted_data = {}
    
    for report_path in report_files:
        try:
            logger.info(f"📄 Processing report: {os.path.basename(report_path)}")
            
            # Extract sensitive data from report
            extracted_data = extract_sensitive_data(report_path)
            
            # If vulnerabilities found, determine severity
            if extracted_data:
                # Convert extracted_data to features and determine severity
                severity_result = determine_severity(extracted_data)
                target_url = extract_target_url(report_path)
                
                # Update vulnerability database
                update_vulnerability_database(extracted_data, report_path)
                
                # Store complete data for report generation
                all_extracted_data[report_path] = {
                    "vulnerabilities": extracted_data,
                    "severity": severity_result,
                    "target_url": target_url
                }
                
                # Print colorized summary
                print(f"{Fore.CYAN}Report:{Style.RESET_ALL} {os.path.basename(report_path)}")
                print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {target_url}")
                print(f"{Fore.CYAN}Severity:{Style.RESET_ALL} {severity_result['severity']} ({severity_result['confidence']}% confidence)")
                print(f"{Fore.CYAN}Vulnerabilities:{Style.RESET_ALL}")
                
                for vuln_type, data in extracted_data.items():
                    color = Fore.RED if vuln_type in ["API Keys", "Secrets", "SQL Injection", "Remote Code Execution"] else Fore.YELLOW
                    print(f"  {color}{vuln_type}:{Style.RESET_ALL} {len(data['matches'])} instances ({data['confidence']}% confidence)")
                
                print(f"{Fore.GREEN}Contributing factors:{Style.RESET_ALL} {', '.join(severity_result['contributing_factors'])}")
                print("-" * 80)
            else:
                logger.info(f"No vulnerabilities found in {os.path.basename(report_path)}")
        
        except Exception as e:
            logger.error(f"Error processing {os.path.basename(report_path)}: {str(e)}")
    
    return all_extracted_data

# Add missing take_evidence_screenshot function
def take_evidence_screenshot(target_url, vulnerability_type, value):
    """Take screenshot evidence using headless browser (simulated)."""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{SCREENSHOTS_FOLDER}/evidence_{vulnerability_type.replace(' ', '_')}_{timestamp}.png"
    
    try:
        # Simulate screenshot taking (in a real implementation, you'd use selenium or playwright)
        logger.info(f"📸 Taking evidence screenshot for {vulnerability_type} at {target_url}")
        
        # Create a dummy file for demonstration
        with open(filename, "w") as f:
            f.write(f"Screenshot evidence for {vulnerability_type} at {target_url}")
        
        return filename
    except Exception as e:
        logger.error(f"Error taking screenshot: {str(e)}")
        return None

# Add missing main function to tie everything together
def main():
    """Main function to run the entire bug bounty automation process."""
    logger.info("🚀 Starting Bug Bounty AI Automation")
    
    # Process all reports
    all_extracted_data = process_reports()
    
    if all_extracted_data:
        # Generate comprehensive report
        output_file = generate_bug_bounty_report(all_extracted_data)
        
        if output_file:
            logger.info(f"✅ Bug Bounty Analysis Complete!")
            logger.info(f"📊 Final Report: {output_file}")
            
            # Try to open the report in default browser
            try:
                report_url = f"file://{os.path.abspath(output_file)}"
                logger.info(f"🌐 Opening report in browser: {report_url}")
                subprocess.run(["python", "-m", "webbrowser", report_url], check=False)
            except Exception as e:
                logger.error(f"Error opening report in browser: {str(e)}")
    else:
        logger.warning("❌ No vulnerabilities found in any reports. No final report generated.")

# Add command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="AI-Powered Bug Bounty Report Analysis")
    parser.add_argument("--reports", type=str, default=REPORTS_FOLDER, 
                      help=f"Path to folder containing bug bounty reports (default: {REPORTS_FOLDER})")
    parser.add_argument("--output", type=str, default=OUTPUT_FOLDER,
                      help=f"Path to output folder for generated reports (default: {OUTPUT_FOLDER})")
    parser.add_argument("--template", type=str, default=TEMPLATE_FILE,
                      help=f"Path to HTML template file (default: {TEMPLATE_FILE})")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    # Update global variables with command line arguments
    REPORTS_FOLDER = args.reports
    OUTPUT_FOLDER = args.output
    TEMPLATE_FILE = args.template
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled")
    
    # Ensure folders exist
    for folder in [REPORTS_FOLDER, OUTPUT_FOLDER, SCREENSHOTS_FOLDER]:
        os.makedirs(folder, exist_ok=True)
    
    # Run the main process
    main()
