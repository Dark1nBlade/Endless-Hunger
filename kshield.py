#!/usr/bin/env python3
"""
kshield.py - Defensive Security and Attack Surface Assessment Tool for Kali Linux.

Defensive/authorized use only with clear scope warnings.
"""

import sys
import os
import socket
import ssl
import json
import csv
import argparse
import threading
import ipaddress
import subprocess
from datetime import datetime
import concurrent.futures
import time

# Scope and authorized use warning
WARNING_BANNER = """
================================================================================
                                 SCOPE WARNING
================================================================================
This utility, KShield, is designed specifically for defensive security analysis,
vulnerability identification, and local compliance verification.
Unauthorized scanning of networks/hosts without explicit written permission
is illegal and violates computer fraud laws.
By proceeding, you agree that you are authorized to evaluate the designated targets.
================================================================================
"""

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 5000, 8000, 9000]

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy/Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
    5000: "Flask/UPnP",
    8000: "HTTP-Alt/Dev",
    9000: "HTTP-Alt/Dev"
}

# Mapping open ports/findings to MITRE ATT&CK techniques with tactics
MITRE_MAPPINGS = {
    21: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion", "severity": "Medium"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "severity": "Medium"}
    ],
    22: [
        {"id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement", "severity": "Medium"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1552.004", "name": "Unsecured Credentials: Private Keys", "tactic": "Credential Access", "severity": "High"}
    ],
    23: [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement", "severity": "High"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"}
    ],
    25: [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1114", "name": "Email Collection", "tactic": "Collection", "severity": "Medium"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "severity": "Medium"}
    ],
    53: [
        {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control", "severity": "Medium"},
        {"id": "T1568", "name": "Dynamic Resolution", "tactic": "Command and Control", "severity": "Medium"},
        {"id": "T1043", "name": "Commonly Used Port", "tactic": "Command and Control", "severity": "Low"}
    ],
    80: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "severity": "High"},
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "severity": "Medium"}
    ],
    110: [
        {"id": "T1114", "name": "Email Collection", "tactic": "Collection", "severity": "Medium"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"}
    ],
    143: [
        {"id": "T1114", "name": "Email Collection", "tactic": "Collection", "severity": "Medium"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"}
    ],
    443: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "severity": "High"},
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "severity": "Medium"}
    ],
    445: [
        {"id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares", "tactic": "Lateral Movement", "severity": "High"},
        {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement", "severity": "Critical"},
        {"id": "T1135", "name": "Network Share Discovery", "tactic": "Discovery", "severity": "Medium"}
    ],
    3306: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact", "severity": "Medium"}
    ],
    3389: [
        {"id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol", "tactic": "Lateral Movement", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1563", "name": "Remote Service Session Hijacking", "tactic": "Lateral Movement", "severity": "High"}
    ],
    5432: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact", "severity": "Medium"}
    ],
    5900: [
        {"id": "T1021.005", "name": "Remote Services: VNC", "tactic": "Lateral Movement", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access", "severity": "High"}
    ],
    6379: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access", "severity": "Medium"},
        {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "severity": "Medium"}
    ],
    8080: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "severity": "High"},
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "severity": "Medium"}
    ],
    8443: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "severity": "High"},
        {"id": "T1071.001", "name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control", "severity": "Medium"}
    ],
    9200: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery", "severity": "Medium"},
        {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "severity": "Medium"}
    ],
    27017: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access", "severity": "High"},
        {"id": "T1496", "name": "Resource Hijacking", "tactic": "Impact", "severity": "Medium"}
    ],
    5000: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "severity": "High"},
        {"id": "T1043", "name": "Commonly Used Port", "tactic": "Command and Control", "severity": "Low"}
    ],
    8000: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "severity": "High"},
        {"id": "T1043", "name": "Commonly Used Port", "tactic": "Command and Control", "severity": "Low"}
    ],
    9000: [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access", "severity": "High"},
        {"id": "T1505.003", "name": "Server Software Component: Web Shell", "tactic": "Persistence", "severity": "High"},
        {"id": "T1043", "name": "Commonly Used Port", "tactic": "Command and Control", "severity": "Low"}
    ]
}

# Detection recommendations per-technique
DETECTION_RECOMMENDATIONS = {
    "T1190": "Monitor web server logs for anomalies, directory traversal attempts, SQL injection payloads, and execution flags. Deploy web application firewalls (WAF) to inspect incoming payloads.",
    "T1078": "Analyze auth/syslog logs for unusual login origins, unexpected high volume of administrative access, or logins during off-business hours.",
    "T1048": "Implement network flow analysis. Monitor high-volume data transfers targeting external servers over alternative protocols (FTP, SSH, raw sockets).",
    "T1021.004": "Ensure SSH key-based authentication is strictly enforced. Audit auth.log for successful SSH logins. Disable password authentication.",
    "T1110": "Configure account lockout thresholds. Analyze auth.log, fail2ban, or central syslog for high-frequency connection rejections or invalid login attempts.",
    "T1552.004": "Enforce strict local filesystem permissions. Scan home directories for unencrypted id_rsa files or embedded configuration passwords.",
    "T1021": "Ensure remote services are securely restricted via network firewalls and host-based access lists. Log all remote terminal attempts.",
    "T1040": "Audit raw socket creation on endpoints. Ensure transport level encryption is enabled for all legacy protocols (use SSL/TLS).",
    "T1566": "Implement email filtering gateways, attachment blocklists, SPF/DKIM/DMARC validation, and user security awareness training.",
    "T1114": "Monitor mail flow rates, unauthorized IMAP/POP3 connections from unknown subnets, and bulk email exports.",
    "T1071.004": "Inspect local DNS query logs for high volume of subdomains, dynamic names, or high-frequency TXT/NULL record lookups representing tunnel traffic.",
    "T1568": "Monitor endpoint connection attempts to fast-flux IP pools or external domain-generation algorithm (DGA) resolved hosts.",
    "T1043": "Verify that outbound server requests are restricted strictly to authorized infrastructure and ports via outbound firewall policy.",
    "T1505.003": "Audit local web document roots (/var/www) for newly created .py, .php, or .sh files. Use file integrity monitoring (FIM).",
    "T1071.001": "Inspect application proxies and HTTP proxy logs. Look for un-user-agented clients or anomalous HTTP payloads targeting outbound destinations.",
    "T1021.002": "Disable SMBv1 entirely. Restrict port 445 inbound access to designated management subnets. Require SMB signing and encryption.",
    "T1210": "Ensure prompt software patching (e.g., MS17-010 or Samba vulnerabilities). Enable endpoint network analysis tools.",
    "T1135": "Restrict administrative share access. Enable access auditing for shared drives and directories.",
    "T1498": "Implement rate limiting, traffic filtering at perimeter gateways, and upstream DDoS mitigation measures.",
    "T1021.001": "Disable RDP if unnecessary. Place RDP servers behind a VPN/bastion host and use multi-factor authentication (MFA).",
    "T1563": "Enable RDP connection logs and review reconnect attempts. Correlate with concurrent active administrative sessions.",
    "T1021.005": "Avoid exposing VNC to untrusted networks. Require encryption and robust authentication mechanisms.",
    "T1496": "Monitor system resources (CPU, Memory) for unusual persistent spikes. Restrict outbound egress connections to crypto pools.",
    "T1083": "Monitor filesystem command history (e.g., frequent recursive directory traversals) and check for system profiling command usage."
}

# Sigma rules template parameters per technique
SIGMA_TEMPLATES = {
    "T1110": """title: SSH/Service Brute Force Attempt
id: f6b51bf1-766b-4e1a-8260-ca72a819bdfb
status: experimental
description: Detects multiple failed authentication attempts to critical remote management ports indicative of brute force.
references:
    - https://attack.mitre.org/techniques/T1110/
logsource:
    product: linux
    service: auth
detection:
    selection:
        message|contains:
            - 'Failed password for'
            - 'invalid user'
            - 'Authentication failure'
    timeframe: 5m
    condition: selection | count() > 10
falsepositives:
    - Administrator forgetting password
level: high""",
    "T1021.004": """title: Successful SSH Login from Non-Standard Origin
id: cd2684b3-3a1b-4171-bc01-e24c70bbefcb
status: experimental
description: Detects successful SSH logins, which can be correlated with non-standard networks.
references:
    - https://attack.mitre.org/techniques/T1021/004/
logsource:
    product: linux
    service: auth
detection:
    selection:
        message|contains:
            - 'Accepted password for'
            - 'Accepted publickey for'
    condition: selection
falsepositives:
    - Regular administrative logins
level: medium""",
    "T1505.003": """title: Web Shell Activity and File Creation
id: a7d8e2d4-0c2b-4221-bcde-2a21e49d0315
status: experimental
description: Detects creation or execution of potential web shell payloads in web directories.
references:
    - https://attack.mitre.org/techniques/T1505/003/
logsource:
    product: linux
    category: file_event
detection:
    selection:
        target_path|contains:
            - '/var/www/html/'
            - '/usr/share/nginx/html/'
        target_path|endswith:
            - '.php'
            - '.jsp'
            - '.py'
            - '.sh'
    condition: selection
falsepositives:
    - Legitimate application deployments or updates
level: high""",
    "T1190": """title: Web Exploitation Attempt Against Public Application
id: d761b2c4-1100-47b7-ab00-e24ca819bdf1
status: experimental
description: Detects common exploit patterns in incoming web requests.
references:
    - https://attack.mitre.org/techniques/T1190/
logsource:
    product: webserver
detection:
    selection:
        cs-uri-query|contains:
            - '/etc/passwd'
            - '../'
            - 'select '
            - 'union '
            - 'chmod '
    condition: selection
falsepositives:
    - Security scanning or penetration testing
level: high""",
    "T1021.002": """title: Remote Service Access Over SMB
id: a9b8c7d6-3e21-4f11-9aab-0cb2b11562ad
status: experimental
description: Detects remote SMB service connections and file accesses that could represent lateral movement.
references:
    - https://attack.mitre.org/techniques/T1021/002/
logsource:
    product: windows/linux
    service: smb
detection:
    selection:
        RelativeTargetName|contains:
            - 'ADMIN$'
            - 'C$'
            - 'IPC$'
    condition: selection
falsepositives:
    - Domain controller replication or system administrator tasks
level: medium""",
    "T1071.001": """title: Anomalous HTTP Outbound Egress
id: e2b4f177-33aa-44dd-ab88-e219ba99276d
status: experimental
description: Detects outbound HTTP requests with common C2 patterns or anomalous User-Agents.
references:
    - https://attack.mitre.org/techniques/T1071/001/
logsource:
    category: proxy
detection:
    selection:
        user-agent|contains:
            - 'curl'
            - 'wget'
            - 'powershell'
            - 'python'
    condition: selection
falsepositives:
    - Standard administrative scripts or software updates
level: low"""
}

# Default Sigma rule template for any mapped technique
DEFAULT_SIGMA_TEMPLATE = """title: MITRE Technique detection trigger
id: {uuid}
status: experimental
description: Automatically generated rule to detect activity associated with MITRE technique {tech_id} ({tech_name}).
references:
    - https://attack.mitre.org/techniques/{tech_id}/
logsource:
    product: linux
detection:
    selection:
        message|contains:
            - '{tech_id}'
    condition: selection
falsepositives:
    - Legitimate administration behavior
level: medium"""


# Tactic severity definitions for priority risk matrix scoring
TACTIC_SEVERITY = {
    "Initial Access": 8,
    "Execution": 7,
    "Persistence": 7,
    "Credential Access": 8,
    "Defense Evasion": 6,
    "Lateral Movement": 9,
    "Discovery": 3,
    "Collection": 5,
    "Command and Control": 8,
    "Exfiltration": 7,
    "Impact": 6
}


def parse_targets(target_str):
    """
    Parses comma-separated targets.
    Supports individual IPs, Hostnames, CIDR ranges.
    """
    targets = []
    for raw in target_str.split(','):
        raw = raw.strip()
        if not raw:
            continue
        # Check if CIDR
        if '/' in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
                for ip in net.hosts():
                    targets.append(str(ip))
                if not targets: # If it was a /32 or /31 with no hosts()
                    targets.append(str(net.network_address))
            except Exception as e:
                # Fallback as hostname or literal
                targets.append(raw)
        else:
            # Check if simple IP
            try:
                ip = ipaddress.ip_address(raw)
                targets.append(str(ip))
            except ValueError:
                # Probably a hostname
                targets.append(raw)
    return targets


def banner_grab(sock, port, timeout):
    """
    Attempts to read banner from the connected socket.
    Sends protocol-specific triggers if necessary to elicit response.
    """
    sock.settimeout(timeout)
    try:
        # Standard socket read
        return sock.recv(1024).decode('utf-8', errors='ignore').strip()
    except Exception:
        pass

    # Protocol-specific active prompts
    try:
        if port == 80 or port == 8080 or port == 8000 or port == 9000:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        elif port == 21:
            sock.sendall(b"HELP\r\n")
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
        elif port == 23:
            # Telnet negotiate options
            sock.sendall(b"\xff\xfd\x03\xff\xfb\x18\xff\xfb\x1f\xff\xfd\x00")
            return sock.recv(1024).decode('utf-8', errors='ignore').strip()
    except Exception:
        pass
    return ""


def perform_ssl_analysis(target, port, timeout):
    """
    Performs basic SSL/TLS connection.
    Retrieves version, cipher, certificate details, and checks expiration.
    """
    results = {
        "ssl_enabled": False,
        "tls_version": None,
        "cipher": None,
        "cert_expiry": None,
        "expired": False,
        "weak_config": False,
        "weak_reasons": []
    }

    context = ssl.create_default_context()
    # Accept self-signed certificates for assessment purposes
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                results["ssl_enabled"] = True
                results["tls_version"] = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    results["cipher"] = cipher_info[0]
                    # Check for weak cipher configuration (under 128-bit security)
                    if cipher_info[2] < 128:
                        results["weak_config"] = True
                        results["weak_reasons"].append(f"Weak cipher strength ({cipher_info[2]} bits)")

                # TLS Version weak checks
                if results["tls_version"] in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                    results["weak_config"] = True
                    results["weak_reasons"].append(f"Outdated TLS version ({results['tls_version']})")

                # SSL Certificate details
                cert = ssock.getpeercert(binary_form=True)
                if cert:
                    # In python with CERT_NONE we only get binary cert. Let's load and inspect.
                    # Standard stdlib parser
                    try:
                        parsed_cert = ssock.getpeercert()
                        if not parsed_cert:
                            # Reconnect with validation to fetch cert metadata
                            context_val = ssl.create_default_context()
                            context_val.check_hostname = False
                            context_val.verify_mode = ssl.CERT_REQUIRED
                            # If verification fails, SSLCertVerificationError is raised, but we can capture it
                            # to extract the DER cert first. But let's try reading getpeercert() first.
                            pass
                    except Exception:
                        pass

                # Alternative get_server_certificate to get plain expiry (or load the cert info)
                # To keep it reliable without double connections, let's fall back to standard library connection to parse:
                try:
                    pem_cert = ssl.get_server_certificate((target, port), timeout=timeout)
                    # We can parse the time using raw parsing of the cert or simple lookup of expiration
                    # A robust way is converting to DER then parsing, but since we are standard-library-only,
                    # we can use ssl.getpeercert(True) parsing or an openssl subprocess call if installed,
                    # or standard regex over pem/der. Let's do a quick datetime parser if possible, or gracefully skip if not parsed.
                    # Standard Python ssl can parse cert dict if verify_mode is set. Let's do a sub-connection with verify.
                    pass
                except Exception:
                    pass

                # Let's extract certificate details by doing a context connection with CERT_OPTIONAL
                try:
                    context_opt = ssl.create_default_context()
                    context_opt.check_hostname = False
                    context_opt.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((target, port), timeout=timeout) as s2:
                        with context_opt.wrap_socket(s2, server_hostname=target) as ss2:
                            # Note: CERT_NONE doesn't return decoded cert, CERT_REQUIRED does.
                            # So we try CERT_REQUIRED.
                            pass
                except Exception:
                    pass
    except Exception:
        # Port might not support SSL or connection closed
        pass

    # Let's do a second attempt to retrieve certificate expiration using standard library certificate fetcher
    if results["ssl_enabled"]:
        try:
            # We can use the ssl.get_server_certificate to fetch PEM.
            # Then we can parse it if needed. However, standard ssl provides certificate parsed info
            # only if we use ssl.create_default_context() with CA certificates.
            # Let's try to load default verify paths and establish connection.
            ctx_verify = ssl.create_default_context()
            ctx_verify.check_hostname = False
            ctx_verify.verify_mode = ssl.CERT_REQUIRED
            with socket.create_connection((target, port), timeout=timeout) as s_verify:
                with ctx_verify.wrap_socket(s_verify, server_hostname=target) as ss_verify:
                    cert_dict = ss_verify.getpeercert()
                    if cert_dict and "notAfter" in cert_dict:
                        expiry_str = cert_dict["notAfter"]
                        results["cert_expiry"] = expiry_str
                        # Parse date, format: "Jan 31 23:59:59 2026 GMT"
                        try:
                            expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                            if expiry_dt < datetime.utcnow():
                                results["expired"] = True
                                results["weak_config"] = True
                                results["weak_reasons"].append("Certificate is expired")
                        except Exception:
                            pass
        except Exception:
            # If CA cert is missing or self-signed, it might fail. We gracefully ignore.
            pass

    return results


def perform_http_probing(target, port, timeout):
    """
    Performs standard HTTP probe.
    Gets response status, Server header, and identifies potential dev portals.
    """
    results = {
        "is_http": False,
        "status_code": None,
        "server_header": None,
        "is_dev_port": False,
        "additional_info": ""
    }

    # Identify if it is a commonly used dev port
    if port in [5000, 8000, 9000, 8080]:
        results["is_dev_port"] = True

    try:
        # Use HTTP/HTTPS probe
        protocol = "https" if port in [443, 8443] else "http"
        # We can construct raw HTTP request to stay robust and support short timeouts
        with socket.create_connection((target, port), timeout=timeout) as sock:
            # If port is 443/8443 wrap with SSL
            if protocol == "https":
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            # Send HTTP HEAD request
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\nConnection: close\r\n\r\n")
            response = sock.recv(2048).decode('utf-8', errors='ignore')

            if response.startswith("HTTP/"):
                results["is_http"] = True
                lines = response.split("\r\n")
                status_line = lines[0]
                # Extract status code
                parts = status_line.split(" ")
                if len(parts) >= 2:
                    try:
                        results["status_code"] = int(parts[1])
                    except ValueError:
                        pass

                # Extract Server header
                for line in lines:
                    if line.lower().startswith("server:"):
                        results["server_header"] = line.split(":", 1)[1].strip()
                        break
    except Exception:
        pass

    return results


def scan_single_port(target, port, timeout):
    """
    Connects to a single target port and gathers details.
    """
    finding = {
        "port": port,
        "service": PORT_SERVICES.get(port, "unknown"),
        "state": "closed",
        "banner": "",
        "ssl_analysis": None,
        "http_probing": None
    }

    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            finding["state"] = "open"

            # Banner Grabbing
            banner = banner_grab(sock, port, timeout)
            finding["banner"] = banner
    except Exception:
        # Port is closed or timeout
        return None

    # Perform subsequent probes if open
    finding["ssl_analysis"] = perform_ssl_analysis(target, port, timeout)
    finding["http_probing"] = perform_http_probing(target, port, timeout)

    return finding


def scan_target(target, ports, threads, timeout):
    """
    Scans a single target for the designated ports.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_single_port, target, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            f = future.result()
            if f:
                results.append(f)
    return results


def run_full_scan(targets, ports, threads, timeout):
    """
    Executes scanning over all targets and ports.
    """
    all_findings = {}
    for target in targets:
        print(f"[*] Scanning target: {target}")
        findings = scan_target(target, ports, threads, timeout)
        all_findings[target] = findings
        print(f"[+] Scan completed for {target}. Found {len(findings)} open ports.")
    return all_findings


def map_to_mitre(all_findings):
    """
    Maps findings to MITRE ATT&CK techniques, tactics, priority risk matrix,
    recommendations, and Sigma rule candidates.
    """
    mitre_summary = {
        "mapped_techniques": [],
        "risk_priority_matrix": {},
        "recommendations": {},
        "sigma_rules": {}
    }

    # Extract all unique techniques triggered across findings
    unique_techs = {}
    tactic_exposure = {} # Count exposure per tactic

    # Initialize tactic exposure count
    for t in TACTIC_SEVERITY:
        tactic_exposure[t] = 0

    for target, findings in all_findings.items():
        for f in findings:
            port = f["port"]
            if port in MITRE_MAPPINGS:
                for mapping in MITRE_MAPPINGS[port]:
                    tech_id = mapping["id"]
                    tactic = mapping["tactic"]

                    if tech_id not in unique_techs:
                        unique_techs[tech_id] = {
                            "id": tech_id,
                            "name": mapping["name"],
                            "tactic": tactic,
                            "severity": mapping["severity"],
                            "ports_triggered": set()
                        }
                    unique_techs[tech_id]["ports_triggered"].add(port)
                    # Increment exposure for tactic
                    tactic_exposure[tactic] = tactic_exposure.get(tactic, 0) + 1

    # Map techniques format
    for tid, t_details in unique_techs.items():
        t_details["ports_triggered"] = sorted(list(t_details["ports_triggered"]))
        mitre_summary["mapped_techniques"].append(t_details)

        # Map to recommendations
        rec = DETECTION_RECOMMENDATIONS.get(tid, f"Audit event logs for references to {tid}.")
        mitre_summary["recommendations"][tid] = {
            "name": t_details["name"],
            "tactic": t_details["tactic"],
            "recommendation": rec
        }

        # Map to Sigma Rules
        if tid in SIGMA_TEMPLATES:
            rule_content = SIGMA_TEMPLATES[tid]
        else:
            rule_content = DEFAULT_SIGMA_TEMPLATE.format(
                uuid=f"a9b8c7d6-3e21-4f11-9aab-0cb2b1156{hash(tid) % 10000:04d}",
                tech_id=tid,
                tech_name=t_details["name"]
            )
        mitre_summary["sigma_rules"][tid] = rule_content

    # Calculate Risk Priority Matrix scoring: severity + exposure count
    # Scoring = Tactic Base Severity * Exposure Count
    matrix = {}
    for tactic, base_sev in TACTIC_SEVERITY.items():
        exposure = tactic_exposure.get(tactic, 0)
        score = base_sev * exposure
        if exposure > 0:
            matrix[tactic] = {
                "base_severity": base_sev,
                "exposure_count": exposure,
                "calculated_score": score,
                "priority_level": "Critical" if score >= 15 else "High" if score >= 8 else "Medium" if score >= 3 else "Low"
            }
    mitre_summary["risk_priority_matrix"] = matrix

    return mitre_summary


def validate_local_policies():
    """
    Validates local security policies.
    Returns firewall/service statuses, logs access, and a percentage score.
    """
    results = {
        "firewall_status": {
            "iptables": {"active": False, "details": ""},
            "ufw": {"active": False, "details": ""},
            "nftables": {"active": False, "details": ""}
        },
        "defense_services": {
            "fail2ban": {"active": False, "details": ""},
            "auditd": {"active": False, "details": ""},
            "selinux": {"active": False, "details": ""},
            "apparmor": {"active": False, "details": ""}
        },
        "audit_trails": {
            "auth_log": {"accessible": False, "path": "/var/log/auth.log", "details": ""},
            "syslog": {"accessible": False, "path": "/var/log/syslog", "details": ""},
            "audit_log": {"accessible": False, "path": "/var/log/audit/audit.log", "details": ""},
            "ufw_log": {"accessible": False, "path": "/var/log/ufw.log", "details": ""}
        },
        "policy_score": 0.0,
        "enforced_percentage": 0
    }

    checks_run = 0
    checks_passed = 0

    # Helper function to run shell commands safely
    def run_cmd(args):
        try:
            res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, text=True)
            return res.returncode == 0, res.stdout.strip() + "\n" + res.stderr.strip()
        except Exception as e:
            return False, str(e)

    # 1. Firewalls
    # iptables check
    success, output = run_cmd(["which", "iptables"])
    if success:
        # Check active rules
        rules_success, rules_output = run_cmd(["sudo", "iptables", "-L", "-n"])
        # If any chains exist and have rules/default drop, or just command runs successfully
        if rules_success:
            results["firewall_status"]["iptables"]["active"] = True
            # Simple check if there are actual rule entries besides headers
            non_empty_rules = [line for line in rules_output.split("\n") if line.strip() and not line.startswith("Chain") and not line.startswith("target")]
            if non_empty_rules:
                results["firewall_status"]["iptables"]["details"] = f"Rules configured ({len(non_empty_rules)} rules detected)."
            else:
                results["firewall_status"]["iptables"]["details"] = "Service installed, but no active filtering rules defined."
        else:
            results["firewall_status"]["iptables"]["details"] = "Installed, but failed to list rules (sudo access required)."
    else:
        results["firewall_status"]["iptables"]["details"] = "Binary not found in standard system path."

    # ufw check
    success, output = run_cmd(["which", "ufw"])
    if success:
        st_success, st_output = run_cmd(["sudo", "ufw", "status"])
        if st_success:
            if "inactive" not in st_output.lower():
                results["firewall_status"]["ufw"]["active"] = True
                results["firewall_status"]["ufw"]["details"] = "UFW is active and enforcing."
            else:
                results["firewall_status"]["ufw"]["details"] = "UFW is installed but inactive."
        else:
            results["firewall_status"]["ufw"]["details"] = "Installed, but failed to retrieve status."
    else:
        results["firewall_status"]["ufw"]["details"] = "Binary not found."

    # nftables check
    success, output = run_cmd(["which", "nft"])
    if success:
        st_success, st_output = run_cmd(["sudo", "nft", "list", "ruleset"])
        if st_success:
            if st_output.strip():
                results["firewall_status"]["nftables"]["active"] = True
                results["firewall_status"]["nftables"]["details"] = "nftables ruleset is active."
            else:
                results["firewall_status"]["nftables"]["details"] = "nftables is installed, but ruleset is empty."
        else:
            results["firewall_status"]["nftables"]["details"] = "Installed, but failed to list ruleset."
    else:
        results["firewall_status"]["nftables"]["details"] = "Binary not found."

    # Determine if firewall is active (at least one firewall check counts toward policy score)
    checks_run += 1
    if any(results["firewall_status"][fw]["active"] for fw in results["firewall_status"]):
        checks_passed += 1

    # 2. Defense Services
    # fail2ban check
    success, output = run_cmd(["which", "fail2ban-client"])
    if success:
        st_success, st_output = run_cmd(["sudo", "fail2ban-client", "status"])
        if st_success:
            results["defense_services"]["fail2ban"]["active"] = True
            results["defense_services"]["fail2ban"]["details"] = "Fail2ban client verified. " + st_output.replace("\n", " ")
        else:
            results["defense_services"]["fail2ban"]["details"] = "Installed, but failed to query status."
    else:
        results["defense_services"]["fail2ban"]["details"] = "Service binary not found."

    checks_run += 1
    if results["defense_services"]["fail2ban"]["active"]:
        checks_passed += 1

    # auditd check
    success, output = run_cmd(["which", "auditctl"])
    if success:
        st_success, st_output = run_cmd(["sudo", "auditctl", "-s"])
        if st_success:
            if "enabled 1" in st_output.lower() or "active" in st_output.lower():
                results["defense_services"]["auditd"]["active"] = True
                results["defense_services"]["auditd"]["details"] = "auditd is enabled and logging. " + st_output
            else:
                results["defense_services"]["auditd"]["details"] = "auditd binary found, but not active."
        else:
            results["defense_services"]["auditd"]["details"] = "Installed, but failed to read status."
    else:
        results["defense_services"]["auditd"]["details"] = "Service binaries not found."

    checks_run += 1
    if results["defense_services"]["auditd"]["active"]:
        checks_passed += 1

    # SELinux check
    success, output = run_cmd(["which", "selinuxenabled"])
    if success:
        st_success, st_output = run_cmd(["selinuxenabled"])
        if st_success:
            results["defense_services"]["selinux"]["active"] = True
            results["defense_services"]["selinux"]["details"] = "SELinux is enabled."
        else:
            results["defense_services"]["selinux"]["details"] = "SELinux is installed but disabled/inactive."
    else:
        # Fallback to check sestatus if available
        success_se, output_se = run_cmd(["which", "sestatus"])
        if success_se:
            st_success, st_output = run_cmd(["sestatus"])
            if st_success and "enabled" in st_output.lower() and "disabled" not in st_output.lower():
                results["defense_services"]["selinux"]["active"] = True
                results["defense_services"]["selinux"]["details"] = "SELinux sestatus verified enabled."
            else:
                results["defense_services"]["selinux"]["details"] = "SELinux sestatus reported inactive."
        else:
            results["defense_services"]["selinux"]["details"] = "SELinux binaries not found."

    # AppArmor check
    success, output = run_cmd(["which", "apparmor_status"])
    if success:
        st_success, st_output = run_cmd(["sudo", "apparmor_status"])
        if st_success:
            results["defense_services"]["apparmor"]["active"] = True
            # Parse profiles loaded
            profiles = [line for line in st_output.split("\n") if "profiles are loaded" in line]
            details = profiles[0] if profiles else "AppArmor active."
            results["defense_services"]["apparmor"]["details"] = details
        else:
            results["defense_services"]["apparmor"]["details"] = "Installed, but failed to query status."
    else:
        results["defense_services"]["apparmor"]["details"] = "Service binary not found."

    # AppArmor / SELinux checking (at least one MAC system should be configured/active)
    checks_run += 1
    if results["defense_services"]["selinux"]["active"] or results["defense_services"]["apparmor"]["active"]:
        checks_passed += 1

    # 3. Audit Trails Accessibility
    # Check if files can be opened/read (access verification)
    for trail, trail_info in results["audit_trails"].items():
        path = trail_info["path"]
        checks_run += 1
        try:
            # Test read access
            with open(path, 'r') as f:
                # Read small chunk to confirm
                f.read(10)
                results["audit_trails"][trail]["accessible"] = True
                results["audit_trails"][trail]["details"] = "Accessible (Readable)."
                checks_passed += 1
        except PermissionError:
            results["audit_trails"][trail]["details"] = "Inaccessible (Permission Denied - sudo required)."
        except FileNotFoundError:
            results["audit_trails"][trail]["details"] = "Not Found."
        except Exception as e:
            results["audit_trails"][trail]["details"] = f"Error: {str(e)}"

    # Score calculation
    if checks_run > 0:
        score = (checks_passed / checks_run) * 100.0
        results["policy_score"] = round(score, 2)
        results["enforced_percentage"] = int(score)

    return results


def print_console_report(all_findings, mitre_summary, policy_results):
    """
    Prints a detailed console report.
    """
    print("\n" + "=" * 80)
    print("                      KSHIELD SYSTEM ASSESSMENT REPORT")
    print("=" * 80)
    print(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 80)

    # 1. Exposure & Surface scan Summary
    print("\n[+] 1. ATTACK SURFACE EXPOSURE ASSESSMENT")
    print("-" * 40)
    total_ports = 0
    for target, findings in all_findings.items():
        print(f"Target Host: {target}")
        if not findings:
            print("  No open ports detected from top 20 ports.")
        else:
            for f in findings:
                total_ports += 1
                banner_str = f"| Banner: {f['banner']}" if f["banner"] else ""
                print(f"  - Port {f['port']:<5} [{f['service']:<12}] STATE: {f['state']} {banner_str}")
                # SSL Details
                ssl_a = f.get("ssl_analysis")
                if ssl_a and ssl_a["ssl_enabled"]:
                    weak_cfg = " (WEAK CONFIG!)" if ssl_a["weak_config"] else ""
                    print(f"    * SSL/TLS: {ssl_a['tls_version']} | Cipher: {ssl_a['cipher']}{weak_cfg}")
                    if ssl_a["weak_reasons"]:
                        print(f"      Reasons: {', '.join(ssl_a['weak_reasons'])}")
                    if ssl_a["cert_expiry"]:
                        print(f"      Cert Expiration: {ssl_a['cert_expiry']}")
                # HTTP Probing details
                http_p = f.get("http_probing")
                if http_p and http_p["is_http"]:
                    dev_str = " [DEV PORT DETECTED]" if http_p["is_dev_port"] else ""
                    print(f"    * HTTP Probe: Status {http_p['status_code']} | Server: {http_p['server_header']}{dev_str}")
        print()

    # 2. MITRE ATT&CK Mapping & Priority Matrix
    print("[+] 2. MITRE ATT&CK EXPOSURE MATRIX & PRIORITY MATRIX")
    print("-" * 40)
    if not mitre_summary["mapped_techniques"]:
        print("No exposure mapped to MITRE ATT&CK tactics.")
    else:
        # Risk priority matrix table
        print(f"{'MITRE TACTIC':<25} | {'BASE SEVERITY':<15} | {'EXPOSURE COUNT':<15} | {'SCORE':<8} | {'PRIORITY':<10}")
        print("-" * 80)
        # Sort matrix by score descending
        sorted_matrix = sorted(mitre_summary["risk_priority_matrix"].items(), key=lambda x: x[1]["calculated_score"], reverse=True)
        for tactic, data in sorted_matrix:
            print(f"{tactic:<25} | {data['base_severity']:<15} | {data['exposure_count']:<15} | {data['calculated_score']:<8} | {data['priority_level']:<10}")
        print("-" * 80)

        print("\nMapped MITRE ATT&CK Techniques:")
        for t in mitre_summary["mapped_techniques"]:
            print(f"  - {t['id']:<10} [{t['tactic']:<20}] {t['name']} (Severity: {t['severity']})")
            print(f"    Triggered by Port(s): {', '.join(map(str, t['ports_triggered']))}")

    # 3. Detection Recommendations
    print("\n[+] 3. DETECTION RECOMMENDATIONS")
    print("-" * 40)
    if not mitre_summary["recommendations"]:
        print("No detection recommendations available.")
    else:
        for tid, data in mitre_summary["recommendations"].items():
            print(f"Technique: {tid} - {data['name']} ({data['tactic']})")
            print(f"Recommendation: {data['recommendation']}\n")

    # 4. Local Compliance Policy Validation
    print("[+] 4. LOCAL POLICY VALIDATION")
    print("-" * 40)
    print(f"Policy Enforcement Percentage: {policy_results['enforced_percentage']}%")
    print(f"Local Compliance Score: {policy_results['policy_score']}/100.0\n")

    print("Firewall Enforcement Status:")
    for fw, details in policy_results["firewall_status"].items():
        status = "ENABLED" if details["active"] else "DISABLED"
        print(f"  - {fw:<10} Status: {status:<10} | Details: {details['details']}")

    print("\nSystem Security Services Status:")
    for srv, details in policy_results["defense_services"].items():
        status = "ENABLED" if details["active"] else "DISABLED"
        print(f"  - {srv:<10} Status: {status:<10} | Details: {details['details']}")

    print("\nSystem Audit Trails Accessibility:")
    for trail, details in policy_results["audit_trails"].items():
        status = "ACCESSIBLE" if details["accessible"] else "INACCESSIBLE"
        print(f"  - {trail:<10} Path: {details['path']:<25} Status: {status:<15} | {details['details']}")

    print("\n" + "=" * 80)
    print("                              END OF REPORT")
    print("=" * 80 + "\n")


def export_json(filepath, all_findings, mitre_summary, policy_results):
    """
    Exports full assessment results to JSON.
    """
    # Create serializable output
    serializable = {
        "assessment_timestamp": datetime.now().isoformat(),
        "attack_surface_scanned": all_findings,
        "mitre_attack_mappings": {
            "mapped_techniques": mitre_summary["mapped_techniques"],
            "risk_priority_matrix": mitre_summary["risk_priority_matrix"],
            "recommendations": mitre_summary["recommendations"]
        },
        "policy_validation": policy_results
    }

    try:
        with open(filepath, 'w') as f:
            json.dump(serializable, f, indent=4)
        print(f"[+] JSON report successfully exported to {filepath}")
    except Exception as e:
        print(f"[-] Error exporting to JSON: {str(e)}")


def export_csv(filepath, all_findings, mitre_summary):
    """
    Exports parsed vulnerabilities and MITRE ATT&CK mapping to CSV format.
    """
    try:
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["Target", "Port", "Service", "State", "Banner", "MITRE Technique ID", "MITRE Technique Name", "Tactic", "Severity"])

            for target, findings in all_findings.items():
                for fn in findings:
                    port = fn["port"]
                    # If mapped to MITRE, write mapping rows
                    mapped_any = False
                    if port in MITRE_MAPPINGS:
                        for mapping in MITRE_MAPPINGS[port]:
                            mapped_any = True
                            writer.writerow([
                                target,
                                port,
                                fn["service"],
                                fn["state"],
                                fn["banner"].replace("\n", " ").replace("\r", ""),
                                mapping["id"],
                                mapping["name"],
                                mapping["tactic"],
                                mapping["severity"]
                            ])
                    if not mapped_any:
                        writer.writerow([
                            target,
                            port,
                            fn["service"],
                            fn["state"],
                            fn["banner"].replace("\n", " ").replace("\r", ""),
                            "N/A",
                            "N/A",
                            "N/A",
                            "N/A"
                        ])
        print(f"[+] CSV report successfully exported to {filepath}")
    except Exception as e:
        print(f"[-] Error exporting to CSV: {str(e)}")


def export_sigma(filepath, mitre_summary):
    """
    Exports generated Sigma Rule YAML candidates into a single combined rule file or package structure.
    """
    try:
        with open(filepath, 'w') as f:
            f.write("# Combined Sigma Rule Candidates Generated by KShield\n")
            f.write("# Import these configurations directly into your SIEM platform.\n")
            f.write("---\n")

            for tid, rule_yaml in mitre_summary["sigma_rules"].items():
                f.write(rule_yaml)
                f.write("\n---\n")
        print(f"[+] Sigma rules successfully exported to {filepath}")
    except Exception as e:
        print(f"[-] Error exporting to Sigma rules: {str(e)}")


def main():
    parser = argparse.ArgumentParser(
        description="KShield - Defensive security analyzer and compliance policy validation tool for Kali Linux."
    )
    parser.add_argument("--targets", required=True, help="IP addresses, hostnames, or CIDR blocks (comma-separated).")
    parser.add_argument("--ports", default=None, help="Comma-separated ports to scan (Defaults to standard top 20 ports).")
    parser.add_argument("--threads", type=int, default=10, help="Maximum thread execution count (default 10).")
    parser.add_argument("--timeout", type=float, default=2.0, help="Connection socket timeout duration in seconds (default 2.0).")
    parser.add_argument("--validate-policies", action="store_true", help="Include local endpoint policy and compliance audit checks.")
    parser.add_argument("--json", help="Path to export report results in JSON format.")
    parser.add_argument("--csv", help="Path to export report results in CSV spreadsheet format.")
    parser.add_argument("--sigma", help="Path to export candidate Sigma rules in YAML format.")

    args = parser.parse_args()

    # Display Warning and require confirmation to ensure defensive / authorized use only
    print(WARNING_BANNER)
    try:
        choice = input("Do you confirm you have authorized access to scan the specified target environment? (yes/no): ").strip().lower()
        if choice not in ["yes", "y"]:
            print("Aborted. Authorized consent is required to execute security assessments.")
            sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        sys.exit(1)

    # 1. Parsing target networks and ranges
    targets = parse_targets(args.targets)
    if not targets:
        print("[-] Error: No valid targets parsed. Verify target values input.")
        sys.exit(1)

    # Parsing port range
    ports = TOP_PORTS
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',') if p.strip()]
        except ValueError:
            print("[-] Error: Ports list must contain valid integers.")
            sys.exit(1)

    print(f"[*] Parsing target(s) completed. Evaluated host list: {', '.join(targets)}")
    print(f"[*] Attack surface scan initialized targeting {len(ports)} specific ports with thread pool of {args.threads}.")

    # 2. Execute scanning
    start_time = time.time()
    all_findings = run_full_scan(targets, ports, args.threads, args.timeout)
    scan_duration = time.time() - start_time
    print(f"[*] Network exposure assessment completed in {scan_duration:.2f} seconds.")

    # 3. Map to MITRE
    mitre_summary = map_to_mitre(all_findings)

    # 4. Local policy compliance validation
    policy_results = {}
    if args.validate_policies:
        print("[*] Validating host local endpoint security enforcement policies...")
        policy_results = validate_local_policies()
    else:
        # Produce placeholder response structure if validation is disabled
        policy_results = {
            "firewall_status": {},
            "defense_services": {},
            "audit_trails": {},
            "policy_score": 0.0,
            "enforced_percentage": 0,
            "validation_run": False
        }

    # 5. Report output
    print_console_report(all_findings, mitre_summary, policy_results)

    # 6. Optional file outputs
    if args.json:
        export_json(args.json, all_findings, mitre_summary, policy_results)
    if args.csv:
        export_csv(args.csv, all_findings, mitre_summary)
    if args.sigma:
        export_sigma(args.sigma, mitre_summary)


if __name__ == "__main__":
    main()
