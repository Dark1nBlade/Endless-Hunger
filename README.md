# KShield: Defensive Security & Attack Surface Mapping Tool for Kali Linux

KShield is a robust, lightweight, pure Python 3 command-line utility designed for high-fidelity defensive security scanning, local compliance auditing, and threat mapping to the MITRE ATT&CK framework.

Developed specifically for defensive operators and system administrators on Kali Linux, **KShield uses standard library modules only** (no external dependencies) and strictly implements secure, non-destructive assessment procedures.

---

## Key Features

### 1. Attack Surface Scanning
- **Multi-Threaded TCP Port Scanner**: Highly performant concurrent port scans targeting the top 20 ports.
- **Banner Grabbing**: Proactively queries banners and service protocols (supports HTTP, FTP, Telnet active negotiation triggers).
- **SSL/TLS Security Analysis**: Connects via TLS to parse negotiation version, cryptographic ciphers, certificate details, check for weak cipher configurations (<128 bits), outdated protocol levels (SSLv2, SSLv3, TLSv1, TLSv1.1), and certificate expiration.
- **Active HTTP/HTTPS Probing**: Evaluates web servers, extracts `Server` response headers, records status codes, and tags non-standard or developer environments (ports 5000, 8000, 9000, 8080).
- **Extensive Target Syntax**: Supports individual hostnames, IPv4/IPv6 addresses, and CIDR subnet blocks.

### 2. Threat & MITRE ATT&CK Mapping
- **Port-to-Technique Mapping**: Translates raw open ports to highly relevant security exposures (e.g. SSH port 22 mapped to `T1021.004` Remote SSH Services, `T1110` Brute Force, and `T1552.004` Private Keys).
- **Full Tactic Lifecycle Coverage**: Covers a wide array of tactics including *Initial Access*, *Execution*, *Persistence*, *Credential Access*, *Lateral Movement*, *Collection*, *Command and Control*, *Exfiltration*, and *Impact*.
- **Risk Priority Matrix**: Dynamically scores risk by correlating tactic base severity weights with the count of exposures discovered.
- **Actionable Remediation & Detection**: Generates contextual detection recommendations for every mapped technique.
- **Candidate Sigma Rules**: Automatically produces valid, ready-to-import Sigma YAML rule patterns corresponding to each identified technique.

### 3. Local Security Policy Validation
- **Firewall Rule Verification**: Queries active configurations and rules for `iptables`, `ufw`, and `nftables`.
- **System Defender Status**: Queries active states of host defenses such as `fail2ban`, `auditd`, SELinux, and AppArmor.
- **Audit Trail Accessibility**: Confirms path existence and readable/open status of crucial system log stores:
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `/var/log/audit/audit.log`
  - `/var/log/ufw.log`
- **Security Score Calculation**: Evaluates all policy components to generate an overall system policy enforcement percentage score.

### 4. High-Value Outputs & Integrations
- **Ansi Console Dashboard**: Highly legible, structured command-line summary.
- **JSON Export**: Full structured assessment object for automated vulnerability workflows.
- **CSV Export**: Spreadsheet-compatible row outputs detailing targets, exposed ports, and mapped MITRE techniques.
- **Sigma YAML Export**: Automatically packages generated SIEM logging detections into a valid Sigma rule manifest file.

---

## Installation & Requirements

KShield is **zero-dependency** and requires only standard Python 3.x installations.

```bash
# Clone the repository
git clone <repository_url>
cd <repository_folder>

# Mark kshield.py executable
chmod +x kshield.py
```

---

## Command-Line Usage

```
usage: kshield.py [-h] --targets TARGETS [--ports PORTS] [--threads THREADS] [--timeout TIMEOUT]
                  [--validate-policies] [--json JSON] [--csv CSV] [--sigma SIGMA]

KShield - Defensive security analyzer and compliance policy validation tool for Kali Linux.

options:
  -h, --help            show this help message and exit
  --targets TARGETS     IP addresses, hostnames, or CIDR blocks (comma-separated).
  --ports PORTS         Comma-separated ports to scan (Defaults to standard top 20 ports).
  --threads THREADS     Maximum thread execution count (default 10).
  --timeout TIMEOUT     Connection socket timeout duration in seconds (default 2.0).
  --validate-policies   Include local endpoint policy and compliance audit checks.
  --json JSON           Path to export report results in JSON format.
  --csv CSV             Path to export report results in CSV spreadsheet format.
  --sigma SIGMA         Path to export candidate Sigma rules in YAML format.
```

### Examples

**Scan a network CIDR range with standard top ports:**
```bash
./kshield.py --targets 192.168.1.0/24 --threads 16 --timeout 1.5
```

**Perform an attack surface scan and audit local system compliance policies:**
```bash
./kshield.py --targets 127.0.0.1 --validate-policies
```

**Export full outputs to JSON, CSV, and Sigma SIEM configurations:**
```bash
./kshield.py --targets 127.0.0.1 --validate-policies --json report.json --csv report.csv --sigma rules.yaml
```

---

## Defensive Consent Banner
To prevent accidental or malicious usage on unauthorized networks, **KShield prompts for explicit consent** before scanning.

```
================================================================================
                                 SCOPE WARNING
================================================================================
This utility, KShield, is designed specifically for defensive security analysis,
vulnerability identification, and local compliance verification.
Unauthorized scanning of networks/hosts without explicit written permission
is illegal and violates computer fraud laws.
By proceeding, you agree that you are authorized to evaluate the designated targets.
================================================================================

Do you confirm you have authorized access to scan the specified target environment? (yes/no):
```

---

## Running Unit Tests
You can verify the codebase integrity using Python's built-in `unittest` runner:

```bash
python3 -m unittest discover -s .
```

---

## License
Defensive and authorized use only. Strictly governed under cyber security research and compliance regulations.
