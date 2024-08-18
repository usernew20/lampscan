## Introduction

**LAMPscan** is a comprehensive command-line utility designed to assess and bolster the security of servers running the LAMP stack (Linux, Apache, MySQL/MariaDB, PHP), with a particular focus on (but not limited to) WordPress installations. Leveraging Nmap, the tool automates thorough security scans, checking for open ports, detecting running services, and identifying potential vulnerabilities, including those from the OWASP Top Ten list.

### Key Features

- **Automated Nmap Scans**: Automates comprehensive security scans using Nmap, tailored for LAMP/WordPress environments.
- **OWASP Top Ten Coverage**: Expanded script and port coverage to detect vulnerabilities in alignment with OWASP Top Ten recommendations.
- **CVE Lookup Integration**: Automatically retrieves severity and CVSS scores for identified CVEs from the NVD API.
- **Configurable Settings**: Customizable via the `lampscan.conf` file, with defaults targeting common vulnerabilities.
- **HTML Report Generation**: Detailed HTML reports include:
    - **Summary of Findings**: Overview of open, closed, and filtered ports.
    - **Detailed Vulnerability Information**: Information on detected vulnerabilities, severity ratings, CVSS scores, and CVE details.
    - **Scan Environment Details**: Information on Nmap version, scripts used, and scanning host.
- **Enhanced Error Handling**: Improved feedback and error messages for troubleshooting.
- **Detailed Logging**: Consolidated logs with timestamps and levels for easier analysis.

---

## Configuration

### `lampscan.conf`

The `lampscan.conf` file is the heart of the tool's configuration. It allows users to customize the scan options, scripts, arguments, and ports.

#### Updated Configuration Options

- **NMAP_OPTIONS**: Enhanced with aggressive scanning options (`-Pn -sC -A`).
- **NMAP_SCRIPTS**: Expanded to cover a broader range of vulnerabilities, including OWASP Top Ten risks.
- **NMAP_PORTS**: Extended to include a wider range of ports relevant to common services and databases.

#### Example Configuration

```bash
NMAP_OPTIONS="-Pn -sC -A"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*,ssl-enum-ciphers,ssl-cert,http-sql-injection,http-methods,http-auth,http-rfi-spider,http-phpmyadmin-dir-traversal,http-config-backup,http-vhosts,vulners,ssh-auth-methods"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995,5432,1433,1521,389,636,53,445,1194,500,4500"
GENERATE_HTML_REPORT="true"
```

---

## Summary of Changes

1. **Enhanced OWASP Top Ten Coverage**: Added additional Nmap scripts and ports to increase detection of vulnerabilities in alignment with OWASP Top Ten.
2. **CVE Lookup Integration**: Introduced functionality to fetch severity and CVSS scores for CVEs from the NVD API.
3. **Script and Port Expansion**: Included scripts and ports to cover a broader range of services and vulnerabilities.
4. **Improved Configuration and Error Handling**: Default configurations are now more robust, with improved error handling and logging.

---