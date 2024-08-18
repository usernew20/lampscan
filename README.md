# LAMPscan

## Overview

The **LAMPscan** is a comprehensive security assessment script designed for LAMP stack servers, with a particular focus on WordPress installations and the OWASP Top Ten vulnerabilities. This tool automates the process of scanning for open ports, services, and vulnerabilities, delivering a detailed HTML report that includes both scan results and relevant vulnerability information.

## Features

- **Automated Nmap Scans**: The script conducts thorough scans using Nmap, including service detection, vulnerability detection, and various other checks.
- **OWASP Top Ten Coverage**: Updated configuration to include additional scripts and ports to cover most of the OWASP Top Ten vulnerabilities.
- **IPv6 Awareness**: Automatically detects and adjusts scans based on IPv6 support.
- **Professional HTML Reports**: Generates detailed HTML reports that include scan results, service detection results, and vulnerability details, including CVE lookups where applicable.
- **Configurable Scanning**: The script is fully configurable via the `lampscan.conf` file, allowing users to adjust Nmap options, scripts, and other parameters.
- **Enhanced Error Handling**: Improved error handling for missing commands and other edge cases.
- **File Ownership**: Ensures that all generated files are owned by the user running the script.
- **Nikto Web Server Scanning**: Integrates Nikto scanning for web server vulnerabilities and includes the results in the HTML report.

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/your-repository/lampscan.git
   ```

2. Navigate to the directory:
   ```bash
   cd lampscan
   ```

3. Ensure the script has executable permissions:
   ```bash
   chmod +x lampscan.sh
   ```

## Usage

Run the script with root privileges, providing a domain or IP address as the argument:
```bash
sudo ./lampscan.sh <domain_or_ip>
```

Example:
```bash
sudo ./lampscan.sh example.com
```

The tool will automatically detect whether IPv6 is supported and perform the scans accordingly. The results will be saved as an HTML report and a log file.

## Configuration

The script uses a configuration file named `lampscan.conf` to set Nmap options, scripts, and other parameters. If the file does not exist, the script will create a default configuration file.

Example configuration (`lampscan.conf`):
```bash
NMAP_OPTIONS="-Pn -sC -A"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*,ssl-enum-ciphers,ssl-cert,http-sql-injection,http-methods,http-auth,http-rfi-spider,http-phpmyadmin-dir-traversal,http-config-backup,http-vhosts,vulners,ssh-auth-methods"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995,5432,1433,1521,389,636,53,445,1194,500,4500"
NIKTO_OPTIONS="-Tuning 1 2 3 4 7 -timeout 5"  # Add your custom Nikto options here
GENERATE_HTML_REPORT="true"
```

### Nikto Scanning Integration

In addition to Nmap, **LAMPscan** now supports Nikto web server scanning. Nikto is a comprehensive web server scanner that performs checks for various dangerous files, outdated server software, and other issues.

#### Configuration

The script includes Nikto options within the `lampscan.conf` configuration file. You can customize the Nikto scan by modifying the `NIKTO_OPTIONS` parameter in the configuration file.

Example configuration (`lampscan.conf`):
```bash
NMAP_OPTIONS="-Pn -sC -A"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*,ssl-enum-ciphers,ssl-cert,http-sql-injection,http-methods,http-auth,http-rfi-spider,http-phpmyadmin-dir-traversal,http-config-backup,http-vhosts,vulners,ssh-auth-methods"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995,5432,1433,1521,389,636,53,445,1194,500,4500"
NIKTO_OPTIONS="-Tuning 1 2 3 4 7 -timeout 5"  # Add your custom Nikto options here
GENERATE_HTML_REPORT="true"
```

#### Running the Scan

Run the script as usual, and the Nikto scan will be executed alongside the Nmap scan. The results of the Nikto scan will be included in the HTML report under a dedicated section.

```bash
sudo ./lampscan.sh <domain_or_ip>
```

Example:
```bash
sudo ./lampscan.sh example.com
```

#### Output

The HTML report will include a section for Nikto scan results, alongside the Nmap scan results. This section will list vulnerabilities and other issues identified by Nikto.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.