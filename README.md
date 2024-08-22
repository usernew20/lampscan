# LAMPscan

## Overview

The **LAMPscan** is a comprehensive security assessment script designed for LAMP stack servers, with a particular focus on WordPress installations and OWASP Top Ten vulnerabilities. This tool automates the process of scanning for open ports, services, and vulnerabilities, delivering a detailed HTML report that includes both scan results and relevant vulnerability information.

### Key Features

- **Automated Nmap and Nikto Scans**: The script conducts thorough scans using Nmap for open ports and services, and Nikto for web server vulnerabilities, covering a wide range of potential issues including those identified by the OWASP Top Ten.
- **IPv6 Awareness**: Automatically detects and adjusts scans based on IPv6 support on the target machine.
- **Configurable Scanning**: Fully configurable via the `lampscan.conf` file, allowing users to adjust Nmap options, scripts, and other parameters to suit their environment.
- **Detailed Logging with Verbose Option**: The script includes a `VERBOSE` logging level, providing comprehensive logs that detail every action taken, including the specific commands executed and their outputs.
- **Professional HTML Reports**: Generates detailed HTML reports that include scan results, service detection results, and vulnerability details, with relevant CVE lookups where applicable.
- **Enhanced Error Handling**: Improved handling of missing commands and configuration issues ensures robust operation and clear error messages.
- **File Ownership and Cleanup**: Ensures that all generated files are owned by the user running the script and that temporary files are properly cleaned up after the scan completes.
- **Parallel Nmap Scanning**: Nmap scans are now organized into meaningful groups (web, auth, database, common, vuln) and run in parallel to enhance performance.
- **Customizable Scan Groups**: Users can define a custom group in the configuration file to add additional scans, ensuring flexibility while maintaining safety.
- **Grouped Nmap Scans**: The script now runs multiple Nmap instances in parallel, grouped into categories like web, auth, database, common, and vuln. Each group has tailored script arguments and ports, improving scanning efficiency.
- **Custom Scan Group**: A dedicated group for custom Nmap scans is available, allowing users to add their own scripts without affecting the predefined groups.


## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/intuitionamiga/lampscan
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

The tool automatically detects whether IPv6 is supported and performs the scans accordingly. The results are saved as both an HTML report and a log file.

### Verbose Logging

To enable detailed logging, run the script with the `-v` option:
```bash
sudo ./lampscan.sh -v <domain_or_ip>
```

This will provide a more granular log output, recording each command executed and the detailed results of each scan.

## Configuration

The script uses a configuration file named `lampscan.conf` to set Nmap options, scripts, and other parameters. If the file does not exist, the script will automatically create a default configuration file.

Example configuration (`lampscan.conf`):
```bash
# Default Nmap options
NMAP_OPTIONS="-Pn -sC -A"

# Group-specific Nmap scripts
WEB_NMAP_SCRIPTS="http-enum,http-vuln*,http-wordpress*,http-phpmyadmin-dir-traversal,http-config-backup,http-vhosts"
AUTH_NMAP_SCRIPTS="ssh*,ftp*,auth*,ssh-auth-methods"
DATABASE_NMAP_SCRIPTS="*sql*,mysql*,http-sql-injection"
COMMON_NMAP_SCRIPTS="*apache*,dns*,smb*,firewall*,ssl-enum-ciphers,ssl-cert"
VULN_NMAP_SCRIPTS="vuln*,vulners"

# Group-specific Nmap script arguments
WEB_NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10"
AUTH_NMAP_SCRIPT_ARGS=""
DATABASE_NMAP_SCRIPT_ARGS="ftp-anon.maxlist=10"
COMMON_NMAP_SCRIPT_ARGS=""
VULN_NMAP_SCRIPT_ARGS=""

# Custom group scripts (user-defined)
CUSTOM_NMAP_SCRIPTS=""
CUSTOM_NMAP_SCRIPT_ARGS=""

# Ports to scan
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995,5432,1433,1521,389,636,53,445,1194,500,4500"

# Nikto scan options
NIKTO_OPTIONS="-Tuning 1 -ssl"

# Report generation
GENERATE_HTML_REPORT="true"

# Log level
LOG_LEVEL="INFO"  # Change this to "VERBOSE" for more detailed logs

```

### Nikto Integration

In addition to Nmap, **LAMPscan** includes Nikto for web server scanning, which checks for various vulnerabilities, outdated software, and configuration issues.

To customize Nikto's behavior, modify the `NIKTO_OPTIONS` in the `lampscan.conf` file.

#### Running the Scan

```bash
sudo ./lampscan.sh <domain_or_ip>
```

Example:
```bash
sudo ./lampscan.sh example.com
```

Both the Nmap and Nikto scans are run sequentially, ensuring that each scan completes before the next begins. The HTML report generated includes a dedicated section for Nikto results, alongside the detailed Nmap findings.

## Report Output

The generated HTML report contains:
- **Nmap Scan Results**: Details about open ports, running services, and potential vulnerabilities.
- **Nikto Scan Results**: Information about web server vulnerabilities and other potential security issues.
- **Vulnerability Information**: Relevant CVEs and their details based on the scan results.
- **Grouped Scan Results**: The HTML report now includes detailed results from each scan group, providing a comprehensive overview of the security assessment.


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.