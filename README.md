# LAMP/WordPress Server Nmap Scan

## Overview

The **LAMP/WordPress Server Nmap Scan Tool** is a comprehensive security assessment script designed for LAMP stack servers, with a particular focus on WordPress installations. This tool automates the process of scanning for open ports, services, and vulnerabilities, delivering a detailed HTML report that includes both scan results and relevant vulnerability information.

## Features

- **Automated Nmap Scans**: The script conducts thorough scans using Nmap, including service detection, vulnerability detection, and various other checks.
- **IPv6 Awareness**: Automatically detects and adjusts scans based on IPv6 support.
- **Professional HTML Reports**: Generates detailed HTML reports that include scan results, service detection results, and vulnerability details, including CVE lookups where applicable.
- **Configurable Scanning**: The script is fully configurable via the `lampscan.conf` file, allowing users to adjust Nmap options, scripts, and other parameters.
- **Enhanced Error Handling**: Improved error handling for missing commands and other edge cases.
- **File Ownership**: Ensures that all generated files are owned by the user running the script.

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
NMAP_OPTIONS="-Pn -sC"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10,http-slowloris.runforever=true"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995"
GENERATE_HTML_REPORT="true"
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

