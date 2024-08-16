
# LAMP/WordPress Server Nmap Scan Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io-badge/version-2.1-green.svg)
![Nmap](https://img.shields.io/badge/Nmap-7.94+-orange.svg)

## Overview

The **LAMP/WordPress Server Nmap Scan Tool** is a Bash script designed to perform a comprehensive security assessment on servers running the LAMP stack (Linux, Apache, MySQL/MariaDB, PHP) with a particular focus on WordPress instances. Leveraging the power of Nmap, this tool automates the process of scanning for open ports, detecting services, and identifying potential vulnerabilities.

## Features

- **Configurable Settings**: Supports loading configuration settings from an external `lampscan.conf` file, making it easier to adjust scan parameters without modifying the script.
- **Enhanced Logging**: Consolidated and improved logging with timestamps and log levels, saved in a single log file named `<target>_<date>_<time>_scan.log`.
- **Streamlined Header Management**: Centralized and unified header printing to reduce code duplication and improve maintainability.
- **Automated Nmap Scanning**: The script automates Nmap scans, including service enumeration, common vulnerability detection, and WordPress-specific checks.
- **IPv6 Awareness**: Detects IPv6 support on the host machine and adjusts the scanning process accordingly, with clear logging if IPv6 is not supported.
- **Comprehensive Port Scanning**: Scans a wide range of ports typically associated with LAMP stack services and WordPress installations.
- **Evasion Techniques**: Randomizes host scan order and uses decoys to reduce detection likelihood by intrusion detection systems (IDS).
- **Expanded Script Library**: Includes additional Nmap scripts to detect DNS, SMB, and firewall-related vulnerabilities.
- **Improved Error Handling**: Checks for required commands and handles IP resolution failures gracefully with detailed error messages.

## Scans Performed

### IPv4 Scans

The script performs the following scans for IPv4:

- **Port Scanning**: Scans ports 80, 443, 22, 21, 3306, 8080, 8443, 25, 110, 143, 993, 995.
- **Nmap Scripts**: 
  - `http-enum`
  - `http-vuln*`
  - `*sql*`
  - `*php*`
  - `http-wordpress*`
  - `vuln*`
  - `auth*`
  - `*apache*`
  - `*ssh*`
  - `*ftp*`
  - `dns*`
  - `smb*`
  - `firewall*`
- **Script Arguments**:
  - `http-wordpress-enum.threads=10`
  - `http-wordpress-brute.threads=10`
  - `ftp-anon.maxlist=10`
  - `http-slowloris.runforever=true`

### IPv6 Scans

The script performs the following scans for IPv6 (if supported and configured):

- **Port Scanning**: Scans ports 80, 443, 22, 21, 3306, 8080, 8443, 25, 110, 143, 993, 995.
- **Nmap Scripts**: 
  - `http-enum`
  - `http-vuln*`
  - `*sql*`
  - `*php*`
  - `http-wordpress*`
  - `vuln*`
  - `auth*`
  - `*apache*`
  - `*ssh*`
  - `*ftp*`
  - `dns*`
  - `smb*`
  - `firewall*`
- **Script Arguments**:
  - `http-wordpress-enum.threads=10`
  - `http-wordpress-brute.threads=10`
  - `ftp-anon.maxlist=10`
  - `http-slowloris.runforever=true`

## Installation

### Prerequisites

- **Nmap 7.94+**: Ensure you have Nmap version 7.94 or later installed on your system.
- **Bash**: This script is designed to run in a Bash shell.

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/lampscan.git
   cd lampscan
   ```

2. **Make the script executable:**

   ```bash
   chmod +x lampscan.sh
   ```

3. **Run the script:**

   ```bash
   sudo ./lampscan.sh <domain_or_ip>
   ```

## Usage

```bash
sudo ./lampscan.sh <domain_or_ip>
```

### Example

```bash
sudo ./lampscan.sh example.com
```

### Output

- **Console Output**: Displays the progress of the scan, including any open, filtered, or closed ports, and key findings.
- **Log File**: Generates a log file named `<target>_<date>_<time>_scan.log` containing detailed logs of the scan.
- **Result Files**: Scan results are saved in files named `<target>_<date>_<time>_scan_results.ipv4` and `<target>_<date>_<time>_scan_results.ipv6`, depending on the IP version scanned.

### Options

- The script automatically detects IPv6 support and adjusts the scan accordingly.
- If IPv6 is not supported, it will skip the IPv6 scan and notify the user.

## Roadmap

- **Further Enhancements**: Continue improving error handling and expanding the script library with additional Nmap scripts for new and emerging threats.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. Ensure that your code adheres to the existing style and passes any tests before submitting.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For issues, questions, or suggestions, please open an issue in the repository.

## Acknowledgments

- Special thanks to the Nmap team for creating such a powerful and versatile tool.
- Thanks to all contributors and the open-source community for their support and inspiration.
