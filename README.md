
# LAMP/WordPress Server Nmap Scan Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Version](https://img.shields.io-badge/version-2.0-green.svg)
![Nmap](https://img.shields.io/badge/Nmap-7.94+-orange.svg)

## Overview

The **LAMP/WordPress Server Nmap Scan Tool** is a Bash script designed to perform a comprehensive security assessment on servers running the LAMP stack (Linux, Apache, MySQL/MariaDB, PHP) with a particular focus on WordPress instances. Leveraging the power of Nmap, this tool automates the process of scanning for open ports, detecting services, and identifying potential vulnerabilities.

## Features

- **Configurable Settings**: Now supports loading configuration settings from an external `lampscan.conf` file, making it easier to adjust scan parameters without modifying the script.
- **Enhanced Logging**: Consolidated and improved logging with timestamps and log levels, saved in a single log file named `<target>_<date>_<time>_scan.log`.
- **Streamlined Header Management**: Centralized and unified header printing to reduce code duplication and improve maintainability.
- **Automated Nmap Scanning**: The script automates Nmap scans, including service enumeration, common vulnerability detection, and WordPress-specific checks.
- **IPv6 Awareness**: Detects IPv6 support on the host machine and adjusts the scanning process accordingly, with clear logging if IPv6 is not supported.
- **Comprehensive Port Scanning**: Scans a wide range of ports typically associated with LAMP stack services and WordPress installations.
- **Evasion Techniques**: Randomizes host scan order and uses decoys to reduce detection likelihood by intrusion detection systems (IDS).
- **Improved File Naming**: The scan results are now saved as `<target>_<date>_<time>_scan_results.ipv4` and `<target>_<date>_<time>_scan_results.ipv6` for better clarity and organization.

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

- **Enhanced Error Handling**: Improve feedback and error reporting for edge cases.
- **Integration**: Consider adding support for integrating scan results with other tools like Metasploit.
- **Expanded Script Library**: Incorporate additional Nmap scripts for emerging threats and configurations.

## Contributing

Contributions are welcome! Please fork the repository and create a pull request with your changes. Ensure that your code adheres to the existing style and passes any tests before submitting.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For issues, questions, or suggestions, please open an issue in the repository.

## Acknowledgments

- Special thanks to the Nmap team for creating such a powerful and versatile tool.
- Thanks to all contributors and the open-source community for their support and inspiration.
