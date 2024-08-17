
# LAMP/WordPress Server Nmap Scan Tool - End User Documentation

---

## Table of Contents

1. [Introduction](#introduction)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Understanding the Output](#understanding-the-output)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)
9. [FAQs](#faqs)
10. [Support](#support)

---

## Introduction

The **LAMP/WordPress Server Nmap Scan Tool** is a command-line utility designed to assess the security of servers running the LAMP stack (Linux, Apache, MySQL/MariaDB, PHP), with a focus on WordPress installations. By leveraging Nmap, the tool automates the process of scanning for open ports, identifying running services, and detecting potential vulnerabilities.

### Key Features

- **Automated Nmap Scans**: The tool automates Nmap commands to perform comprehensive security scans.
- **IPv6 Awareness**: Automatically detects and adjusts scans based on IPv6 support.
- **Configurable Settings**: Allows customization through the `lampscan.conf` file.
- **HTML Report Generation**: Generates detailed HTML reports with:
  - **Summary of Findings**: Overview of open, closed, and filtered ports.
  - **Detailed Vulnerability Information**: Links to CVE entries and mitigation suggestions.
  - **Scan Environment Details**: Information on Nmap version, scripts used, and scanning host.
- **Enhanced Error Handling**: Improved error messages and feedback for troubleshooting.
- **Detailed Logging**: Consolidated logging with timestamps and log levels for easy analysis.

---

## System Requirements

- **Operating System**: Linux (Any distribution with Bash)
- **Bash**: Version 4.0 or higher
- **Nmap**: Version 7.94 or higher

---

## Installation

### Step 1: Download and Install Nmap

Ensure Nmap is installed on your system.

**For Debian/Ubuntu:**

```bash
sudo apt-get install nmap
```

**For macOS (using Homebrew):**

```bash
brew install nmap
```

### Step 2: Download the LAMP/WordPress Server Nmap Scan Tool

Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/lampscan.git
cd lampscan
```

### Step 3: Make the Script Executable

Run the following command to make the script executable:

```bash
chmod +x lampscan.sh
```

---

## Usage

### Basic Usage

To run the scan, use the following command:

```bash
sudo ./lampscan.sh <domain_or_ip>
```

### Example

```bash
sudo ./lampscan.sh example.com
```

### Output Files

1. **Console Output**: Displays real-time progress, including open, filtered, or closed ports.
2. **Log File**: Saved as `<target>_<date>_<time>_scan.log`. It contains detailed logs of the scan.
3. **HTML Report**: Generated as `<target>_<date>_<time>_scan_report.html` containing:
   - **Summary of Findings**: Overview of open, closed, and filtered ports.
   - **Detailed Vulnerability Information**: Links to relevant CVE entries and suggested mitigations.
   - **Scan Environment Details**: Nmap version, scripts used, and scanning host information.

---

## Understanding the Output

### Console Output

During the scan, you’ll see various messages indicating the progress and results. For example:

- **Status Messages**: Indicate the start of IPv4 or IPv6 scans, check for IPv6 support, etc.
- **Port States**: Shows open, filtered, or closed ports for each scanned IP.

### Log File

The log file captures all the console output and additional details such as:

- Timestamps for each operation.
- Status, warning, and error messages.
- Any issues encountered during the scan.

### HTML Report

The HTML report is a comprehensive document that includes:

- **Summary of Findings**: A high-level overview of the scan results.
- **Detailed Vulnerability Information**: Detailed descriptions of detected vulnerabilities with links to CVE entries and suggested mitigations.
- **Scan Environment Details**: Information about the Nmap version, options used, scripts executed, and the scanning host.

---

## Configuration

### `lampscan.conf`

The tool uses a configuration file (`lampscan.conf`) to manage its settings. If the file is missing, the tool will create it with default settings.

#### Configuration Options

- **NMAP_OPTIONS**: Default Nmap options (`-Pn -sC`)
- **NMAP_SCRIPTS**: List of Nmap scripts to run during the scan.
- **NMAP_SCRIPT_ARGS**: Arguments passed to the Nmap scripts.
- **NMAP_PORTS**: List of ports to scan.

#### Example Configuration

```bash
NMAP_OPTIONS="-Pn -sC"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10,http-slowloris.runforever=true"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995"
GENERATE_HTML_REPORT="true"
```

---

## Troubleshooting

### Common Issues

1. **Permission Denied**:
   - Ensure you run the script with `sudo` as it requires root privileges.
   
2. **Nmap Command Not Found**:
   - Make sure Nmap is installed and accessible from your command line.

3. **Invalid Domain or IP**:
   - Double-check the domain or IP address you provided. The tool requires a valid input.

4. **No Results**:
   - The target may be behind a firewall or filtering tool that blocks the scan. Adjust Nmap options in the `lampscan.conf` file if necessary.

---

## Best Practices

- **Run Regularly**: Use this tool regularly as part of your security routine to identify vulnerabilities early.
- **Custom Configurations**: Adjust the `lampscan.conf` settings to fit the specific needs of your environment.
- **Review Logs**: Always review the log file after a scan for any warnings or errors.

---

## FAQs

### 1. **Can this tool run on Windows?**
   - No, this tool is designed for Linux environments. However, it can be run on WSL (Windows Subsystem for Linux) on a Windows machine.

### 2. **What does it mean if all ports are filtered?**
   - This typically indicates that a firewall is blocking the scan. You may need to adjust your scanning strategy.

### 3. **Can I add custom Nmap scripts?**
   - Yes, you can edit the `lampscan.conf` file to include additional Nmap scripts that suit your needs.

---

## Support

For any issues, questions, or suggestions, please open an issue in the [GitHub repository](https://github.com/yourusername/lampscan/issues) or contact the maintainer directly.

---

This documentation is designed to provide you with all the necessary information to effectively use the LAMP/WordPress Server Nmap Scan Tool. Regularly refer to this document to ensure you are making the most of the tool’s capabilities.
