# **LAMPscan User Manual**

## **Introduction**

**LAMPscan** is a robust command-line utility designed to perform security assessments of servers running the LAMP stack (Linux, Apache, MySQL/MariaDB, PHP), with special attention to WordPress installations. The tool leverages Nmap for network vulnerability scanning and Nikto for web server vulnerability analysis, making it a comprehensive solution for identifying and addressing potential security issues.

### **Key Features**

- **Automated Nmap and Nikto Scans**: Conducts thorough scans using Nmap for open ports and services, and Nikto for web server vulnerabilities, covering a wide range of potential issues, including those identified by the OWASP Top Ten.
- **IPv6 Awareness**: Automatically detects and adjusts scans based on IPv6 support on the target machine.
- **Configurable Scanning**: Fully configurable via the `lampscan.conf` file, allowing users to adjust Nmap options, scripts, and other parameters to suit their environment.
- **Parallel Nmap Scanning**: The script supports running Nmap scans in parallel, grouped into categories like web, auth, database, common, and vuln, enhancing the efficiency of the scanning process.
- **Customizable Scan Groups**: A "custom" group is available for user-defined scans, allowing additional Nmap scripts to be run safely without affecting the predefined groups.
- **Detailed Logging with Verbose Option**: Includes a `VERBOSE` logging level, providing comprehensive logs that detail every action taken, including the specific commands executed and their outputs.
- **Professional HTML Reports**: Generates detailed HTML reports that include scan results, service detection results, and vulnerability details, with relevant CVE lookups where applicable.
- **Enhanced Error Handling**: Improved handling of missing commands and configuration issues ensures robust operation and clear error messages.
- **File Ownership and Cleanup**: Ensures that all generated files are owned by the user running the script and that temporary files are properly cleaned up after the scan completes.

---

## **Installation**

### **Prerequisites**

Before running LAMPscan, ensure the following tools are installed on your system:

- **Nmap**: The core tool for network scanning.
- **Nikto**: For web server vulnerability analysis.
- **curl**: Used for CVE lookup and other web-based tasks.
- **jq**: A lightweight command-line JSON processor, used for parsing CVE data.
- **dig**: A DNS lookup utility to resolve IP addresses.
- **ping6**: Used to check IPv6 support.

### **Installation Steps**

1. **Clone the Repository**: Clone the LAMPscan repository from your version control system.

   ```bash
   git clone <repository-url>
   cd lampscan
   ```

2. **Set Permissions**: Ensure the main script has executable permissions.

   ```bash
   chmod +x lampscan.sh
   ```

3. **Install Dependencies**: Install the required dependencies using your package manager.

   ```bash
   sudo apt-get install nmap nikto curl jq dnsutils iputils-ping
   ```

4. **Run LAMPscan**: Execute the script with the target domain or IP address.

   ```bash
   sudo ./lampscan.sh <domain_or_ip>
   ```

---

## **Usage**

### **Command Syntax**

```bash
sudo ./lampscan.sh <domain_or_ip>
```

- `<domain_or_ip>`: The target domain name or IP address for scanning.

### **Verbose Logging**

To enable detailed logging, run the script with the `-v` option:

```bash
sudo ./lampscan.sh -v <domain_or_ip>
```

This will provide a more granular log output, recording each command executed and the detailed results of each scan.

### **Configuration**

LAMPscan is highly configurable through the `lampscan.conf` file. This file allows you to specify options for both Nmap and Nikto, ensuring that the scans are tailored to your specific environment and needs.

#### **Default Configuration**

The `lampscan.conf` file is created automatically if it doesn't exist. Below is the default configuration:

```bash
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

#### **Configuration Options**

- **NMAP_OPTIONS**: Nmap options to control the scan's aggressiveness and scope.
- **Group-Specific Nmap Scripts**: Scripts organized into groups for web, auth, database, common, and vuln, each with tailored script arguments.
- **Custom Group**: Users can define custom scripts in the `CUSTOM_NMAP_SCRIPTS` variable.
- **NMAP_PORTS**: Ports to be scanned by Nmap.
- **NIKTO_OPTIONS**: Options to customize the behavior of Nikto.
- **GENERATE_HTML_REPORT**: Set to `true` to generate an HTML report after the scan.

### **Running a Scan**

1. **Basic Scan**: To run a basic scan against a target, execute the script with the target's domain or IP.

   ```bash
   sudo ./lampscan.sh example.com
   ```

2. **Using a Custom Configuration**: Modify the `lampscan.conf` file to customize the scan parameters.

3. **Viewing the Results**: After the scan, LAMPscan generates a detailed HTML report summarizing the findings, vulnerabilities, and scan environment details. The report is saved in the same directory as the script.

---

## **Output**

### **HTML Report**

The HTML report provides a detailed overview of the scan results, including:

- **Summary of Findings**: Overview of scanned ports and their status.
- **Grouped Scan Results**: The HTML report now includes detailed results from each scan group (web, auth, database, common, vuln), providing a comprehensive overview of the security assessment.
- **Detailed Vulnerability Information**: Lists vulnerabilities detected by Nmap and Nikto, along with CVE details.
- **Nikto Scan Results**: Specific vulnerabilities identified by Nikto during the web server scan.
- **Scan Environment Details**: Information on the Nmap and Nikto versions, scripts used, and scanning host environment.

### **Logs**

All scan activities are logged in a log file, which is useful for troubleshooting and audit purposes. The log file includes timestamps and log levels to help trace the scan's execution flow.

---

## **Advanced Usage**

### **Customizing Nmap and Nikto Scans**

Users can modify the `lampscan.conf` file to adjust the scanning behavior. For instance, you can change the Nmap options to include more aggressive scanning or add specific Nikto plugins to focus on particular vulnerabilities.

### **Integrating with CI/CD Pipelines**

LAMPscan can be integrated into CI/CD pipelines to automate security checks during the development process. By running LAMPscan as part of your build process, you can ensure that vulnerabilities are identified and addressed before deployment.

### **Integrating Custom Scans**

Modify the `CUSTOM_NMAP_SCRIPTS` and `CUSTOM_NMAP_SCRIPT_ARGS` in `lampscan.conf` to integrate your own Nmap scripts into the scan process. This allows for flexibility in addressing specific security concerns.

---

## **Troubleshooting**

### **Common Issues**

- **Missing Dependencies**: Ensure all required tools are installed.
- **Permission Issues**: Run the script with `sudo` to ensure it has the necessary permissions.
- **Invalid Configuration**: Double-check the `lampscan.conf` file for syntax errors or invalid options.
- **Custom Group Issues**: If custom scripts in the `CUSTOM_NMAP_SCRIPTS` variable are not found or incorrectly defined, the script will issue a warning. Ensure that the paths and script names are correct.

### **Contact and Support**

For further assistance, please raise an issue on the LAMPscan repository or contact the maintainers directly.

---