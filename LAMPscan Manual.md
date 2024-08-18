# **LAMPscan User Manual**

## **Introduction**

**LAMPscan** is a robust command-line utility designed to perform security assessments of servers running the LAMP stack (Linux, Apache, MySQL/MariaDB, PHP), with special attention to WordPress installations. The tool leverages Nmap for network vulnerability scanning and Nikto for web server vulnerability analysis, making it a comprehensive solution for identifying and addressing potential security issues.

### **Key Features**

- **Automated Nmap Scans**: Executes in-depth network security scans tailored for LAMP and WordPress environments.
- **Nikto Web Vulnerability Scanning**: Identifies web server vulnerabilities using Nikto.
- **OWASP Top Ten Coverage**: Scans align with OWASP Top Ten recommendations, covering common vulnerabilities.
- **CVE Lookup Integration**: Retrieves severity and CVSS scores for identified CVEs from the NVD API.
- **Configurable Settings**: Customizable via the `lampscan.conf` file, allowing users to modify scan behavior and parameters.
- **HTML Report Generation**: Generates detailed HTML reports, including scan summaries, vulnerability information, and environment details.
- **Enhanced Error Handling**: Provides clear feedback and error messages for troubleshooting.
- **Detailed Logging**: Maintains comprehensive logs with timestamps and levels for thorough analysis.

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

### **Configuration**

LAMPscan is highly configurable through the `lampscan.conf` file. This file allows you to specify options for both Nmap and Nikto, ensuring that the scans are tailored to your specific environment and needs.

#### **Default Configuration**

The `lampscan.conf` file is created automatically if it doesn't exist. Below is the default configuration:

```bash
NMAP_OPTIONS="-Pn -sC -A"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*,ssl-enum-ciphers,ssl-cert,http-sql-injection,http-methods,http-auth,http-rfi-spider,http-phpmyadmin-dir-traversal,http-config-backup,http-vhosts,vulners,ssh-auth-methods"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995,5432,1433,1521,389,636,53,445,1194,500,4500"
NIKTO_OPTIONS=""
GENERATE_HTML_REPORT="true"
```

#### **Configuration Options**

- **NMAP_OPTIONS**: Nmap options to control the scan's aggressiveness and scope.
- **NMAP_SCRIPTS**: A list of Nmap scripts to execute, focusing on vulnerability detection.
- **NMAP_SCRIPT_ARGS**: Additional arguments to fine-tune the selected Nmap scripts.
- **NMAP_PORTS**: Ports to be scanned by Nmap.
- **NIKTO_OPTIONS**: Options to customize the behavior of Nikto, focusing on tuning and timeout.
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

---

## **Troubleshooting**

### **Common Issues**

- **Missing Dependencies**: Ensure all required tools are installed.
- **Permission Issues**: Run the script with `sudo` to ensure it has the necessary permissions.
- **Invalid Configuration**: Double-check the `lampscan.conf` file for syntax errors or invalid options.

### **Contact and Support**

For further assistance, please contact the LAMPscan development team at [support@lampscan.com](mailto:support@lampscan.com).

---