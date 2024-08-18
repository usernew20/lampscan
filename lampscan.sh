#!/bin/bash

# ANSI color codes
BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[0m"
RESET="\033[0m"

# Default log level (INFO)
LOG_LEVEL="INFO"

# Header text
HEADER_TEXT="================================================================
LAMP/WordPress Server Nmap Scan (c) 2024 Zayn Otley
================================================================"

# Function to print headers to console and optionally to the log file
print_header() {
    if [ "$1" != "log" ]; then
        echo -e "${BOLD}${CYAN}$HEADER_TEXT${RESET}"
    fi

    if [ "$1" = "log" ] && [ -n "$LOG_FILE" ]; then
        echo "$HEADER_TEXT" >> "$LOG_FILE"
    fi
}

# Function to log messages
log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    if [ "$level" = "ERROR" ]; then
        echo -e "${RED}$message${RESET}"
        if [ -n "$LOG_FILE" ]; then echo "[$timestamp] ERROR: $message" >> "$LOG_FILE"; fi
    elif [ "$level" = "WARNING" ]; then
        echo -e "${YELLOW}$message${RESET}"
        if [ -n "$LOG_FILE" ]; then echo "[$timestamp] WARNING: $message" >> "$LOG_FILE"; fi
    elif [ "$level" = "INFO" ]; then
        if [ "$LOG_LEVEL" = "INFO" ]; then
            echo -e "${GREEN}$message${RESET}"
            if [ -n "$LOG_FILE" ]; then echo "[$timestamp] INFO: $message" >> "$LOG_FILE"; fi
        fi
    fi
}

# Function to print status messages
print_status() {
    log_message "INFO" "$1"
}

# Function to print warnings
print_warning() {
    log_message "WARNING" "$1"
}

# Function to print errors
print_error() {
    log_message "ERROR" "$1"
}

# Function to load configuration file
load_config() {
    local config_file="lampscan.conf"
    if [ -f "$config_file" ]; then
        source "$config_file"
    else
        print_warning "Configuration file lampscan.conf not found. Creating a default configuration."
        create_default_config
    fi
}

# Function to create a default configuration file
create_default_config() {
    cat <<EOL > lampscan.conf
NMAP_OPTIONS="-Pn -sC -A"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*,ssl-enum-ciphers,ssl-cert,http-sql-injection,http-methods,http-auth,http-rfi-spider,http-phpmyadmin-dir-traversal,http-config-backup,http-vhosts,vulners,ssh-auth-methods"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995,5432,1433,1521,389,636,53,445,1194,500,4500"
NIKTO_OPTIONS=""
GENERATE_HTML_REPORT="true"
EOL
    print_status "Default configuration file created at lampscan.conf"

    # Add a small delay to ensure the file is fully written and recognized
    sleep 1

    # Source the configuration file again after creation
    source lampscan.conf
}

# Enhanced error handling for missing required commands
check_required_commands() {
    local cmds=("nmap" "dig" "ping6" "jq" "curl" "nikto")
    for cmd in "${cmds[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            print_error "$cmd could not be found. Please install it and try again."
            exit 1
        fi
    done
}

# Function to look up CVE details from the NVD API
lookup_cve_details() {
    local cve_id="$1"
    local api_url="https://services.nvd.nist.gov/rest/json/cve/1.0/$cve_id"

    # Fetch CVE details from the NVD API
    local response=$(curl -s "$api_url")

    # Extract severity and CVSS score using jq
    local severity=$(echo "$response" | jq -r '.result.CVE_Items[0].impact.baseMetricV3.cvssV3.baseSeverity // "N/A"')
    local cvss_score=$(echo "$response" | jq -r '.result.CVE_Items[0].impact.baseMetricV3.cvssV3.baseScore // "N/A"')

    # Return the details
    echo "$severity,$cvss_score"
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root."
    exit 1
fi

# Check if the user provided an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <domain_or_ip>"
    exit 1
fi

TARGET="$1"

# Function to validate the target domain, IPv4, or IPv6 address
validate_target() {
    local target="$1"

    # Regex for valid IPv4 address
    local ipv4_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"

    # Regex for valid IPv6 address
    local ipv6_regex="^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$|^::([0-9a-fA-F]{1,4}:){0,6}([0-9a-fA-F]{1,4})$|^([0-9a-fA-F]{1,4}:){1,6}:([0-9a-fA-F]{1,4})$"

    # Regex for valid domain name (simple check)
    local domain_regex="^([a-zA-Z0-9](-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"

    # Check if the target is a valid IPv4 address
    if [[ $target =~ $ipv4_regex ]]; then
        return 0
    # Check if the target is a valid IPv6 address
    elif [[ $target =~ $ipv6_regex ]]; then
        return 0
    # Check if the target is a valid domain name
    elif [[ $target =~ $domain_regex ]]; then
        return 0
    else
        print_error "Invalid target: $target. Please provide a valid domain name, IPv4, or IPv6 address."
        exit 1
    fi
}

# Validate the target input
validate_target "$TARGET"

# Load the configuration file
load_config

# Check required commands
check_required_commands

# Function to check if input is an IP address
is_ip() {
    if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

# Spinner function
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep "$pid")" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\r"
    done
    printf "    \r" # clear spinner after process is done
}

# Get the current date and time for the suffix
DATE_TIME=$(date +"%Y%m%d_%H%M%S")

# Output file name based on target and current date/time
LOG_FILE="${TARGET}_${DATE_TIME}_scan.log"
HTML_REPORT_FILE="${TARGET}_${DATE_TIME}_scan_report.html"
TEMP_OUTPUT_FILE="${TARGET}_${DATE_TIME}_temp_output.txt"
NIKTO_OUTPUT_FILE="${TARGET}_${DATE_TIME}_nikto_output.txt"

# Print the header to console
print_header

# Print the header to the log file only
print_header "log"

# Notify user that IPv6 support is being checked
print_status "Checking for IPv6 support on this machine..."

# Detect if IPv6 is supported on the machine
if ! ping6 -c 1 ::1 &> /dev/null; then
    IPV6_SUPPORTED=false
    print_warning "IPv6 is not supported on this machine."
else
    IPV6_SUPPORTED=true
fi

# Resolve the IP addresses of the target if it's not an IP
if is_ip "$TARGET"; then
    ipv4="$TARGET"
else
    ipv4=$(dig +short A "$TARGET")
    ipv6=$(dig +short AAAA "$TARGET")

    if [ -z "$ipv4" ]; then
        print_error "Failed to resolve IPv4 address for $TARGET."
        exit 1
    fi

    if [ -z "$ipv6" ]; then
        print_warning "Failed to resolve IPv6 address for $TARGET."
    fi
fi

# Function to run an IPv4 scan using configuration values
run_scan_ipv4() {
    print_status "Starting IPv4 scan on $1..."
    nmap $NMAP_OPTIONS \
        --script "$NMAP_SCRIPTS" \
        --script-args="$NMAP_SCRIPT_ARGS" \
        -p "$NMAP_PORTS" "$1" --min-rate=100 --randomize-hosts -oN "$TEMP_OUTPUT_FILE" -vv &
    spinner
}

# Function to run an IPv6 scan using configuration values
run_scan_ipv6() {
    print_status "Starting IPv6 scan on $1..."
    nmap $NMAP_OPTIONS -6 \
        --script "$NMAP_SCRIPTS" \
        --script-args="$NMAP_SCRIPT_ARGS" \
        -p "$NMAP_PORTS" "$1" --min-rate=100 --randomize-hosts -oN "$TEMP_OUTPUT_FILE" -vv &
    spinner
}

# Function to run a Nikto scan
run_nikto_scan() {
    local target_ip="$1"
    print_status "Starting Nikto scan on $target_ip..."
    nikto -h "$target_ip" "$NIKTO_OPTIONS" -output "$NIKTO_OUTPUT_FILE" &
    spinner
}


# Run the scan on IPv4 and save to temp file
run_scan_ipv4 "$ipv4" &

# Run the scan on IPv6 if available and supported and save to temp file
if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
    run_scan_ipv6 "$ipv6" &
elif [ "$IPV6_SUPPORTED" = false ]; then
    print_warning "Skipping IPv6 scan because IPv6 is not supported on this machine."
elif [ -z "$ipv6" ]; then
    print_warning "No IPv6 address found for $TARGET. Skipping IPv6 scan."
fi

# Run Nikto scan on IPv4 only (since it's more likely for a web server)
run_nikto_scan "$ipv4" &

wait  # Wait for all background jobs to finish

# Print final status messages
print_status "Nmap and Nikto scanning complete for $TARGET."
print_status "Log saved to: ${LOG_FILE}"

# Function to generate an HTML report with advanced features
generate_html_report() {
    print_status "Generating HTML report..."
    echo "<html><head><title>Scan Report for $TARGET</title>" > "$HTML_REPORT_FILE"
    echo "<style>
            body { font-family: Arial, sans-serif; }
            h1, h2 { color: #2e6c80; }
            pre { background-color: #f4f4f4; padding: 10px; border-radius: 5px; white-space: pre-wrap; word-wrap: break-word; }
            .scan-section { margin-bottom: 20px; }
            .vuln-section { margin-bottom: 10px; border: 1px solid #ccc; padding: 10px; border-radius: 5px; }
          </style>" >> "$HTML_REPORT_FILE"
    echo "</head><body>" >> "$HTML_REPORT_FILE"
    echo "<h1>Scan Report for $TARGET</h1>" >> "$HTML_REPORT_FILE"
    echo "<p><strong>Scan Date:</strong> $(date)</p>" >> "$HTML_REPORT_FILE"

    # Summary of Findings
    echo "<div class=\"scan-section\"><h2>Summary of Findings</h2><pre>" >> "$HTML_REPORT_FILE"
    grep "open\|closed\|filtered" "$TEMP_OUTPUT_FILE" | wc -l | xargs echo "Total number of ports scanned: " >> "$HTML_REPORT_FILE"
    grep "open" "$TEMP_OUTPUT_FILE" | wc -l | xargs echo "Open ports: " >> "$HTML_REPORT_FILE"
    grep "filtered" "$TEMP_OUTPUT_FILE" | wc -l | xargs echo "Filtered ports: " >> "$HTML_REPORT_FILE"
    grep "closed" "$TEMP_OUTPUT_FILE" | wc -l | xargs echo "Closed ports: " >> "$HTML_REPORT_FILE"
    echo "Recommendations: Review and secure any open ports, apply necessary patches for vulnerabilities, and close unnecessary ports." >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Include IPv4 scan results
    echo "<div class=\"scan-section\"><h2>Scan Results (IPv4)</h2><pre>" >> "$HTML_REPORT_FILE"
    cat "$TEMP_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Include IPv6 scan results if available
    if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
        echo "<div class=\"scan-section\"><h2>Scan Results (IPv6)</h2><pre>" >> "$HTML_REPORT_FILE"
        cat "$TEMP_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
        echo "</pre></div>" >> "$HTML_REPORT_FILE"
    fi

    # Service Detection Results
    echo "<div class=\"scan-section\"><h2>Service Detection Results</h2><pre>" >> "$HTML_REPORT_FILE"
    grep -E "^([0-9]{1,5}/tcp)" "$TEMP_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Detailed Vulnerability Information
    echo "<div class=\"scan-section\"><h2>Detailed Vulnerability Information</h2>" >> "$HTML_REPORT_FILE"

    # Parsing vulnerabilities from the Nmap output
    grep -E "VULNERABLE|vuln|Warning|open" "$TEMP_OUTPUT_FILE" | while read -r line; do

        # Set default values
        severity="N/A"
        cvss_score="N/A"

        # Check if the line contains a CVE identifier
        if echo "$line" | grep -q "CVE-"; then
            # Extract the CVE ID
            cve_id=$(echo "$line" | grep -o "CVE-[0-9]\+-[0-9]\+")
            if [ -n "$cve_id" ]; then
                # Look up the CVE details from the NVD API
                cve_info=$(lookup_cve_details "$cve_id")
                severity=$(echo "$cve_info" | cut -d',' -f1)
                cvss_score=$(echo "$cve_info" | cut -d',' -f2)
            fi
        fi

        # Filter out any line that contains the "scan initiated" or "Nikto v2." text
        if ! echo "$line" | grep -q "scan initiated\|Nikto v2."; then
            echo "<div class=\"vuln-section\"><pre>" >> "$HTML_REPORT_FILE"
            echo "$line" >> "$HTML_REPORT_FILE"
            echo "<strong>Severity:</strong> $severity<br>" >> "$HTML_REPORT_FILE"
            echo "<strong>CVSS Score:</strong> $cvss_score<br>" >> "$HTML_REPORT_FILE"
            echo "</pre></div>" >> "$HTML_REPORT_FILE"
        fi
    done

    # If no vulnerabilities found, add a note
    if ! grep -qE "VULNERABLE|vuln|Warning|open" "$TEMP_OUTPUT_FILE"; then
        echo "<p>No vulnerabilities detected during the scan.</p>" >> "$HTML_REPORT_FILE"
    fi

    # Include Nikto Scan Results
    if [ -f "$NIKTO_OUTPUT_FILE" ]; then
        echo "<div class=\"scan-section\"><h2>Nikto Scan Results</h2><pre>" >> "$HTML_REPORT_FILE"
        cat "$NIKTO_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
        echo "</pre></div>" >> "$HTML_REPORT_FILE"
    else
        echo "<div class=\"scan-section\"><h2>Nikto Scan Results</h2><p>No Nikto results found.</p></div>" >> "$HTML_REPORT_FILE"
    fi

    echo "</div>" >> "$HTML_REPORT_FILE"

    # Scan Environment Details
    echo "<div class=\"scan-section\"><h2>Scan Environment Details</h2><pre>" >> "$HTML_REPORT_FILE"
    echo "Nmap version: $(nmap --version | head -n 1)" >> "$HTML_REPORT_FILE"
    echo "Nmap options: $NMAP_OPTIONS" >> "$HTML_REPORT_FILE"
    echo "Scripts used: $NMAP_SCRIPTS" >> "$HTML_REPORT_FILE"
    echo "Script arguments: $NMAP_SCRIPT_ARGS" >> "$HTML_REPORT_FILE"
    echo "Ports scanned: $NMAP_PORTS" >> "$HTML_REPORT_FILE"
    echo "Nikto output file: $NIKTO_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
    echo "Scanning host IP: $(hostname -I | awk '{print $1}')" >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    echo "</body></html>" >> "$HTML_REPORT_FILE"
    print_status "HTML report saved to: $HTML_REPORT_FILE"
}


# Generate HTML report if enabled
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
    generate_html_report
fi

# Ensure all created files are owned by the user running the script
chown $SUDO_USER:$SUDO_USER "$LOG_FILE" "$HTML_REPORT_FILE" "$NIKTO_OUTPUT_FILE"

# Clean up the temporary files
rm -f "$TEMP_OUTPUT_FILE" "$NIKTO_OUTPUT_FILE"

exit 0
