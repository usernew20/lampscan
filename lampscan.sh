#!/bin/bash

# ANSI color codes
BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

# Default log level (INFO)
LOG_LEVEL="INFO"

# Default log file (in case it's needed before configuration is loaded)
LOG_FILE=""

# Function to log messages with timestamps
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
        if [ "$LOG_LEVEL" = "INFO" ] || [ "$LOG_LEVEL" = "VERBOSE" ]; then
            echo -e "${GREEN}$message${RESET}"
            if [ -n "$LOG_FILE" ]; then echo "[$timestamp] INFO: $message" >> "$LOG_FILE"; fi
        fi
    elif [ "$level" = "VERBOSE" ]; then
        if [ "$LOG_LEVEL" = "VERBOSE" ]; then
            echo -e "${CYAN}$message${RESET}"
            if [ -n "$LOG_FILE" ]; then echo "[$timestamp] VERBOSE: $message" >> "$LOG_FILE"; fi
        fi
    fi
}

# Function to print status messages
print_status() {
    log_message "INFO" "$1"
}

# Function to print verbose messages
print_verbose() {
    log_message "VERBOSE" "$1"
}

# Function to print warnings
print_warning() {
    log_message "WARNING" "$1"
}

# Function to print errors
print_error() {
    log_message "ERROR" "$1"
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    log_message "ERROR" "This script must be run as root."
    exit 1
fi

# Load the configuration file early in the script
load_config() {
    local config_file="lampscan.conf"
    if [ -f "$config_file" ]; then
        source "$config_file"
    else
        log_message "WARNING" "Configuration file lampscan.conf not found. Creating a default configuration."
        create_default_config
    fi
}

create_default_config() {
    cat <<EOL > lampscan.conf
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

# Ports to scan
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995,5432,1433,1521,389,636,53,445,1194,500,4500"

# Custom group scripts (can be defined by the user)
CUSTOM_NMAP_SCRIPTS=""
CUSTOM_NMAP_SCRIPT_ARGS=""

# Nikto scan options
NIKTO_OPTIONS="-Tuning 1 -ssl"

# Report generation
GENERATE_HTML_REPORT="true"

# Log level
LOG_LEVEL="INFO"  # Change this to "VERBOSE" for more detailed logs
EOL

    log_message "INFO" "Default configuration file created at lampscan.conf"
    sync

    if [ -f "lampscan.conf" ]; then
        source lampscan.conf
    else
        log_message "ERROR" "Failed to create and source the configuration file."
        exit 1
    fi
}

# Now load the configuration
load_config

# Check if the user provided an argument
if [ -z "$1" ]; then
    echo "Usage: $0 [-v] <domain_or_ip>"
    exit 1
fi

# Check for verbose flag
if [ "$1" == "-v" ]; then
    LOG_LEVEL="VERBOSE"
    shift  # Remove the -v from the argument list
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

# Check required commands
check_required_commands() {
    local cmds=("nmap" "dig" "ping6" "jq" "curl" "nikto")
    for cmd in "${cmds[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            print_error "$cmd could not be found. Please install it and try again."
            exit 1
        fi
    done
}

# Check required commands
check_required_commands

# Initialize log file based on the target and current date/time
DATE_TIME=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${TARGET}_${DATE_TIME}_scan.log"
HTML_REPORT_FILE="${TARGET}_${DATE_TIME}_scan_report.html"
NIKTO_OUTPUT_FILE="${TARGET}_${DATE_TIME}_nikto_output.txt"

# Spinner function
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\r"
    done
    printf "    \r" # clear spinner after process is done
    wait $pid
}

# Function to run a group scan
run_scan_group() {
    local group_name="$1"
    local group_scripts="$2"
    local group_script_args="$3"
    local output_file="${TARGET}_${group_name}_scan_output.txt"

    print_status "Starting $group_name scan on $TARGET..."
    nmap $NMAP_OPTIONS \
        --script "$group_scripts" \
        --script-args="$group_script_args" \
        -p "$NMAP_PORTS" "$TARGET" --min-rate=100 --randomize-hosts -oN "$output_file" -vv &
    spinner
    print_verbose "Nmap command executed for $group_name: nmap $NMAP_OPTIONS --script \"$group_scripts\" --script-args=\"$group_script_args\" -p \"$NMAP_PORTS\" $TARGET --min-rate=100 --randomize-hosts -oN \"$output_file\" -vv"
}

# Group definitions
WEB_NMAP_SCRIPTS="http-enum,http-vuln*,http-wordpress*,http-phpmyadmin-dir-traversal,http-config-backup,http-vhosts"
AUTH_NMAP_SCRIPTS="ssh*,ftp*,auth*,ssh-auth-methods"
DATABASE_NMAP_SCRIPTS="*sql*,mysql*,http-sql-injection"
COMMON_NMAP_SCRIPTS="*apache*,dns*,smb*,firewall*,ssl-enum-ciphers,ssl-cert"
VULN_NMAP_SCRIPTS="vuln*,vulners"
CUSTOM_NMAP_SCRIPTS="$CUSTOM_NMAP_SCRIPTS"

# Group-specific arguments
WEB_NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10"
AUTH_NMAP_SCRIPT_ARGS=""
DATABASE_NMAP_SCRIPT_ARGS="ftp-anon.maxlist=10"
COMMON_NMAP_SCRIPT_ARGS=""
VULN_NMAP_SCRIPT_ARGS=""
CUSTOM_NMAP_SCRIPT_ARGS="$CUSTOM_NMAP_SCRIPT_ARGS"

# Execute groups in parallel
run_scan_group "web" "$WEB_NMAP_SCRIPTS" "$WEB_NMAP_SCRIPT_ARGS"
run_scan_group "auth" "$AUTH_NMAP_SCRIPTS" "$AUTH_NMAP_SCRIPT_ARGS"
run_scan_group "database" "$DATABASE_NMAP_SCRIPTS" "$DATABASE_NMAP_SCRIPT_ARGS"
run_scan_group "common" "$COMMON_NMAP_SCRIPTS" "$COMMON_NMAP_SCRIPT_ARGS"
run_scan_group "vuln" "$VULN_NMAP_SCRIPTS" "$VULN_NMAP_SCRIPT_ARGS"

# Run the custom group if defined
if [ -n "$CUSTOM_NMAP_SCRIPTS" ]; then
    if ! nmap --script-help="$CUSTOM_NMAP_SCRIPTS" > /dev/null 2>&1; then
        print_warning "Custom scripts not found or invalid: $CUSTOM_NMAP_SCRIPTS"
    else
        run_scan_group "custom" "$CUSTOM_NMAP_SCRIPTS" "$CUSTOM_NMAP_SCRIPT_ARGS"
    fi
fi

# Wait for all scans to finish
wait

# Merge results
FINAL_OUTPUT_FILE="${TARGET}_${DATE_TIME}_final_scan_output.txt"
cat *_scan_output.txt > "$FINAL_OUTPUT_FILE"

# Run Nikto scan on IPv4 only (since it's more likely for a web server)
run_nikto_scan() {
    local target_ip="$1"
    print_status "Starting Nikto scan on $target_ip..."
    nikto -h "$target_ip" $NIKTO_OPTIONS -output "$NIKTO_OUTPUT_FILE" &
    spinner
    print_verbose "Nikto command executed: nikto -h \"$target_ip\" $NIKTO_OPTIONS -output \"$NIKTO_OUTPUT_FILE\""
}

run_nikto_scan "$TARGET"

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
    grep "open\|closed\|filtered" "$FINAL_OUTPUT_FILE" | wc -l | xargs echo "Total number of ports scanned: " >> "$HTML_REPORT_FILE"
    grep "open" "$FINAL_OUTPUT_FILE" | wc -l | xargs echo "Open ports: " >> "$HTML_REPORT_FILE"
    grep "filtered" "$FINAL_OUTPUT_FILE" | wc -l | xargs echo "Filtered ports: " >> "$HTML_REPORT_FILE"
    grep "closed" "$FINAL_OUTPUT_FILE" | wc -l | xargs echo "Closed ports: " >> "$HTML_REPORT_FILE"
    echo "Recommendations: Review and secure any open ports, apply necessary patches for vulnerabilities, and close unnecessary ports." >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Include IPv4 scan results
    echo "<div class=\"scan-section\"><h2>Scan Results (IPv4)</h2><pre>" >> "$HTML_REPORT_FILE"
    cat "$FINAL_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Include IPv6 scan results if available
    if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
        echo "<div class=\"scan-section\"><h2>Scan Results (IPv6)</h2><pre>" >> "$HTML_REPORT_FILE"
        cat "$FINAL_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
        echo "</pre></div>" >> "$HTML_REPORT_FILE"
    fi

    # Service Detection Results
    echo "<div class=\"scan-section\"><h2>Service Detection Results</h2><pre>" >> "$HTML_REPORT_FILE"
    grep -E "^([0-9]{1,5}/tcp)" "$FINAL_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Detailed Vulnerability Information
    echo "<div class=\"scan-section\"><h2>Detailed Vulnerability Information</h2>" >> "$HTML_REPORT_FILE"

    # Parsing vulnerabilities from the Nmap output
    grep -E "VULNERABLE|vuln|Warning|open" "$FINAL_OUTPUT_FILE" | while read -r line; do
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
    if ! grep -qE "VULNERABLE|vuln|Warning|open" "$FINAL_OUTPUT_FILE"; then
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
    echo "Scripts used: $group_script_args" >> "$HTML_REPORT_FILE"
    echo "Ports scanned: $NMAP_PORTS" >> "$HTML_REPORT_FILE"
    echo "Nikto output file: $NIKTO_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
    echo "Scanning host IP: $(hostname -I | awk '{print $1}')" >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    echo "</body></html>" >> "$HTML_REPORT_FILE"
    print_verbose "HTML report generation completed."
    print_status "HTML report saved to: $HTML_REPORT_FILE"
}

# Generate HTML report if enabled
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
    generate_html_report
fi

# Ensure all created files are owned by the user running the script
if [ -n "$SUDO_USER" ]; then
    chown $SUDO_USER:$SUDO_USER "$LOG_FILE" "$HTML_REPORT_FILE" "$NIKTO_OUTPUT_FILE"
fi

# Clean up the temporary files
rm -f *_scan_output.txt "$NIKTO_OUTPUT_FILE"

exit 0
