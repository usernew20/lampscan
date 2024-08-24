#!/bin/bash

# Function to handle errors
handle_error() {
    local exit_code=$?
    local cmd="${BASH_COMMAND}"
    local line_number="${BASH_LINENO[0]}"
    echo "An error occurred during the execution of the script."
    echo "Command: '${cmd}' failed with exit code ${exit_code}."
    echo "Error occurred on line ${line_number}."
    echo "Cleaning up..."
    # Delete temp files
    rm -f *_output.txt
    exit $exit_code
}

# Automatically trap errors and call the handle_error function
trap 'handle_error' ERR

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
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
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
        log_message "WARNING" "Configuration file lampscan.conf not found."
        create_default_config
    fi
}

create_default_config() {
    cat <<EOL > lampscan.conf
# Default Nmap options
NMAP_OPTIONS="-Pn -sC -A -sV"

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

# Ports to scan by group
WEB_PORTS="80,443,8080,8443"
AUTH_PORTS="389,636"
DATABASE_PORTS="3306,5432,1433,1521"
COMMON_PORTS="22,21,53,445"
VULN_PORTS="25,110,143,993,995,1194,500,4500"
CUSTOM_PORTS=""

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
        if ! command -v "$cmd" &> /dev/null; then
            print_error "$cmd could not be found. Please install it and try again."
            exit 1
        fi
    done
}

check_ipv6_support() {
    local target="$1"
    if ping6 -c 1 -W 1 "$target" &> /dev/null; then
        IPV6_SUPPORTED=true
        log_message "INFO" "IPv6 is supported and reachable for $target."
    else
        IPV6_SUPPORTED=false
        log_message "INFO" "IPv6 is not supported or not reachable for $target."
    fi
}

# Check if the local machine supports IPv6
check_ipv6_support

# Check required commands
check_required_commands

# Initialize log file based on the target and current date/time
DATE_TIME=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="${TARGET}_${DATE_TIME}_scan.log"
HTML_REPORT_FILE="${TARGET}_${DATE_TIME}_scan_report.html"
NIKTO_OUTPUT_FILE="${TARGET}_${DATE_TIME}_nikto_output.txt"

# Function to print the banner to console and log file
print_banner() {
    local banner_text="================================================================
LAMP/WordPress Server Nmap Scan (c) 2024 Zayn Otley
https://github.com/intuitionamiga/lampscan
MIT License - Use at your own risk!
================================================================"

    # Print with ANSI coloring to the console
    echo -e "${BOLD}${CYAN}$banner_text${RESET}"

    # Print without ANSI coloring to the log file
    echo "$banner_text" >> "$LOG_FILE"
}

# Print the banner
print_banner

# Spinner function
spinner() {
    local pid=$!
    local delay=0.1
    local spinstr='|/-\'
    local scan_name="$1"

    while kill -0 $pid 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c] %s  " "$spinstr" "$scan_name"
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
    local group_ports="$4"
    local ip_version="$5"
    local target_ip="$6"

    local output_file="${TARGET}_${group_name}_${ip_version}_scan_output.txt"
    local nmap_options="$NMAP_OPTIONS"

    if [ "$ip_version" == "IPv6" ]; then
        nmap_options="$nmap_options -6"
    fi

    print_status "Starting $group_name scan on $target_ip ($ip_version)..."
    nmap $nmap_options \
        --script "$group_scripts" \
        --script-args="$group_script_args" \
        -p "$group_ports" "$target_ip" --min-rate=100 --randomize-hosts -oN "$output_file" -vv &
    spinner "$group_name"
    print_verbose "Nmap command executed for $group_name ($ip_version): nmap $nmap_options --script \"$group_scripts\" --script-args=\"$group_script_args\" -p \"$group_ports\" $target_ip --min-rate=100 --randomize-hosts -oN \"$output_file\" -vv"
}

# Execute scans in parallel for IPv4 and IPv6
run_scans() {
    local ip_version="$1"
    local target_ip="$2"

    # Run predefined scan groups
    run_scan_group "web" "$WEB_NMAP_SCRIPTS" "$WEB_NMAP_SCRIPT_ARGS" "$WEB_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "auth" "$AUTH_NMAP_SCRIPTS" "$AUTH_NMAP_SCRIPT_ARGS" "$AUTH_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "database" "$DATABASE_NMAP_SCRIPTS" "$DATABASE_NMAP_SCRIPT_ARGS" "$DATABASE_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "common" "$COMMON_NMAP_SCRIPTS" "$COMMON_NMAP_SCRIPT_ARGS" "$COMMON_PORTS" "$ip_version" "$target_ip" &
    run_scan_group "vuln" "$VULN_NMAP_SCRIPTS" "$VULN_NMAP_SCRIPT_ARGS" "$VULN_PORTS" "$ip_version" "$target_ip" &

    # Run the custom group if defined
    if [ -n "$CUSTOM_NMAP_SCRIPTS" ]; then
        if ! nmap --script-help="$CUSTOM_NMAP_SCRIPTS" > /dev/null 2>&1; then
            print_warning "Custom scripts not found or invalid: $CUSTOM_NMAP_SCRIPTS"
        else
            run_scan_group "custom" "$CUSTOM_NMAP_SCRIPTS" "$CUSTOM_NMAP_SCRIPT_ARGS" "$CUSTOM_PORTS" "$ip_version" "$target_ip" &
        fi
    fi
}

# Run for IPv4
run_scans "IPv4" "$TARGET"

if [ "$IPV6_SUPPORTED" = true ]; then
    run_scans "IPv6" "$TARGET"
fi

# Run Nikto scan on IPv4 only (since it's more likely for a web server)
run_nikto_scan() {
    local target_ip="$1"
    print_status "Starting Nikto scan on $target_ip..."
    nikto -h "$target_ip" $NIKTO_OPTIONS -output "$NIKTO_OUTPUT_FILE" &
    spinner "Nikto"
    print_verbose "Nikto command executed: nikto -h \"$target_ip\" $NIKTO_OPTIONS -output \"$NIKTO_OUTPUT_FILE\""
}

run_nikto_scan "$TARGET" &

# Wait for all scans to finish
wait

# Merge results
FINAL_OUTPUT_FILE="${TARGET}_${DATE_TIME}_final_scan_output.txt"
cat *_scan_output.txt > "$FINAL_OUTPUT_FILE"

# Print final status messages
print_status "Nmap and Nikto scanning complete for $TARGET."
print_status "Log saved to: ${LOG_FILE}"

# Function to generate an HTML report with advanced features
function lookup_cve_details() {
    local cve_id="$1"
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cve/1.0/$cve_id"

    # Fetch CVE details from NVD
    local cve_details
    cve_details=$(curl -s "$nvd_api_url" | jq '.result.CVE_Items[0].cve')

    # Check if we got a valid response
    if [[ -z "$cve_details" || "$cve_details" == "null" ]]; then
        print_warning "CVE details for $cve_id could not be retrieved."
        echo "N/A,N/A"
        return
    fi

    # Extract relevant information from the JSON response
    local cve_description
    cve_description=$(echo "$cve_details" | jq -r '.description.description_data[0].value')
    #local cve_published_date
    #cve_published_date=$(echo "$cve_details" | jq -r '.publishedDate')
    local cve_impact_score
    cve_impact_score=$(echo "$cve_details" | jq -r '.impact.baseMetricV2.cvssV2.baseScore // "N/A"')

    # Return severity and CVSS score
    echo "$cve_description,$cve_impact_score"
}

# Function to lookup CVEs based on service version
lookup_cve_by_service_version() {
    local service_name="$1"
    local version="$2"
    local nvd_api_url="https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=$service_name+$version"

    # Fetch CVE details from NVD with proper headers
    local cve_details
    cve_details=$(curl -s -H "User-Agent: YourScriptName/1.0" "$nvd_api_url")

    # Debugging: Print the raw API response
    echo "API Response for $service_name $version: $cve_details" >> "$LOG_FILE"

    # Check if the response is valid JSON
    if ! echo "$cve_details" | jq empty; then
        print_warning "Invalid JSON received from NVD API for $service_name $version."
        return
    fi

    # Parse the CVE details from the response
    local cve_list
    cve_list=$(echo "$cve_details" | jq -r '.result.CVE_Items[] | .cve.CVE_data_meta.ID + " - " + .cve.description.description_data[0].value + " (CVSS Score: " + (.impact.baseMetricV2.cvssV2.baseScore | tostring) + ")"')

    if [ -z "$cve_list" ]; then
        echo "No CVEs found for $service_name $version."
    else
        echo "$cve_list"
    fi
}

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

    # Iterate over scan groups and IP versions
    for ip_version in IPv4 IPv6; do
        for group_name in web auth database common vuln; do
            local output_file="${TARGET}_${group_name}_${ip_version}_scan_output.txt"
            if [ -f "$output_file" ]; then
                echo "<div class=\"scan-section\"><h2>${group_name^} Scan Results ($ip_version)</h2><pre>" >> "$HTML_REPORT_FILE"
                cat "$output_file" >> "$HTML_REPORT_FILE"
                echo "</pre></div>" >> "$HTML_REPORT_FILE"
            fi
        done
    done

    # Service Detection Results
    echo "<div class=\"scan-section\"><h2>Service Detection Results</h2><pre>" >> "$HTML_REPORT_FILE"
    grep -E "^([0-9]{1,5}/tcp|udp)" "$FINAL_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
    echo "</pre></div>" >> "$HTML_REPORT_FILE"

    # Nikto Scan Results
    if [ -f "$NIKTO_OUTPUT_FILE" ]; then
        echo "<div class=\"scan-section\"><h2>Nikto Scan Results</h2><pre>" >> "$HTML_REPORT_FILE"
        cat "$NIKTO_OUTPUT_FILE" >> "$HTML_REPORT_FILE"
        echo "</pre></div>" >> "$HTML_REPORT_FILE"
    else
        echo "<div class=\"scan-section\"><h2>Nikto Scan Results</h2><p>No Nikto results found.</p></div>" >> "$HTML_REPORT_FILE"
    fi

    # Detailed Vulnerability Information
    echo "<div class=\"scan-section\"><h2>Detailed Vulnerability Information</h2>" >> "$HTML_REPORT_FILE"

    # Collect vulnerabilities from the scan results
    local vuln_file="${TARGET}_vuln_scan_output.txt"
    if [ -f "$vuln_file" ]; then
        while IFS= read -r line; do
            local severity="N/A"
            local cvss_score="N/A"
            local cve_id=""

            # Extract CVE if present
            if echo "$line" | grep -q "CVE-"; then
                cve_id=$(echo "$line" | grep -o "CVE-[0-9]\+-[0-9]\+")
                if [ -n "$cve_id" ]; then
                    local cve_info=$(lookup_cve_details "$cve_id")
                    severity=$(echo "$cve_info" | cut -d',' -f1)
                    cvss_score=$(echo "$cve_info" | cut -d',' -f2)
                fi
            fi

            # Display vulnerability information in the report
            echo "<div class=\"vuln-section\"><pre>" >> "$HTML_REPORT_FILE"
            echo "$line" >> "$HTML_REPORT_FILE"
            if [ -n "$cve_id" ]; then
                echo "<strong>CVE:</strong> $cve_id<br>" >> "$HTML_REPORT_FILE"
            fi
            echo "<strong>Severity:</strong> $severity<br>" >> "$HTML_REPORT_FILE"
            echo "<strong>CVSS Score:</strong> $cvss_score<br>" >> "$HTML_REPORT_FILE"
            echo "</pre></div>" >> "$HTML_REPORT_FILE"

        done < "$vuln_file"
    else
        echo "<p>No vulnerabilities detected during the scan.</p>" >> "$HTML_REPORT_FILE"
    fi

    echo "</div>" >> "$HTML_REPORT_FILE"

    echo "</body></html>" >> "$HTML_REPORT_FILE"

    print_status "HTML report generated at: ${HTML_REPORT_FILE}"
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

# Open the HTML report in the default browser as the non-root user
if [ "$GENERATE_HTML_REPORT" = "true" ]; then
    if command -v xdg-open &> /dev/null; then
        export DISPLAY=:0
        export XDG_RUNTIME_DIR="/tmp/runtime-$SUDO_USER"
        sudo -u "$SUDO_USER" xdg-open "$HTML_REPORT_FILE"
    elif command -v open &> /dev/null; then
        sudo -u "$SUDO_USER" open "$HTML_REPORT_FILE"
    fi
fi

exit 0