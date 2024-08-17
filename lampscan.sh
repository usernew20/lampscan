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

# Function to create a default configuration file
create_default_config() {
    local config_file="lampscan.conf"
    cat <<EOL > "$config_file"
# LAMP/WordPress Server Nmap Scan Tool Configuration
# Default configuration settings

# Nmap command options
NMAP_OPTIONS="-Pn -sC"
NMAP_SCRIPTS="http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*,dns*,smb*,firewall*"
NMAP_SCRIPT_ARGS="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10,http-slowloris.runforever=true"
NMAP_PORTS="80,443,22,21,3306,8080,8443,25,110,143,993,995"

# Log level (INFO, WARNING, ERROR)
LOG_LEVEL="INFO"
EOL
    echo "Configuration file lampscan.conf not found. Creating a default configuration."
    print_status "Default configuration file created at $config_file"
}

# Function to load configuration file
load_config() {
    local config_file="lampscan.conf"
    if [ -f "$config_file" ]; then
        if ! source "$config_file"; then
            print_error "Failed to load configuration from $config_file. Please check the file syntax."
            exit 1
        fi
    else
        create_default_config
        source "$config_file"
    fi
}

# Enhanced error handling for missing required commands
check_required_commands() {
    local cmds=("nmap" "dig" "ping6")
    for cmd in "${cmds[@]}"; do
        if ! command -v $cmd &> /dev/null; then
            if [ "$cmd" = "nmap" ]; then
                print_error "Nmap is not installed. Please install it using:\n- Ubuntu: sudo apt-get install nmap\n- macOS: brew install nmap"
            elif [ "$cmd" = "dig" ]; then
                print_error "dig command is not installed. Please install it using:\n- Ubuntu: sudo apt-get install dnsutils\n- macOS: dig comes pre-installed. If missing, reinstall the DNS utilities."
            elif [ "$cmd" = "ping6" ]; then
                print_error "ping6 command is not installed. Please install it using:\n- Ubuntu: sudo apt-get install inetutils-ping\n- macOS: ping6 comes pre-installed. If missing, reinstall the network utilities."
            fi
            exit 1
        fi
    done
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root. Please rerun the script using sudo: sudo ./lampscan.sh <domain_or_ip>"
    exit 1
fi

# Check if the user provided an argument
if [ -z "$1" ]; then
    echo "Usage: $0 <domain_or_ip>"
    exit 1
fi

TARGET="$1"

# Get the current date and time for the suffix
DATE_TIME=$(date +"%Y%m%d_%H%M%S")

# Output file name based on target and current date/time
OUTPUT_FILE="${TARGET}_${DATE_TIME}_scan_results"
LOG_FILE="${TARGET}_${DATE_TIME}_scan.log"

# Print the header to console
print_header

# Print the header to the log file only
print_header "log"

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
    if [ -z "$ipv4" ]; then
        print_error "Failed to resolve IPv4 address for $TARGET. Please check your network connection or DNS settings."
        exit 1
    fi

    ipv6=$(dig +short AAAA "$TARGET")
    if [ -z "$ipv6" ]; then
        print_warning "No IPv6 address found for $TARGET. IPv6 scan will be skipped."
    fi
fi

# Function to run an IPv4 scan with expanded Nmap script library
run_scan_ipv4() {
    print_status "Starting IPv4 scan on $1..."
    if ! nmap $NMAP_OPTIONS \
        --script "$NMAP_SCRIPTS" \
        --script-args="$NMAP_SCRIPT_ARGS" \
        -p "$NMAP_PORTS" "$1" --min-rate=100 --randomize-hosts -oN "${OUTPUT_FILE}.ipv4" -vv; then
        print_error "Nmap scan failed on $1. Please ensure the target is reachable and that Nmap is properly configured."
        exit 1
    fi
}

# Function to run an IPv6 scan with expanded Nmap script library
run_scan_ipv6() {
    print_status "Starting IPv6 scan on $1..."
    if ! nmap $NMAP_OPTIONS -6 \
        --script "$NMAP_SCRIPTS" \
        --script-args="$NMAP_SCRIPT_ARGS" \
        -p "$NMAP_PORTS" "$1" --min-rate=100 --randomize-hosts -oN "${OUTPUT_FILE}.ipv6" -vv; then
        print_error "Nmap scan failed on $1. Please ensure the target is reachable and that Nmap is properly configured."
        exit 1
    fi
}

# Run the scan on IPv4
run_scan_ipv4 "$ipv4" &

# Run the scan on IPv6 if available and supported
if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
    run_scan_ipv6 "$ipv6" &
elif [ "$IPV6_SUPPORTED" = false ]; then
    print_warning "Skipping IPv6 scan because IPv6 is not supported on this machine."
elif [ -z "$ipv6" ]; then
    print_warning "No IPv6 address found for $TARGET. Skipping IPv6 scan."
fi

wait  # Wait for all background jobs to finish

# Function to process and print scan results
process_and_print_results() {
    local file="$1"
    echo -e "${BOLD}${CYAN}Scan Results:${RESET}"
    grep -E "open|filtered|closed" "$file" || echo "No results found."
}

# Process and print IPv4 results
process_and_print_results "${OUTPUT_FILE}.ipv4"

# Process and print IPv6 results if available
if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
    process_and_print_results "${OUTPUT_FILE}.ipv6"
fi

# Print final status messages
print_status "Nmap scanning complete for $TARGET."
print_status "Results saved to: ${OUTPUT_FILE}.ipv4"

if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
    print_status "IPv6 results saved to: ${OUTPUT_FILE}.ipv6"
fi

print_status "Log file saved to: $LOG_FILE"

exit 0
