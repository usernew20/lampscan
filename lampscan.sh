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
        print_warning "Configuration file lampscan.conf not found. Using default settings."
    fi
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

# Load the configuration file
load_config

# Function to check if input is an IP address
is_ip() {
    if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

# Get the current date and time for the suffix
DATE_TIME=$(date +"%Y%m%d_%H%M%S")

# Output file name based on target and current date/time
OUTPUT_FILE="${TARGET}_${DATE_TIME}_scan_results"
LOG_FILE="${TARGET}_${DATE_TIME}_scan.log"

# Print the header to console
print_header

# Print the header to the log file only
print_header "log"

# Check if required commands are available
for cmd in nmap dig; do
    if ! command -v $cmd &> /dev/null; then
        print_error "$cmd could not be found. Please install it and try again."
        exit 1
    fi
done

# Notify user that IPv6 support is being checked
print_status "Checking for IPv6 support on this machine..."

# Detect if IPv6 is supported on the machine
if ping6 -c 1 ::1 &> /dev/null; then
    IPV6_SUPPORTED=true
else
    IPV6_SUPPORTED=false
fi

# Resolve the IP addresses of the target if it's not an IP
if is_ip "$TARGET"; then
    ipv4="$TARGET"
else
    ipv4=$(dig +short A $TARGET)
    ipv6=$(dig +short AAAA $TARGET)
fi

if [ -z "$ipv4" ]; then
    print_error "No IPv4 address found for $TARGET."
    exit 1
fi

if [ "$IPV6_SUPPORTED" = true ] && [ -z "$ipv6" ]; then
    print_warning "No IPv6 address found for $TARGET."
fi

# Function to run an IPv4 scan
run_scan_ipv4() {
    print_status "Starting IPv4 scan on $1..."
    nmap -Pn -sC \
        --script "http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*" \
        --script-args="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10,http-slowloris.runforever=true" \
        -p 80,443,22,21,3306,8080,8443,25,110,143,993,995 "$1" --min-rate=100 --randomize-hosts -oN "${OUTPUT_FILE}.ipv4" -vv
}

# Function to run an IPv6 scan
run_scan_ipv6() {
    print_status "Starting IPv6 scan on $1..."
    nmap -Pn -sC -6 \
        --script "http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*" \
        --script-args="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10,http-slowloris.runforever=true" \
        -p 80,443,22,21,3306,8080,8443,25,110,143,993,995 "$1" --min-rate=100 --randomize-hosts -oN "${OUTPUT_FILE}.ipv6" -vv
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

exit 0
