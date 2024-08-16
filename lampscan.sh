#!/bin/bash

# ANSI color codes
BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

# Function to print headers
print_header() {
    echo -e "${BOLD}${CYAN}================================================================${RESET}"
    echo -e "${BOLD}${CYAN}LAMP/WordPress Server Nmap Scan (c) 2024 Zayn Otley${RESET}"
    echo -e "${BOLD}${CYAN}================================================================${RESET}"
}

# Function to print headers to the log file
print_log_header() {
    echo "================================================================" >> "$LOG_FILE"
    echo "LAMP/WordPress Server Nmap Scan (c) 2024 Zayn Otley" >> "$LOG_FILE"
    echo "================================================================" >> "$LOG_FILE"
}

# Function to print status messages
print_status() {
    echo -e "${GREEN}$1${RESET}"
}

# Function to print warnings
print_warning() {
    echo -e "${YELLOW}$1${RESET}"
}

# Function to print errors
print_error() {
    echo -e "${RED}$1${RESET}"
}

# Always print the header first to console and log
print_header

# Check if the user provided an argument
if [ -z "$1" ]; then
    print_error "Usage: $0 <domain_or_ip>"
    exit 1
fi

TARGET="$1"

# Get the current date and time for the suffix
DATE_TIME=$(date +"%Y%m%d_%H%M%S")

# Output file name based on target and current date/time
OUTPUT_FILE="${TARGET}_${DATE_TIME}_scan_results"
LOG_FILE="${OUTPUT_FILE}_log.txt"

# Write header to the log file
print_log_header

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
    print_status "IPv6 is supported on this machine."
else
    IPV6_SUPPORTED=false
    print_warning "IPv6 is not supported on this machine. Skipping IPv6 scans."
fi

# Display a summary of what the script will do and write it to the log file
{
    echo -e "Target: $TARGET"
    echo -e "Scanning Ports: 80, 443, 22, 21, 3306, 8080, 8443, 25, 110, 143, 993, 995"
    echo -e "Scanning IPv4 and IPv6 addresses (if available)."
    echo -e "Using Nmap with detailed verbosity (-vv), service detection, and common vulnerability scripts."
    echo -e "Randomizing host scan order to evade detection systems."
    echo -e "Scan results will be saved as: ${OUTPUT_FILE}_ipv4 and ${OUTPUT_FILE}_ipv6"
} | tee -a "$LOG_FILE"

# Function to run Nmap scan on IPv4
run_scan_ipv4() {
    local target_ip="$1"
    print_status "Starting Nmap IPv4 scan on $target_ip at $(date)..."

    sudo nmap -Pn -sC \
    --script "http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*" \
    --script-args="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10,http-slowloris.runforever=true" \
    -p 80,443,22,21,3306,8080,8443,25,110,143,993,995 "$target_ip" -D RND:10 --min-rate=100 --randomize-hosts -oA "${OUTPUT_FILE}_ipv4" -vv

    print_status "Completed Nmap IPv4 scan on $target_ip at $(date)"
}

# Function to run Nmap scan on IPv6
run_scan_ipv6() {
    local target_ip="$1"
    print_status "Starting Nmap IPv6 scan on $target_ip at $(date)..."

    sudo nmap -A -Pn -sC -6 \
    --script "http-enum,http-vuln*,*sql*,*php*,http-wordpress*,vuln*,auth*,*apache*,*ssh*,*ftp*" \
    --script-args="http-wordpress-enum.threads=10,http-wordpress-brute.threads=10,ftp-anon.maxlist=10,http-slowloris.runforever=true" \
    -p 80,443,22,21,3306,8080,8443,25,110,143,993,995 "$target_ip" --min-rate=100 --randomize-hosts -oA "${OUTPUT_FILE}_ipv6" -vv

    print_status "Completed Nmap IPv6 scan on $target_ip at $(date)"
}

# Resolve both IPv4 and IPv6 addresses
ipv4=$(dig +short "$TARGET" A)
ipv6=$(dig +short "$TARGET" AAAA)

# Run the scan on IPv4 if available
if [ -n "$ipv4" ]; then
    run_scan_ipv4 "$ipv4" &
else
    print_error "No IPv4 address found for $TARGET." | tee -a "$LOG_FILE"
fi

# Run the scan on IPv6 if available and supported
if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
    run_scan_ipv6 "$ipv6" &
elif [ "$IPV6_SUPPORTED" = false ]; then
    print_warning "Skipping IPv6 scan because IPv6 is not supported on this machine." | tee -a "$LOG_FILE"
elif [ -z "$ipv6" ]; then
    print_error "No IPv6 address found for $TARGET." | tee -a "$LOG_FILE"
fi

wait  # Wait for all background jobs to finish

print_status "Nmap scanning complete for $TARGET."

# Provide a summary of findings
grep -E "open|filtered|closed" "${OUTPUT_FILE}_ipv4.nmap" | \
while IFS= read -r line; do
    if [[ $line == *"open"* ]]; then
        echo -e "${GREEN}${line}${RESET}"
        echo "$line" >> "$LOG_FILE"
    elif [[ $line == *"filtered"* ]]; then
        echo -e "${YELLOW}${line}${RESET}"
        echo "$line" >> "$LOG_FILE"
    elif [[ $line == *"closed"* ]]; then
        echo -e "${RED}${line}${RESET}"
        echo "$line" >> "$LOG_FILE"
    else
        echo "$line" >> "$LOG_FILE"
    fi
done

# Determine if the IPv6 scan results should be included in the final output message
if [ "$IPV6_SUPPORTED" = true ] && [ -n "$ipv6" ]; then
    grep -E "open|filtered|closed" "${OUTPUT_FILE}_ipv6.nmap" | \
    while IFS= read -r line; do
        if [[ $line == *"open"* ]]; then
            echo -e "${GREEN}${line}${RESET}"
            echo "$line" >> "$LOG_FILE"
        elif [[ $line == *"filtered"* ]]; then
            echo -e "${YELLOW}${line}${RESET}"
            echo "$line" >> "$LOG_FILE"
        elif [[ $line == *"closed"* ]]; then
            echo -e "${RED}${line}${RESET}"
            echo "$line" >> "$LOG_FILE"
        else
            echo "$line" >> "$LOG_FILE"
        fi
    done
    print_status "Scan complete. Results saved to: ${OUTPUT_FILE}_ipv4 and ${OUTPUT_FILE}_ipv6"
else
    print_status "Scan complete. Results saved to: ${OUTPUT_FILE}_ipv4"
fi
