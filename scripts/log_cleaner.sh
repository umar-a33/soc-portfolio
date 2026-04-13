#!/bin/bash
# =====================================================================
# Log Cleaner & Anonymizer for SOC Analysts
# 
# This script processes log files to remove or anonymize sensitive data
# including IP addresses, email addresses, usernames, and hostnames.
# Useful for sharing logs internally or with external parties without
# exposing confidential information or PII.
#
# Author: Umar Ahmed
# Date: April 2026
# Version: 1.0
# =====================================================================

set -euo pipefail

# Default options
MODE="anonymize"       # anonymize, remove, or extract
TARGET_IPS=true
TARGET_EMAILS=true
TARGET_USERNAMES=true
TARGET_HOSTNAMES=false
INPUT_FILE=""
OUTPUT_FILE=""
VERBOSE=false
PRESERVE_TIMESTAMPS=true

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------

usage() {
    cat << EOF
Usage: $0 [OPTIONS] -i <input_file> [-o <output_file>]

Sanitize log files by anonymizing or removing sensitive information.

Options:
  -i, --input FILE        Input log file (required)
  -o, --output FILE       Output file (default: input_cleaned.log)
  -m, --mode MODE         Operation mode: anonymize, remove, extract (default: anonymize)
  --no-ips                Do not process IP addresses
  --no-emails             Do not process email addresses
  --no-usernames          Do not process usernames
  --hostnames             Also anonymize internal hostnames
  -v, --verbose           Show detailed processing information
  -h, --help              Show this help message

Examples:
  $0 -i auth.log -o auth_clean.log
  $0 -i firewall.log -m remove --no-emails
  $0 -i app.log -m anonymize --hostnames -v

EOF
    exit 0
}

log() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "${GREEN}[*]${NC} $1"
    fi
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

# Generate a pseudorandom IPv4 address from input string
# This ensures consistent anonymization for the same IP across runs
anonymize_ip() {
    local ip="$1"
    local hash=$(echo -n "$ip" | md5sum | cut -d' ' -f1)
    # Use first 8 chars of hash to generate a pseudo-random but consistent IP
    local octet1=$((0x${hash:0:2} % 223 + 1))  # 1-223
    local octet2=$((0x${hash:2:2} % 256))
    local octet3=$((0x${hash:4:2} % 256))
    local octet4=$((0x${hash:6:2} % 254 + 1)) # 1-254
    echo "${octet1}.${octet2}.${octet3}.${octet4}"
}

# Anonymize email while keeping domain structure
anonymize_email() {
    local email="$1"
    local hash=$(echo -n "$email" | md5sum | cut -d' ' -f1)
    local domain="${email#*@}"
    echo "user_${hash:0:8}@${domain}"
}

# Anonymize username with consistent prefix
anonymize_username() {
    local user="$1"
    local hash=$(echo -n "$user" | md5sum | cut -d' ' -f1)
    echo "anon_${hash:0:6}"
}

# Anonymize internal hostname
anonymize_hostname() {
    local host="$1"
    local hash=$(echo -n "$host" | md5sum | cut -d' ' -f1)
    echo "host-${hash:0:8}.internal"
}

# ---------------------------------------------------------------------
# Core Processing Function
# ---------------------------------------------------------------------

process_line() {
    local line="$1"
    
    # Process IP addresses (IPv4 only for simplicity)
    if [[ "$TARGET_IPS" == true ]]; then
        while IFS= read -r ip_match; do
            if [[ -n "$ip_match" ]]; then
                if [[ "$MODE" == "anonymize" ]]; then
                    local new_ip=$(anonymize_ip "$ip_match")
                    line=${line//$ip_match/$new_ip}
                    log "Anonymized IP: $ip_match -> $new_ip"
                elif [[ "$MODE" == "remove" ]]; then
                    line=${line//$ip_match/[REDACTED_IP]}
                    log "Removed IP: $ip_match"
                fi
            fi
        done < <(echo "$line" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u)
    fi

    # Process email addresses
    if [[ "$TARGET_EMAILS" == true ]]; then
        while IFS= read -r email_match; do
            if [[ -n "$email_match" ]]; then
                if [[ "$MODE" == "anonymize" ]]; then
                    local new_email=$(anonymize_email "$email_match")
                    line=${line//$email_match/$new_email}
                    log "Anonymized Email: $email_match -> $new_email"
                elif [[ "$MODE" == "remove" ]]; then
                    line=${line//$email_match/[REDACTED_EMAIL]}
                    log "Removed Email: $email_match"
                fi
            fi
        done < <(echo "$line" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u)
    fi

    # Process usernames (patterns like "user=", "username:", "for user", etc.)
    if [[ "$TARGET_USERNAMES" == true ]]; then
        # Extract usernames from common log patterns
        while IFS= read -r user_match; do
            if [[ -n "$user_match" ]]; then
                # Clean up the extracted string (remove prefix/suffix)
                local clean_user=$(echo "$user_match" | sed -E 's/.*(user(name)?[=: ]+|[fF]or user )//i' | tr -d '"'\'')
                if [[ "$MODE" == "anonymize" ]]; then
                    local new_user=$(anonymize_username "$clean_user")
                    line=${line//$clean_user/$new_user}
                    log "Anonymized Username: $clean_user -> $new_user"
                elif [[ "$MODE" == "remove" ]]; then
                    line=${line//$clean_user/[REDACTED_USER]}
                    log "Removed Username: $clean_user"
                fi
            fi
        done < <(echo "$line" | grep -oEi '(user(name)?[=: ]+[a-zA-Z0-9._-]+|[fF]or user [a-zA-Z0-9._-]+)' | sort -u)
    fi

    # Process internal hostnames (optional)
    if [[ "$TARGET_HOSTNAMES" == true ]]; then
        while IFS= read -r host_match; do
            if [[ -n "$host_match" ]]; then
                if [[ "$MODE" == "anonymize" ]]; then
                    local new_host=$(anonymize_hostname "$host_match")
                    line=${line//$host_match/$new_host}
                    log "Anonymized Hostname: $host_match -> $new_host"
                elif [[ "$MODE" == "remove" ]]; then
                    line=${line//$host_match/[REDACTED_HOST]}
                    log "Removed Hostname: $host_match"
                fi
            fi
        done < <(echo "$line" | grep -oE '\b([a-zA-Z0-9-]+\.)+internal\b' | sort -u)
    fi

    echo "$line"
}

# ---------------------------------------------------------------------
# Main Script
# ---------------------------------------------------------------------

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--input)
            INPUT_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -m|--mode)
            MODE="$2"
            shift 2
            ;;
        --no-ips)
            TARGET_IPS=false
            shift
            ;;
        --no-emails)
            TARGET_EMAILS=false
            shift
            ;;
        --no-usernames)
            TARGET_USERNAMES=false
            shift
            ;;
        --hostnames)
            TARGET_HOSTNAMES=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Validate input
if [[ -z "$INPUT_FILE" ]]; then
    error "Input file is required. Use -i <file>"
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    error "Input file not found: $INPUT_FILE"
fi

if [[ ! -r "$INPUT_FILE" ]]; then
    error "Input file is not readable: $INPUT_FILE"
fi

# Validate mode
if [[ ! "$MODE" =~ ^(anonymize|remove|extract)$ ]]; then
    error "Invalid mode: $MODE. Use 'anonymize', 'remove', or 'extract'"
fi

# Set default output file
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="${INPUT_FILE%.*}_cleaned.${INPUT_FILE##*.}"
fi

# Counters
TOTAL_LINES=0
PROCESSED_LINES=0

echo -e "${GREEN}=== Log Cleaner & Anonymizer ===${NC}"
echo "Input file:  $INPUT_FILE"
echo "Output file: $OUTPUT_FILE"
echo "Mode:        $MODE"
echo "Targets:     IPS:$TARGET_IPS EMAILS:$TARGET_EMAILS USERS:$TARGET_USERNAMES HOSTS:$TARGET_HOSTNAMES"
echo

# Process file line by line
log "Starting processing..."

# Create a temporary file for safe processing
TEMP_FILE=$(mktemp)
trap 'rm -f "$TEMP_FILE"' EXIT

while IFS= read -r line; do
    TOTAL_LINES=$((TOTAL_LINES + 1))
    
    if [[ "$MODE" == "extract" ]]; then
        # Extract mode: only output lines containing target patterns
        if [[ "$TARGET_IPS" == true ]] && echo "$line" | grep -qE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b'; then
            echo "$line" >> "$TEMP_FILE"
            PROCESSED_LINES=$((PROCESSED_LINES + 1))
        elif [[ "$TARGET_EMAILS" == true ]] && echo "$line" | grep -qE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'; then
            echo "$line" >> "$TEMP_FILE"
            PROCESSED_LINES=$((PROCESSED_LINES + 1))
        elif [[ "$TARGET_USERNAMES" == true ]] && echo "$line" | grep -qiE '(user(name)?[=: ]+|[fF]or user )'; then
            echo "$line" >> "$TEMP_FILE"
            PROCESSED_LINES=$((PROCESSED_LINES + 1))
        elif [[ "$TARGET_HOSTNAMES" == true ]] && echo "$line" | grep -qE '\b([a-zA-Z0-9-]+\.)+internal\b'; then
            echo "$line" >> "$TEMP_FILE"
            PROCESSED_LINES=$((PROCESSED_LINES + 1))
        fi
    else
        # Anonymize or remove mode
        processed_line=$(process_line "$line")
        echo "$processed_line" >> "$TEMP_FILE"
        PROCESSED_LINES=$((PROCESSED_LINES + 1))
    fi
    
    # Progress indicator for large files
    if [[ "$VERBOSE" == true ]] && (( TOTAL_LINES % 1000 == 0 )); then
        echo -ne "\rProcessed: $TOTAL_LINES lines"
    fi
done < "$INPUT_FILE"

# Move temp file to output
mv "$TEMP_FILE" "$OUTPUT_FILE"

echo -e "\n${GREEN}[+] Processing complete.${NC}"
echo "    Total lines read:    $TOTAL_LINES"
if [[ "$MODE" == "extract" ]]; then
    echo "    Lines extracted:     $PROCESSED_LINES"
else
    echo "    Lines processed:     $PROCESSED_LINES"
fi
echo "    Output written to:   $OUTPUT_FILE"

# Show a sample of the result if verbose
if [[ "$VERBOSE" == true ]] && [[ -s "$OUTPUT_FILE" ]]; then
    echo -e "\n${YELLOW}--- Sample of cleaned output (first 5 lines) ---${NC}"
    head -n 5 "$OUTPUT_FILE"
    echo -e "${YELLOW}------------------------------------------------${NC}"
fi

exit 0
