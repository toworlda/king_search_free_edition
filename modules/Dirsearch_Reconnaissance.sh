#!/bin/bash

# 🏆 King Search: Advanced Web Reconnaissance Toolkit 🕵️‍♂️
# Comprehensive Scanning Without External Dependencies

# Base Configurations
SCRIPT_VERSION="3.0.0"
BASE_DIR="${HOME}/king_search"
REPORT_DIR="${BASE_DIR}/Reports/Pentesting"
LOG_DIR="${BASE_DIR}/Reports/Logs"
WORDLIST_DIR="${BASE_DIR}/payload"

# Color Palette
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Advanced Configuration
TARGET="${1:-}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCAN_DEPTH=3
MAX_RETRY=3
TIMEOUT=10

# Comprehensive Wordlists (Embedded)
WORDLISTS=(
    "swagger-wordlist.txt"
    "httparchive_php.txt"
    "httparchive_txt.txt"
    "httparchive_xml.txt"
    "jsp.txt"
    "httparchive_js.txt"
    "html_htm.txt"
    "apiroutes.txt"
    "aspx_asp_cfm_svc_ashx_asmx.txt"
    "directories.txt"
)

# Custom User-Agent Pool
USER_AGENTS=(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
)

# Predefined Headers for Evasion
CUSTOM_HEADERS=(
    "X-Forwarded-For: 127.0.0.1"
    "X-Originating-IP: 127.0.0.1"
    "X-Remote-IP: 127.0.0.1"
    "X-Remote-Addr: 127.0.0.1"
)

# Setup Function
setup_environment() {
    echo -e "${BLUE}[*] Setting up King Search Environment${NC}"
    
    # Create necessary directories
    mkdir -p "${BASE_DIR}"
    mkdir -p "${REPORTS_DIR}"
    mkdir -p "${LOG_DIR}"
    mkdir -p "${WORDLIST_DIR}"

    # Create embedded wordlists if not exist
    create_wordlists
}

# Create Embedded Wordlists
create_wordlists() {
    # Common Web Directories
    #cat > "${WORDLIST_DIR}/swagger-wordlist.txt" << EOL
EOL

    # Large Web Directories
    #cat > "${WORDLIST_DIR}/httparchive_php.txt" << EOL
EOL

    # API Endpoints
    #cat > "${WORDLIST_DIR}/directories.txt" << EOL
EOL

    # Backup Files
    #cat > "${WORDLIST_DIR}/httparchive_js.txt" << EOL
EOL

    # Sensitive Files
    cat > "${WORDLIST_DIR}/apiroutes.txt" << EOL
EOL
}

# Logging Function
log_event() {
    local level="$1"
    local message="$2"
    local log_file="${LOG_DIR}/${TIMESTAMP}_king_search.log"
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$log_file")"
    
    # Log to file and console
    case "$level" in
        "INFO")
            echo -e "${BLUE}[*] $message${NC}" | tee -a "$log_file"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[+] $message${NC}" | tee -a "$log_file"
            ;;
        "WARNING")
            echo -e "${YELLOW}[!] $message${NC}" | tee -a "$log_file"
            ;;
        "ERROR")
            echo -e "${RED}[-] $message${NC}" | tee -a "$log_file"
            ;;
    esac
}

# Advanced URL Parsing
parse_url() {
    local url="$1"
    local proto=$(echo "$url" | grep "://" | sed -e's,^\(.*://\).*,\1,g')
    local url_without_proto=$(echo "${url/$proto/}")
    local domain=$(echo "$url_without_proto" | cut -d/ -f1)
    
    echo "$domain"
}

# Generate Random User-Agent
random_user_agent() {
    echo "${USER_AGENTS[$RANDOM % ${#USER_AGENTS[@]}]}"
}

# Advanced Directory Brute Force
advanced_dir_bruteforce() {
    local target="$1"
    local domain=$(parse_url "$target")
    local output_base="${REPORT_DIR}/${domain}_${TIMESTAMP}"
    
    log_event "INFO" "Starting advanced directory brute force on ${target}"
    
    # Prepare output directories
    mkdir -p "$output_base"
    
    # Parallel scanning with different techniques
    for wordlist in "${WORDLIST_DIR}"/*.txt; do
        (
            # Custom curl-based scanning with advanced headers
            while IFS= read -r path; do
                local full_url="${target}/${path}"
                local user_agent=$(random_user_agent)
                
                # Advanced request with multiple headers and techniques
                response=$(curl -s -k \
                    -A "$user_agent" \
                    -H "X-Requested-With: XMLHttpRequest" \
                    -H "Referer: ${target}" \
                    "${CUSTOM_HEADERS[@]/#/-H }" \
                    -m "$TIMEOUT" \
                    -o /dev/null \
                    -w "%{http_code}" \
                    "$full_url")
                
                # Filter out 404, 403, 500 status codes
                if [[ "$response" != "404" ]] && 
                   [[ "$response" != "403" ]] && 
                   [[ "$response" != "500" ]]; then
                    echo "[${response}] ${full_url}" >> "${output_base}/discovered_paths.txt"
                fi
            done < "$wordlist"
        ) &
    done
    
    # Wait for all background jobs
    wait
    
    log_event "SUCCESS" "Directory brute force completed. Results in ${output_base}"
}

# WAF/Security Detection
detect_security_measures() {
    local target="$1"
    local output_file="${REPORT_DIR}/security_detection_${TIMESTAMP}.txt"
    
    log_event "INFO" "Detecting security measures for ${target}"
    
    # Perform multiple checks
    {
        echo "=== Security Detection Report ==="
        echo "Target: $target"
        echo "Timestamp: $(date)"
        echo ""
        
        # Check server headers
        echo "=== Server Headers ==="
        curl -sI "$target" | grep -E "Server:|X-Powered-By:|X-AspNet-Version:|X-Generator:"
        
        # Check for common security headers
        echo ""
        echo "=== Security Headers ==="
        curl -sI "$target" | grep -E "Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-XSS-Protection"
        
        # Basic WAF detection via response behavior
        echo ""
        echo "=== Potential WAF Indicators ==="
        status_code=$(curl -s -o /dev/null -w "%{http_code}" "$target")
        echo "Base Response Status: ${status_code}"
    } > "$output_file"
    
    log_event "SUCCESS" "Security detection report generated: ${output_file}"
}

# Main Execution
main() {
    # Validate input
    if [ -z "$TARGET" ]; then
        log_event "ERROR" "Usage: $0 <target_url>"
        exit 1
    fi
    
    # Setup environment
    setup_environment
    
    # Start reconnaissance
    log_event "INFO" "🏆 King Search Reconnaissance v${SCRIPT_VERSION}"
    
    # Perform advanced scans
    advanced_dir_bruteforce "$TARGET"
    detect_security_measures "$TARGET"
    
    log_event "SUCCESS" "Reconnaissance completed for ${TARGET}"
}

# Error trapping
trap 'log_event "ERROR" "Unexpected error at line $LINENO"' ERR

# Execute main function
main "$@"
