# IR Collection Script
# By Mike Sayegh
# Version 2.0 - Enhanced with better error handling, logging, and verification
# Usage: ./ir_collection.sh

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Function to log commands and results
log_command() {
    local cmd="$1"
    local output_file="$2"
    local error_file="${output_file}.err"
    
    echo "Command: $cmd" >> "$output_file"
    echo "Timestamp: $(date)" >> "$output_file"
    echo "----------------------------------------" >> "$output_file"
    
    if eval "$cmd" >> "$output_file" 2>> "$error_file"; then
        print_status "Successfully executed: $cmd"
        # Remove error file if empty
        [ ! -s "$error_file" ] && rm -f "$error_file"
    else
        print_error "Failed to execute: $cmd"
        print_error "Check $error_file for details"
    fi
    
    echo -e "\n" >> "$output_file"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to copy file with verification
copy_with_verification() {
    local source="$1"
    local dest="$2"
    
    if [ -f "$source" ]; then
        if cp "$source" "$dest" 2>/dev/null; then
            print_status "Copied: $source"
            # Generate hash for verification
            if command_exists sha256sum; then
                sha256sum "$source" >> "$collect_dir/file_hashes.txt"
            fi
        else
            print_error "Failed to copy: $source"
        fi
    else
        print_warning "File not found: $source"
    fi
}

# Function to copy directory with verification
copy_dir_with_verification() {
    local source="$1"
    local dest="$2"
    
    if [ -d "$source" ]; then
        if cp -R "$source" "$dest" 2>/dev/null; then
            print_status "Copied directory: $source"
        else
            print_error "Failed to copy directory: $source"
        fi
    else
        print_warning "Directory not found: $source"
    fi
}

# Function to create case information file
create_case_info() {
    local case_file="$collect_dir/case_information.txt"
    
    cat > "$case_file" << EOF
=== CASE INFORMATION ===
Investigator Name: $investigator_name
Case Name: $case_name
Case Date: $case_date
Case Time: $case_time
Collection Start: $collection_start
Hostname: $(hostname)
Operating System: $(uname -a)
Current User: $(whoami)
Collection Directory: $location/$collect
Script Location: $location
Script Version: 2.0
===========================
EOF
}

# Function to check prerequisites
check_prerequisites() {
    print_section "Checking Prerequisites"
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_warning "Not running as root. Some data collection may be limited."
        read -p "Continue anyway? (y/n): " continue_choice
        if [[ ! $continue_choice =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check available disk space
    local available_space=$(df . | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 1000000 ]; then  # Less than ~1GB
        print_warning "Low disk space available: ${available_space}KB"
    fi
    
    # Check for required commands
    local required_commands=("netstat" "ss" "ps" "lsof" "find")
    for cmd in "${required_commands[@]}"; do
        if ! command_exists "$cmd"; then
            print_warning "Command not found: $cmd"
        fi
    done
}

# Main script starts here
clear
print_section "IR Collection Script v2.0"
echo 'This program collects critical volatile and non-volatile data'
echo 'Enhanced with better error handling, logging, and verification'
echo

# Get user confirmation
read -p 'Do you wish to continue? (y/n): ' c_answer
case $c_answer in
    [Yy]|[Yy][Ee][Ss]) 
        print_status "Starting collection process"
        ;;
    [Nn]|[Nn][Oo]) 
        print_status "Exiting at user request"
        exit 0
        ;;
    *) 
        print_error "Invalid response. Please answer yes or no"
        exit 1
        ;;
esac

# Collect case information
print_section "Case Information"
read -p 'Investigator Name: ' investigator_name
read -p 'Case Name: ' case_name
read -p 'Case Date (YYYY-MM-DD): ' case_date
read -p 'Case Time (HH:MM): ' case_time

# Set collection timestamp and location
collection_start=$(date)
location=$(pwd)

# Create collection directory
read -p 'Folder name to store collected data: ' collect
collect_dir="$location/$collect"

if [ -d "$collect_dir" ]; then
    print_warning "Directory '$collect' already exists"
    read -p "Overwrite? (y/n): " overwrite
    if [[ ! $overwrite =~ ^[Yy]$ ]]; then
        print_status "Exiting to prevent data loss"
        exit 1
    fi
    rm -rf "$collect_dir"
fi

# Create directory structure
mkdir -p "$collect_dir"/{volatile,non-volatile,logs,network,system}
print_status "Created collection directory: $collect_dir"

# Create subdirectories for organization
mkdir -p "$collect_dir/volatile"/{processes,memory,network}
mkdir -p "$collect_dir/non-volatile"/{files,configs}
mkdir -p "$collect_dir/logs"/{system,application,security}

# Check prerequisites
check_prerequisites

# Create case information file
create_case_info

# Start main collection
print_section "Starting Data Collection"
read -p 'Press Enter to continue...'

# Initialize log file
log_file="$collect_dir/collection.log"
echo "=== IR Collection Log ===" > "$log_file"
echo "Started: $collection_start" >> "$log_file"
echo "Investigator: $investigator_name" >> "$log_file"
echo "Case: $case_name" >> "$log_file"
echo "=========================" >> "$log_file"

# Collect volatile data
print_section "Collecting Volatile Data"

print_status "Collecting system date and time"
log_command "date" "$collect_dir/volatile/system_datetime.txt"

print_status "Recording hostname"
log_command "hostname" "$collect_dir/volatile/hostname.txt"

print_status "Collecting logged-in users"
log_command "who" "$collect_dir/volatile/logged_users.txt"
log_command "w" "$collect_dir/volatile/user_activity.txt"
log_command "last -20" "$collect_dir/volatile/recent_logins.txt"

print_status "Collecting process information"
log_command "ps auxf" "$collect_dir/volatile/processes/ps_auxf.txt"
log_command "ps -eo pid,ppid,cmd,%mem,%cpu --sort=-%mem" "$collect_dir/volatile/processes/ps_memory.txt"

print_status "Collecting network connections"
if command_exists netstat; then
    log_command "netstat -ano" "$collect_dir/volatile/network/netstat.txt"
    log_command "netstat -rn" "$collect_dir/volatile/network/routing_table.txt"
fi

if command_exists ss; then
    log_command "ss -tuln" "$collect_dir/volatile/network/ss_listening.txt"
    log_command "ss -tuap" "$collect_dir/volatile/network/ss_all.txt"
fi

print_status "Collecting network interface information"
log_command "ifconfig -a" "$collect_dir/volatile/network/ifconfig.txt"

if command_exists ip; then
    log_command "ip addr show" "$collect_dir/volatile/network/ip_addresses.txt"
    log_command "ip route show" "$collect_dir/volatile/network/ip_routes.txt"
fi

print_status "Collecting open files"
if command_exists lsof; then
    log_command "lsof" "$collect_dir/volatile/processes/open_files.txt"
fi

print_status "Collecting memory information"
log_command "free -h" "$collect_dir/volatile/memory/memory_usage.txt"
log_command "cat /proc/meminfo" "$collect_dir/volatile/memory/meminfo.txt"

# Collect non-volatile data
print_section "Collecting Non-Volatile Data"

print_status "Collecting system information"
log_command "uname -a" "$collect_dir/non-volatile/system_info.txt"
log_command "uptime" "$collect_dir/non-volatile/uptime.txt"
log_command "df -h" "$collect_dir/non-volatile/disk_usage.txt"
log_command "mount" "$collect_dir/non-volatile/mount_points.txt"

print_status "Collecting environment variables"
log_command "env" "$collect_dir/non-volatile/environment.txt"

print_status "Collecting file system information"
print_status "This may take a while for large file systems..."
log_command "find / -type f -name '*.log' -mtime -7 2>/dev/null | head -100" "$collect_dir/non-volatile/recent_logs.txt"

# Create directory listing with limited depth to avoid excessive output
print_status "Creating directory listing (limited depth)"
log_command "ls -la /" "$collect_dir/non-volatile/root_directory.txt"
log_command "find /etc -type f -name '*.conf' 2>/dev/null | head -50" "$collect_dir/non-volatile/config_files.txt"

# Copy important system files
print_section "Copying Important System Files"

print_status "Copying system configuration files"
copy_with_verification "/etc/passwd" "$collect_dir/non-volatile/passwd"
copy_with_verification "/etc/shadow" "$collect_dir/non-volatile/shadow" 2>/dev/null || print_warning "Could not copy /etc/shadow (requires root)"
copy_with_verification "/etc/group" "$collect_dir/non-volatile/group"
copy_with_verification "/etc/hosts" "$collect_dir/non-volatile/hosts"
copy_with_verification "/etc/resolv.conf" "$collect_dir/non-volatile/resolv.conf"

# Copy system logs
print_status "Copying system logs"
if [ -d "/var/log" ]; then
    # Copy recent logs only to manage size
    find /var/log -name "*.log" -mtime -7 -exec cp {} "$collect_dir/logs/system/" \; 2>/dev/null
    
    # Copy specific important logs
    important_logs=("auth.log" "syslog" "messages" "kern.log" "secure" "boot.log")
    for log in "${important_logs[@]}"; do
        if [ -f "/var/log/$log" ]; then
            copy_with_verification "/var/log/$log" "$collect_dir/logs/system/$log"
        fi
    done
    
    # Copy rotated logs (last 3 rotations)
    for i in {1..3}; do
        if [ -f "/var/log/auth.log.$i" ]; then
            copy_with_verification "/var/log/auth.log.$i" "$collect_dir/logs/system/"
        fi
        if [ -f "/var/log/syslog.$i" ]; then
            copy_with_verification "/var/log/syslog.$i" "$collect_dir/logs/system/"
        fi
    done
else
    print_warning "/var/log directory not found"
fi

# Collect system messages
print_status "Collecting system messages"
if command_exists dmesg; then
    log_command "dmesg" "$collect_dir/logs/system/dmesg.txt"
fi

# Collect cron jobs
print_status "Collecting cron jobs"
log_command "crontab -l" "$collect_dir/non-volatile/user_crontab.txt" 2>/dev/null || echo "No user crontab" > "$collect_dir/non-volatile/user_crontab.txt"
copy_with_verification "/etc/crontab" "$collect_dir/non-volatile/system_crontab"

if [ -d "/etc/cron.d" ]; then
    copy_dir_with_verification "/etc/cron.d" "$collect_dir/non-volatile/"
fi

# Collect startup services
print_status "Collecting startup services"
if command_exists systemctl; then
    log_command "systemctl list-units --type=service" "$collect_dir/non-volatile/systemd_services.txt"
    log_command "systemctl list-unit-files --type=service" "$collect_dir/non-volatile/systemd_service_files.txt"
elif command_exists service; then
    log_command "service --status-all" "$collect_dir/non-volatile/services.txt"
fi

# Collect SSH information
print_status "Collecting SSH information"
if [ -d "/etc/ssh" ]; then
    copy_with_verification "/etc/ssh/sshd_config" "$collect_dir/non-volatile/sshd_config"
fi

if [ -f "/root/.ssh/authorized_keys" ]; then
    copy_with_verification "/root/.ssh/authorized_keys" "$collect_dir/non-volatile/root_authorized_keys"
fi

# Check for user SSH keys
for user_home in /home/*; do
    if [ -d "$user_home/.ssh" ]; then
        username=$(basename "$user_home")
        mkdir -p "$collect_dir/non-volatile/ssh_keys/$username"
        if [ -f "$user_home/.ssh/authorized_keys" ]; then
            copy_with_verification "$user_home/.ssh/authorized_keys" "$collect_dir/non-volatile/ssh_keys/$username/"
        fi
    fi
done

# Collect network configuration
print_status "Collecting network configuration"
if [ -d "/etc/network" ]; then
    copy_dir_with_verification "/etc/network" "$collect_dir/non-volatile/"
fi

if [ -d "/etc/sysconfig/network-scripts" ]; then
    copy_dir_with_verification "/etc/sysconfig/network-scripts" "$collect_dir/non-volatile/"
fi

# Collect firewall rules
print_status "Collecting firewall information"
if command_exists iptables; then
    log_command "iptables -L -n -v" "$collect_dir/network/iptables_rules.txt"
    log_command "iptables -t nat -L -n -v" "$collect_dir/network/iptables_nat.txt"
fi

if command_exists ufw; then
    log_command "ufw status verbose" "$collect_dir/network/ufw_status.txt"
fi

# Collect installed packages
print_status "Collecting installed packages"
if command_exists dpkg; then
    log_command "dpkg -l" "$collect_dir/non-volatile/installed_packages_dpkg.txt"
elif command_exists rpm; then
    log_command "rpm -qa" "$collect_dir/non-volatile/installed_packages_rpm.txt"
elif command_exists pacman; then
    log_command "pacman -Q" "$collect_dir/non-volatile/installed_packages_pacman.txt"
fi

# Collect recent file modifications
print_status "Collecting recently modified files"
print_status "Searching for files modified in the last 7 days..."
log_command "find /etc /var /usr/local -type f -mtime -7 2>/dev/null | head -1000" "$collect_dir/non-volatile/recent_modifications.txt"

# Collect hash information
print_section "Generating File Hashes"
print_status "Generating hashes for collected evidence"

if command_exists sha256sum; then
    find "$collect_dir" -type f -name "*.txt" -o -name "*.log" -o -name "passwd" -o -name "group" -o -name "hosts" | \
    while read -r file; do
        sha256sum "$file" >> "$collect_dir/evidence_hashes.txt" 2>/dev/null
    done
    print_status "File hashes saved to evidence_hashes.txt"
fi

# Create collection summary
print_section "Creating Collection Summary"
summary_file="$collect_dir/collection_summary.txt"

cat > "$summary_file" << EOF
=== COLLECTION SUMMARY ===
Collection Start: $collection_start
Collection End: $(date)
Investigator: $investigator_name
Case Name: $case_name
Case Date: $case_date
Case Time: $case_time
Hostname: $(hostname)
Operating System: $(uname -a)
Collection Directory: $collect_dir
Script Version: 2.0

=== DIRECTORY STRUCTURE ===
$(tree "$collect_dir" 2>/dev/null || find "$collect_dir" -type d | sed 's/^/  /')

=== FILE COUNT ===
Total Files Collected: $(find "$collect_dir" -type f | wc -l)
Total Size: $(du -sh "$collect_dir" | cut -f1)

=== COLLECTION NOTES ===
- All commands were logged with timestamps
- File hashes were generated for verification
- Error files (.err) contain any command failures
- Limited log collection to last 7 days to manage size
- SSH keys and authorized_keys were collected where accessible

=== VERIFICATION ===
Collection completed successfully: $(date)
Investigator signature: ________________________
Date: ___________
EOF

# Final status
print_section "Collection Complete"
print_status "Data collection completed successfully"
print_status "Evidence location: $collect_dir"
print_status "Collection log: $log_file"
print_status "Collection summary: $summary_file"

if [ -f "$collect_dir/evidence_hashes.txt" ]; then
    print_status "Evidence hashes: $collect_dir/evidence_hashes.txt"
fi

echo
print_status "Total files collected: $(find "$collect_dir" -type f | wc -l)"
print_status "Total collection size: $(du -sh "$collect_dir" | cut -f1)"

echo
echo -e "${GREEN}Collection completed at: $(date)${NC}"
echo -e "${BLUE}Please review the collection summary and verify the evidence integrity.${NC}"

# Optional: Create compressed archive
read -p "Create compressed archive of collected evidence? (y/n): " create_archive
if [[ $create_archive =~ ^[Yy]$ ]]; then
    archive_name="${collect}_$(date +%Y%m%d_%H%M%S).tar.gz"
    print_status "Creating compressed archive: $archive_name"
    
    if tar -czf "$archive_name" -C "$location" "$collect"; then
        print_status "Archive created successfully: $archive_name"
        if command_exists sha256sum; then
            sha256sum "$archive_name" > "${archive_name}.sha256"
            print_status "Archive hash saved: ${archive_name}.sha256"
        fi
    else
        print_error "Failed to create archive"
    fi
fi

print_status "Script execution completed"
exit 0
