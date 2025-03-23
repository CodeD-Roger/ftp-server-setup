#!/bin/bash

# ******************************************************************************
# Secure FTP Server Setup Script
# Description: Installs and configures vsftpd with enhanced security settings,
#              fail2ban and iptables. Includes user management with automatic
#              secure password generation.
# ******************************************************************************

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
RESET='\033[0m'

# Global configuration variables
LOG_FILE="/var/log/ftp_setup.log"
CONFIG_BACKUP_DIR="/etc/vsftpd/backups"
VSFTPD_CONF="/etc/vsftpd.conf"
VSFTPD_USER_LIST="/etc/vsftpd.userlist"
CUSTOM_CONFIG_FILE="/etc/ftp_server_setup.conf"
FTP_DATA_PORT_MIN=30000
FTP_DATA_PORT_MAX=31000
FTP_PORT=21
FTP_PASV_PORT=990

# Function to log messages
log() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
    # Display error messages in red
    if [[ "$level" == "ERROR" ]]; then
        echo -e "${RED}[$level] $message${RESET}"
    elif [[ "$level" == "SUCCESS" ]]; then
        echo -e "${GREEN}[$level] $message${RESET}"
    elif [[ "$level" == "WARNING" ]]; then
        echo -e "${YELLOW}[$level] $message${RESET}"
    else
        echo -e "[$level] $message"
    fi
}

# Function to check for root privileges
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "This script must be run as root" "ERROR"
        echo -e "${RED}This script must be run as root.${RESET}"
        echo -e "Please use: ${YELLOW}sudo $0${RESET}"
        exit 1
    fi
    log "Root privilege check: OK"
}

# Function to create a directory if it doesn't exist
create_directory() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir"
        log "Created directory $dir" "SUCCESS"
    fi
}

# Function to backup a configuration file
backup_config() {
    local file="$1"
    local backup_file="$CONFIG_BACKUP_DIR/$(basename "$file").$(date +%Y%m%d%H%M%S).bak"
    
    create_directory "$CONFIG_BACKUP_DIR"
    
    if [[ -f "$file" ]]; then
        cp "$file" "$backup_file"
        log "Backed up $file to $backup_file" "SUCCESS"
    else
        log "File $file doesn't exist, skipping backup" "WARNING"
    fi
}

# Function to restore a configuration file
restore_config() {
    local file="$1"
    local backup_file="$2"
    
    if [[ -f "$backup_file" ]]; then
        cp "$backup_file" "$file"
        log "Restored $file from $backup_file" "SUCCESS"
        return 0
    else
        log "Backup file $backup_file not found" "ERROR"
        return 1
    fi
}

# Function to check if a package is installed
is_package_installed() {
    local package="$1"
    if command -v "$package" > /dev/null 2>&1; then
        return 0  # Package installed
    else
        return 1  # Package not installed
    fi
}

# Function to handle APT locks
handle_apt_lock() {
    local force_remove=$1
    local lock_files=(
        "/var/lib/apt/lists/lock"
        "/var/lib/dpkg/lock"
        "/var/lib/dpkg/lock-frontend"
        "/var/cache/apt/archives/lock"
    )
    local lock_processes=()
    local locked=false
    
    # Check each lock file
    for lock_file in "${lock_files[@]}"; do
        if [ -f "$lock_file" ]; then
            local pids=$(lsof "$lock_file" 2>/dev/null | grep -v "^COMMAND" | awk '{print $2}')
            if [ -n "$pids" ]; then
                locked=true
                for pid in $pids; do
                    local process_name=$(ps -p $pid -o comm= 2>/dev/null)
                    if [ -n "$process_name" ]; then
                        lock_processes+=("$pid:$process_name")
                        echo -e "${YELLOW}Lock detected: $lock_file is used by $process_name (PID: $pid)${RESET}"
                    fi
                done
            elif [ "$force_remove" = "true" ]; then
                echo -e "${YELLOW}Removing orphaned lock file: $lock_file${RESET}"
                sudo rm -f "$lock_file"
            fi
        fi
    done
    
    # If lock processes were found
    if [ ${#lock_processes[@]} -gt 0 ] && [ "$force_remove" = "true" ]; then
        echo -e "${YELLOW}Attempting to stop lock processes...${RESET}"
        for process in "${lock_processes[@]}"; do
            local pid=${process%%:*}
            local name=${process#*:}
            echo -e "${YELLOW}Stopping $name (PID: $pid)${RESET}"
            sudo kill -15 $pid 2>/dev/null
            sleep 2
            if ps -p $pid > /dev/null 2>&1; then
                echo -e "${RED}Process $name (PID: $pid) not responding, using SIGKILL...${RESET}"
                sudo kill -9 $pid 2>/dev/null
            fi
        done
        
        # Remove lock files after killing processes
        for lock_file in "${lock_files[@]}"; do
            if [ -f "$lock_file" ]; then
                echo -e "${YELLOW}Removing lock file: $lock_file${RESET}"
                sudo rm -f "$lock_file"
            fi
        done
        
        echo -e "${GREEN}All locks have been removed${RESET}"
        return 0
    elif $locked; then
        return 1
    else
        return 0
    fi
}

# Function to install a package with lock handling
install_package() {
    local package="$1"
    local max_attempts=3
    local attempt=1
    
    if is_package_installed "$package"; then
        log "Package $package is already installed" "INFO"
        return 0
    fi
    
    log "Installing package $package..." "INFO"
    
    while [ $attempt -le $max_attempts ]; do
        if ! handle_apt_lock "false"; then
            echo -e "${YELLOW}Attempt $attempt/$max_attempts: Waiting for package manager to be released...${RESET}"
            
            if [ $attempt -eq $max_attempts ]; then
                echo -e "\n${RED}Package manager is still locked after $max_attempts attempts.${RESET}"
                echo -e "${YELLOW}Options to resolve this issue:${RESET}"
                echo -e "1. ${CYAN}Wait for system update processes to complete${RESET}"
                echo -e "2. ${CYAN}Force removal of locks (may be risky):${RESET}"
                
                read -p "Do you want to attempt forced lock removal? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    echo -e "${YELLOW}Attempting forced lock removal...${RESET}"
                    sudo systemctl stop packagekit 2>/dev/null
                    sudo systemctl stop unattended-upgrades 2>/dev/null
                    sudo systemctl stop apt-daily.service 2>/dev/null
                    sudo systemctl stop apt-daily-upgrade.service 2>/dev/null
                    
                    if handle_apt_lock "true"; then
                        echo -e "${GREEN}Locks successfully removed, resuming installation...${RESET}"
                        sleep 2
                    else
                        log "Failed to install package $package - Unable to remove locks" "ERROR"
                        return 1
                    fi
                else
                    log "Failed to install package $package - package manager locked" "ERROR"
                    return 1
                fi
            else
                sleep 10
                attempt=$((attempt + 1))
                continue
            fi
        fi
        
        echo -e "${CYAN}Updating package lists...${RESET}"
        if ! apt-get update -qq; then
            log "Failed to update packages" "ERROR"
            return 1
        fi
        
        echo -e "${CYAN}Installing $package...${RESET}"
        if apt-get install -y "$package"; then
            log "Successfully installed package $package" "SUCCESS"
            return 0
        else
            log "Failed to install package $package" "ERROR"
            return 1
        fi
    done
    
    return 1
}

# Function to install required dependencies
install_dependencies() {
    local packages=("vsftpd" "fail2ban" "iptables" "openssl" "pwgen")
    
    log "Installing dependencies..." "INFO"
    
    # First update and upgrade the system
    echo -e "${CYAN}Updating system packages...${RESET}"
    apt-get update -y
    apt-get upgrade -y
    
    for package in "${packages[@]}"; do
        if ! install_package "$package"; then
            log "Failed to install dependencies" "ERROR"
            return 1
        fi
    done
    
    log "All dependencies successfully installed" "SUCCESS"
    return 0
}

# Function to generate a self-signed SSL certificate
generate_ssl_cert() {
    local ssl_dir="/etc/ssl/private"
    local cert_file="$ssl_dir/vsftpd.pem"
    
    create_directory "$ssl_dir"
    
    if [[ -f "$cert_file" ]]; then
        log "SSL certificate already exists at $cert_file" "INFO"
        read -p "Do you want to generate a new certificate? (y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "SSL certificate generation cancelled" "INFO"
            return 0
        fi
    fi
    
    log "Generating self-signed SSL certificate..." "INFO"
    
    # Generate a self-signed SSL certificate valid for 365 days
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$cert_file" -out "$cert_file" \
        -subj "/C=US/ST=State/L=City/O=FTP Server/CN=localhost" 2>/dev/null
    
    if [[ $? -eq 0 && -f "$cert_file" ]]; then
        chmod 600 "$cert_file"
        log "Self-signed SSL certificate successfully generated at $cert_file" "SUCCESS"
        return 0
    else
        log "Failed to generate SSL certificate" "ERROR"
        return 1
    fi
}

# Function to configure vsftpd
configure_vsftpd() {
    log "Configuring vsftpd..." "INFO"
    
    # Backup existing configuration
    backup_config "$VSFTPD_CONF"
    
    # Get server IP address
    local server_ip=$(/sbin/ip -o -4 addr list | grep -v "127.0.0.1" | awk '{print $4}' | cut -d/ -f1 | head -n1)
    
    # Create a new configuration
    cat > "$VSFTPD_CONF" << EOF
# vsftpd Configuration - Automatically generated

# Basic options
listen=YES
listen_ipv6=NO
connect_from_port_20=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
xferlog_std_format=YES
xferlog_file=/var/log/vsftpd.log
dual_log_enable=YES
log_ftp_protocol=YES

# Security parameters
chroot_local_user=YES
chroot_list_enable=NO
allow_writeable_chroot=YES
hide_ids=YES
ssl_enable=YES
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
force_local_logins_ssl=NO
force_local_data_ssl=NO

# Timeout parameters
idle_session_timeout=600
data_connection_timeout=120

# Passive FTP parameters
pasv_enable=YES
pasv_min_port=$FTP_DATA_PORT_MIN
pasv_max_port=$FTP_DATA_PORT_MAX
pasv_address=$server_ip

# Additional options
seccomp_sandbox=NO
pam_service_name=vsftpd
userlist_enable=YES
userlist_file=$VSFTPD_USER_LIST
userlist_deny=NO
EOF
    
    # Create the authorized users list if it doesn't exist
    if [[ ! -f "$VSFTPD_USER_LIST" ]]; then
        touch "$VSFTPD_USER_LIST"
        log "Created user list file $VSFTPD_USER_LIST" "INFO"
    fi
    
    # Configure PAM for vsftpd
    echo -e "${CYAN}Configuring PAM for vsftpd...${RESET}"
    cat > /etc/pam.d/vsftpd << EOF
# Standard behavior for ftpd(8).
auth    required        pam_unix.so nullok
account required        pam_unix.so
session required        pam_unix.so
EOF
    
    log "vsftpd configuration completed" "SUCCESS"
}

# Function to configure fail2ban
configure_fail2ban() {
    log "Configuring fail2ban for vsftpd..." "INFO"
    
    local jail_file="/etc/fail2ban/jail.d/vsftpd.conf"
    local filter_file="/etc/fail2ban/filter.d/vsftpd.conf"
    
    # Backup existing configuration
    if [[ -f "$jail_file" ]]; then
        backup_config "$jail_file"
    fi
    
    # Create fail2ban filter for vsftpd
    cat > "$filter_file" << EOF
[Definition]
failregex = (?i)FAIL.*LOGIN.*:\s*Authentication failure for .* from <HOST>
            (?i)FAIL.*LOGIN.*:\s*Maximum login attempts exceeded for .* from <HOST>
ignoreregex =
EOF
    
    # Create jail configuration for vsftpd
    cat > "$jail_file" << EOF
[vsftpd]
enabled = true
port = $FTP_PORT,$FTP_PASV_PORT
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = 3
bantime = 3600
findtime = 600
EOF
    
    # Restart fail2ban
    if systemctl is-active --quiet fail2ban; then
        systemctl restart fail2ban
        log "fail2ban service restarted" "SUCCESS"
    else
        systemctl enable fail2ban
        systemctl start fail2ban
        log "fail2ban service started" "SUCCESS"
    fi
    
    log "fail2ban configuration for vsftpd completed" "SUCCESS"
}

# Function to configure iptables
configure_iptables() {
    log "Configuring iptables rules for vsftpd..." "INFO"
    
    # Add rules for FTP server
    iptables -A INPUT -p tcp --dport $FTP_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $FTP_PASV_PORT -j ACCEPT
    iptables -A INPUT -p tcp --dport $FTP_DATA_PORT_MIN:$FTP_DATA_PORT_MAX -j ACCEPT
    
    # Save iptables rules to persist after reboot
    if which iptables-save > /dev/null 2>&1; then
        iptables-save > /etc/iptables.rules
        
        # Create a script to restore rules at startup
        cat > /etc/network/if-pre-up.d/iptables << EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
exit 0
EOF
        chmod +x /etc/network/if-pre-up.d/iptables
        
        log "iptables rules saved and restoration script created" "SUCCESS"
    else
        log "iptables-save command not available, rules will not persist" "WARNING"
    fi
    
    log "iptables rules configuration for vsftpd completed" "SUCCESS"
}

# Function to generate a secure password
generate_secure_password() {
    local length=16
    
    # Check if pwgen is installed
    if command -v pwgen > /dev/null 2>&1; then
        # Generate a secure password with pwgen
        password=$(pwgen -s -y $length 1)
    else
        # Fallback to using /dev/urandom if pwgen is not available
        password=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+' < /dev/urandom | head -c $length)
    fi
    
    echo "$password"
}

# Function to diagnose user management tools
diagnose_user_tools() {
    echo -e "${YELLOW}Diagnosing user management tools...${RESET}"
    
    # Check for common user management commands
    echo -e "Checking for useradd: $(which useradd 2>/dev/null || echo 'Not found')"
    echo -e "Checking for adduser: $(which adduser 2>/dev/null || echo 'Not found')"
    echo -e "Checking for passwd: $(which passwd 2>/dev/null || echo 'Not found')"
    echo -e "Checking for chpasswd: $(which chpasswd 2>/dev/null || echo 'Not found')"
    
    # Check if we're in a container
    if [ -f /.dockerenv ] || grep -q 'docker\|lxc' /proc/1/cgroup; then
        echo -e "${YELLOW}Running in a container environment${RESET}"
    fi
    
    # Check PATH
    echo -e "Current PATH: $PATH"
    
    # Try to find the commands in common locations
    for cmd in useradd adduser; do
        if ! which $cmd > /dev/null 2>&1; then
            for path in /usr/sbin /sbin /usr/bin /bin; do
                if [ -x "$path/$cmd" ]; then
                    echo -e "${GREEN}Found $cmd at $path/$cmd${RESET}"
                    echo -e "${YELLOW}Adding $path to PATH${RESET}"
                    export PATH="$PATH:$path"
                    break
                fi
            done
        fi
    done
    
    # Check if we need to install user management tools
    if ! which useradd > /dev/null 2>&1 && ! which adduser > /dev/null 2>&1; then
        echo -e "${YELLOW}Installing user management tools...${RESET}"
        apt-get update -y
        apt-get install -y passwd
    fi
}

# Function to add an FTP user with a secure password
add_ftp_user() {
    local username="$1"
    local password="$2"
    local home_dir="$3"
    local generate_pwd="$4"
    
    # Generate a secure password if requested
    if [[ "$generate_pwd" == "yes" ]]; then
        password=$(generate_secure_password)
        echo -e "${GREEN}Generated secure password for $username: ${CYAN}$password${RESET}"
        echo -e "${YELLOW}Please save this password securely!${RESET}"
    fi
    
    # Check if user already exists
    if grep -q "^$username:" /etc/passwd 2>/dev/null; then
        log "User $username already exists" "WARNING"
        return 1
    fi
    
    # Create home directory if it doesn't exist
    if [ ! -d "$home_dir" ]; then
        mkdir -p "$home_dir"
        log "Created home directory $home_dir" "INFO"
    fi
    
    # Make sure PATH includes common locations for user management tools
    export PATH="$PATH:/usr/sbin:/sbin:/usr/bin:/bin"
    
    # Check if user management tools are available
    if ! command -v useradd > /dev/null 2>&1 && ! command -v adduser > /dev/null 2>&1; then
        diagnose_user_tools
    fi
    
    # Try to create user with useradd
    if command -v useradd > /dev/null 2>&1; then
        echo -e "${CYAN}Creating user with useradd...${RESET}"
        useradd -m -d "$home_dir" -s /bin/false "$username"
        user_created=$?
        
        if [ $user_created -eq 0 ]; then
            # Set password - improved method for handling special characters
            if command -v chpasswd > /dev/null 2>&1; then
                # Create a temporary file with the password
                local temp_pwd_file=$(mktemp)
                echo "$username:$password" > "$temp_pwd_file"
                chpasswd < "$temp_pwd_file"
                rm -f "$temp_pwd_file"
            elif command -v passwd > /dev/null 2>&1; then
                # Alternative method for setting password
                local temp_pwd_file=$(mktemp)
                echo "$password" > "$temp_pwd_file"
                echo "$password" >> "$temp_pwd_file"
                passwd "$username" < "$temp_pwd_file" > /dev/null 2>&1
                rm -f "$temp_pwd_file"
            fi
            log "User $username created with useradd" "SUCCESS"
        else
            log "Failed to create user with useradd (error code: $user_created)" "WARNING"
        fi
    # Try to create user with adduser if useradd failed or isn't available
    elif command -v adduser > /dev/null 2>&1; then
        echo -e "${CYAN}Creating user with adduser...${RESET}"
        adduser --quiet --home "$home_dir" --shell /bin/false --disabled-password "$username"
        user_created=$?
        
        if [ $user_created -eq 0 ]; then
            # Set password - improved method for handling special characters
            if command -v chpasswd > /dev/null 2>&1; then
                # Create a temporary file with the password
                local temp_pwd_file=$(mktemp)
                echo "$username:$password" > "$temp_pwd_file"
                chpasswd < "$temp_pwd_file"
                rm -f "$temp_pwd_file"
            elif command -v passwd > /dev/null 2>&1; then
                # Alternative method for setting password
                local temp_pwd_file=$(mktemp)
                echo "$password" > "$temp_pwd_file"
                echo "$password" >> "$temp_pwd_file"
                passwd "$username" < "$temp_pwd_file" > /dev/null 2>&1
                rm -f "$temp_pwd_file"
            fi
            log "User $username created with adduser" "SUCCESS"
        else
            log "Failed to create user with adduser (error code: $user_created)" "WARNING"
        fi
    else
        log "No user creation command found after diagnosis" "ERROR"
        return 1
    fi
    
    # Add user to the authorized users list
    echo "$username" >> "$VSFTPD_USER_LIST"
    
    # Set home directory permissions
    chown -R "$username":"$username" "$home_dir" 2>/dev/null || {
        # If group doesn't exist, try just with user
        chown -R "$username" "$home_dir" 2>/dev/null || {
            log "Unable to change owner of directory $home_dir" "WARNING"
        }
    }
    
    chmod 750 "$home_dir" 2>/dev/null || {
        log "Unable to change permissions of directory $home_dir" "WARNING"
    }
    
    log "FTP user $username successfully created" "SUCCESS"
    
    # Display connection information for FileZilla
    echo -e "\n${CYAN}=== FileZilla Connection Information ===${RESET}"
    echo -e "${GREEN}Host:${RESET} $(/sbin/ip -o -4 addr list | grep -v "127.0.0.1" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    echo -e "${GREEN}Port:${RESET} $FTP_PORT"
    echo -e "${GREEN}Protocol:${RESET} FTP - File Transfer Protocol"
    echo -e "${GREEN}Encryption:${RESET} Require explicit FTP over TLS"
    echo -e "${GREEN}Logon Type:${RESET} Normal"
    echo -e "${GREEN}User:${RESET} $username"
    echo -e "${GREEN}Password:${RESET} $password"
    
    return 0
}

# Function to delete an FTP user
delete_ftp_user() {
    local username="$1"
    local keep_home="$2"
    
    # Check if user exists
    if ! id -u "$username" > /dev/null 2>&1; then
        log "User $username does not exist" "ERROR"
        return 1
    fi
    
    # Get user's home directory before deleting
    local home_dir=$(getent passwd "$username" | cut -d: -f6)
    
    # Remove user from the authorized users list
    if [[ -f "$VSFTPD_USER_LIST" ]]; then
        sed -i "/^$username$/d" "$VSFTPD_USER_LIST"
        log "Removed $username from authorized users list" "INFO"
    fi
    
    # Delete the user
    if [[ "$keep_home" == "yes" ]]; then
        userdel "$username"
        log "User $username deleted (home directory preserved)" "SUCCESS"
    else
        userdel -r "$username"
        log "User $username deleted with home directory" "SUCCESS"
    fi
    
    return 0
}

# Function to change user password
change_user_password() {
    local username="$1"
    local password="$2"
    local generate_pwd="$3"
    
    # Check if user exists
    if ! id -u "$username" > /dev/null 2>&1; then
        log "User $username does not exist" "ERROR"
        return 1
    fi
    
    # Generate a secure password if requested
    if [[ "$generate_pwd" == "yes" ]]; then
        password=$(generate_secure_password)
        echo -e "${GREEN}Generated secure password for $username: ${CYAN}$password${RESET}"
        echo -e "${YELLOW}Please save this password securely!${RESET}"
    fi
    
    # Set the new password
    if command -v chpasswd > /dev/null 2>&1; then
        # Create a temporary file with the password
        local temp_pwd_file=$(mktemp)
        echo "$username:$password" > "$temp_pwd_file"
        chpasswd < "$temp_pwd_file"
        rm -f "$temp_pwd_file"
    elif command -v passwd > /dev/null 2>&1; then
        # Alternative method for setting password
        local temp_pwd_file=$(mktemp)
        echo "$password" > "$temp_pwd_file"
        echo "$password" >> "$temp_pwd_file"
        passwd "$username" < "$temp_pwd_file" > /dev/null 2>&1
        rm -f "$temp_pwd_file"
    else
        log "No password change command found" "ERROR"
        return 1
    fi
    
    log "Password for user $username successfully changed" "SUCCESS"
    
    # Display updated connection information for FileZilla
    echo -e "\n${CYAN}=== Updated FileZilla Connection Information ===${RESET}"
    echo -e "${GREEN}Host:${RESET} $(/sbin/ip -o -4 addr list | grep -v "127.0.0.1" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
    echo -e "${GREEN}Port:${RESET} $FTP_PORT"
    echo -e "${GREEN}Protocol:${RESET} FTP - File Transfer Protocol"
    echo -e "${GREEN}Encryption:${RESET} Require explicit FTP over TLS"
    echo -e "${GREEN}Logon Type:${RESET} Normal"
    echo -e "${GREEN}User:${RESET} $username"
    echo -e "${GREEN}Password:${RESET} $password"
    
    return 0
}

# Function to list FTP users
list_ftp_users() {
    log "Listing authorized FTP users:" "INFO"
    
    if [[ -f "$VSFTPD_USER_LIST" ]]; then
        if [[ -s "$VSFTPD_USER_LIST" ]]; then
            echo -e "${CYAN}Authorized FTP users:${RESET}"
            cat "$VSFTPD_USER_LIST" | while read user; do
                if id -u "$user" > /dev/null 2>&1; then
                    echo -e "${GREEN}- $user${RESET} (active)"
                else
                    echo -e "${RED}- $user${RESET} (non-existent)"
                fi
            done
        else
            echo -e "${YELLOW}No authorized FTP users found${RESET}"
        fi
    else
        echo -e "${RED}User list file $VSFTPD_USER_LIST not found${RESET}"
    fi
}

# Function to modify user permissions
modify_user_permissions() {
    local username="$1"
    local permission="$2"
    
    # Check if user exists
    if ! id -u "$username" > /dev/null 2>&1; then
        log "User $username does not exist" "ERROR"
        return 1
    fi
    
    # Get user's home directory
    local home_dir=$(getent passwd "$username" | cut -d: -f6)
    
    case "$permission" in
        "read-only")
            # Remove write permissions for the user
            chmod u-w "$home_dir"
            log "Set read-only permissions for user $username" "SUCCESS"
            echo -e "${GREEN}User $username now has read-only access${RESET}"
            ;;
        "read-write")
            # Add write permissions for the user
            chmod u+w "$home_dir"
            log "Set read-write permissions for user $username" "SUCCESS"
            echo -e "${GREEN}User $username now has read-write access${RESET}"
            ;;
        *)
            log "Invalid permission type: $permission" "ERROR"
            echo -e "${RED}Invalid permission type. Use 'read-only' or 'read-write'${RESET}"
            return 1
            ;;
    esac
    
    return 0
}

# Function to change user's access path
change_user_path() {
    local username="$1"
    local new_path="$2"
    
    # Check if user exists
    if ! id -u "$username" > /dev/null 2>&1; then
        log "User $username does not exist" "ERROR"
        return 1
    fi
    
    # Check if new path exists, create if it doesn't
    if [ ! -d "$new_path" ]; then
        read -p "Path $new_path does not exist. Create it? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            mkdir -p "$new_path"
            log "Created directory $new_path" "INFO"
        else
            log "Operation cancelled - path does not exist" "WARNING"
            return 1
        fi
    fi
    
    # Get current home directory
    local old_home=$(getent passwd "$username" | cut -d: -f6)
    
    # Use usermod to change the home directory
    if command -v usermod > /dev/null 2>&1; then
        usermod -d "$new_path" "$username"
        
        # Check if we should move the contents
        if [ -d "$old_home" ] && [ "$old_home" != "$new_path" ]; then
            read -p "Move contents from $old_home to $new_path? (y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Create the directory if it doesn't exist
                mkdir -p "$new_path"
                
                # Copy contents
                cp -a "$old_home/." "$new_path/"
                log "Copied contents from $old_home to $new_path" "INFO"
            fi
        fi
        
        # Set ownership
        chown -R "$username":"$username" "$new_path" 2>/dev/null || {
            # If group doesn't exist, try just with user
            chown -R "$username" "$new_path" 2>/dev/null || {
                log "Unable to change owner of directory $new_path" "WARNING"
            }
        }
        
        chmod 750 "$new_path" 2>/dev/null || {
            log "Unable to change permissions of directory $new_path" "WARNING"
        }
        
        log "Changed access path for user $username to $new_path" "SUCCESS"
        echo -e "${GREEN}User $username access path changed to $new_path${RESET}"
    else
        log "usermod command not found" "ERROR"
        return 1
    fi
    
    return 0
}

# Function to test vsftpd configuration
test_vsftpd_config() {
    log "Testing vsftpd configuration..." "INFO"
    
    if ! command -v vsftpd > /dev/null 2>&1; then
        log "vsftpd is not installed" "ERROR"
        return 1
    fi
    
    echo -e "${CYAN}Checking vsftpd configuration file...${RESET}"
    
    # Check if configuration file exists
    if [ ! -f "$VSFTPD_CONF" ]; then
        log "vsftpd configuration file not found" "ERROR"
        return 1
    fi
    
    # Check for common configuration errors
    local errors=0
    
    # Check for SSL certificate
    if grep -q "ssl_enable=YES" "$VSFTPD_CONF"; then
        local cert_file=$(grep "rsa_cert_file=" "$VSFTPD_CONF" | cut -d= -f2)
        if [ ! -f "$cert_file" ]; then
            echo -e "${RED}Error: SSL certificate file $cert_file not found${RESET}"
            log "SSL certificate file $cert_file not found" "ERROR"
            errors=$((errors + 1))
        fi
    fi
    
    # Check for passive mode configuration
    if grep -q "pasv_address=" "$VSFTPD_CONF"; then
        local pasv_address=$(grep "pasv_address=" "$VSFTPD_CONF" | cut -d= -f2)
        if [ -z "$pasv_address" ]; then
            echo -e "${YELLOW}Warning: Passive mode address is empty${RESET}"
            log "Passive mode address is empty" "WARNING"
        fi
    fi
    
    # Test configuration syntax
    echo -e "${CYAN}Testing vsftpd configuration syntax...${RESET}"
    if vsftpd -olisten=NO "$VSFTPD_CONF" 2>/dev/null; then
        log "vsftpd configuration syntax is valid" "SUCCESS"
    else
        echo -e "${RED}Error: vsftpd configuration syntax is invalid${RESET}"
        log "vsftpd configuration syntax is invalid" "ERROR"
        errors=$((errors + 1))
    fi
    
    if [ $errors -eq 0 ]; then
        echo -e "${GREEN}vsftpd configuration is valid${RESET}"
        return 0
    else
        echo -e "${RED}Found $errors error(s) in vsftpd configuration${RESET}"
        return 1
    fi
}

# Function to fix common vsftpd issues
fix_vsftpd_issues() {
    log "Attempting to fix common vsftpd issues..." "INFO"
    
    # Check if vsftpd is installed
    if ! command -v vsftpd > /dev/null 2>&1; then
        log "vsftpd is not installed, installing now..." "WARNING"
        install_package "vsftpd"
    fi
    
    # Check if SSL certificate exists
    local cert_file="/etc/ssl/private/vsftpd.pem"
    if [ ! -f "$cert_file" ]; then
        log "SSL certificate not found, generating now..." "WARNING"
        generate_ssl_cert
    fi
    
    # Ensure configuration file exists and is valid
    if [ ! -f "$VSFTPD_CONF" ] || ! vsftpd -olisten=NO "$VSFTPD_CONF" 2>/dev/null; then
        log "Creating new vsftpd configuration..." "WARNING"
        configure_vsftpd
    fi
    
    # Ensure user list file exists
    if [ ! -f "$VSFTPD_USER_LIST" ]; then
        touch "$VSFTPD_USER_LIST"
        log "Created user list file $VSFTPD_USER_LIST" "INFO"
    fi
    
    # Try to restart the service
    systemctl restart vsftpd
    sleep 2
    
    # Check if service is running
    if systemctl is-active --quiet vsftpd; then
        log "vsftpd service is now running" "SUCCESS"
        return 0
    else
        # Get service status for debugging
        local status=$(systemctl status vsftpd)
        log "Failed to start vsftpd service. Status: $status" "ERROR"
        
        # Try one more time with a clean configuration
        log "Attempting to create a minimal working configuration..." "WARNING"
        
        # Backup existing configuration
        backup_config "$VSFTPD_CONF"
        
        # Create minimal configuration
        cat > "$VSFTPD_CONF" << EOF
# Minimal vsftpd configuration
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
dirmessage_enable=YES
use_localtime=YES
xferlog_enable=YES
connect_from_port_20=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
EOF
        
        # Try to restart with minimal config
        systemctl restart vsftpd
        sleep 2
        
        if systemctl is-active --quiet vsftpd; then
            log "vsftpd service is now running with minimal configuration" "SUCCESS"
            log "You should reconfigure vsftpd with more secure settings" "WARNING"
            return 0
        else
            log "Failed to start vsftpd even with minimal configuration" "ERROR"
            return 1
        fi
    fi
}

# Function to verify and reset user password
verify_user_password() {
    local username="$1"
    
    if grep -q "^$username:" /etc/passwd; then
        echo -e "${GREEN}User $username exists in the system${RESET}"
        
        # Reset password to ensure it works
        read -p "Do you want to reset the password? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            password=$(generate_secure_password)
            echo -e "${GREEN}New password: ${CYAN}$password${RESET}"
            
            # Use improved password setting method
            local temp_pwd_file=$(mktemp)
            echo "$username:$password" > "$temp_pwd_file"
            chpasswd < "$temp_pwd_file"
            rm -f "$temp_pwd_file"
            
            echo -e "${GREEN}Password reset successfully${RESET}"
            
            # Display updated connection information for FileZilla
            echo -e "\n${CYAN}=== Updated FileZilla Connection Information ===${RESET}"
            echo -e "${GREEN}Host:${RESET} $(/sbin/ip -o -4 addr list | grep -v "127.0.0.1" | awk '{print $4}' | cut -d/ -f1 | head -n1)"
            echo -e "${GREEN}Port:${RESET} $FTP_PORT"
            echo -e "${GREEN}Protocol:${RESET} FTP - File Transfer Protocol"
            echo -e "${GREEN}Encryption:${RESET} Require explicit FTP over TLS"
            echo -e "${GREEN}Logon Type:${RESET} Normal"
            echo -e "${GREEN}User:${RESET} $username"
            echo -e "${GREEN}Password:${RESET} $password"
        fi
    else
        echo -e "${RED}User $username does not exist in the system${RESET}"
    fi
}

# Function to manage vsftpd service
manage_vsftpd_service() {
    local action="$1"
    
    case "$action" in
        start)
            systemctl start vsftpd
            if systemctl is-active --quiet vsftpd; then
                log "vsftpd service started" "SUCCESS"
            else
                log "Failed to start vsftpd service" "ERROR"
                read -p "Do you want to attempt to fix common issues? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    fix_vsftpd_issues
                fi
            fi
            ;;
        stop)
            systemctl stop vsftpd
            log "vsftpd service stopped" "SUCCESS"
            ;;
        restart)
            systemctl restart vsftpd
            if systemctl is-active --quiet vsftpd; then
                log "vsftpd service restarted" "SUCCESS"
            else
                log "Failed to restart vsftpd service" "ERROR"
                read -p "Do you want to attempt to fix common issues? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    fix_vsftpd_issues
                fi
            fi
            ;;
        status)
            if systemctl is-active --quiet vsftpd; then
                echo -e "${GREEN}vsftpd service is active${RESET}"
                log "vsftpd service is active" "INFO"
            else
                echo -e "${RED}vsftpd service is inactive${RESET}"
                log "vsftpd service is inactive" "WARNING"
                
                # Show detailed status for troubleshooting
                echo -e "\n${CYAN}Detailed service status:${RESET}"
                systemctl status vsftpd
                
                read -p "Do you want to attempt to fix common issues? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    fix_vsftpd_issues
                fi
            fi
            ;;
        *)
            log "Action $action not recognized" "ERROR"
            ;;
    esac
}

# Function to quickly stop and disable the FTP server
disable_ftp_server() {
    log "Disabling FTP server..." "INFO"
    
    echo -e "${YELLOW}Stopping vsftpd service...${RESET}"
    systemctl stop vsftpd
    
    echo -e "${YELLOW}Disabling vsftpd service from starting at boot...${RESET}"
    systemctl disable vsftpd
    
    # Check if the service is stopped
    if ! systemctl is-active --quiet vsftpd; then
        echo -e "${GREEN}vsftpd service successfully stopped${RESET}"
    else
        echo -e "${RED}Failed to stop vsftpd service${RESET}"
        log "Failed to stop vsftpd service" "ERROR"
    fi
    
    # Check if the service is disabled
    if ! systemctl is-enabled --quiet vsftpd 2>/dev/null; then
        echo -e "${GREEN}vsftpd service successfully disabled${RESET}"
    else
        echo -e "${RED}Failed to disable vsftpd service${RESET}"
        log "Failed to disable vsftpd service" "ERROR"
    fi
    
    # Ask if user wants to close firewall ports
    read -p "Do you want to close FTP ports in the firewall? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Closing FTP ports in firewall...${RESET}"
        
        # Remove iptables rules for FTP
        iptables -D INPUT -p tcp --dport $FTP_PORT -j ACCEPT 2>/dev/null
        iptables -D INPUT -p tcp --dport $FTP_PASV_PORT -j ACCEPT 2>/dev/null
        iptables -D INPUT -p tcp --dport $FTP_DATA_PORT_MIN:$FTP_DATA_PORT_MAX -j ACCEPT 2>/dev/null
        
        # Save iptables rules
        if which iptables-save > /dev/null 2>&1; then
            iptables-save > /etc/iptables.rules
            echo -e "${GREEN}Firewall rules updated${RESET}"
        else
            echo -e "${YELLOW}iptables-save not available, rules will not persist after reboot${RESET}"
        fi
    fi
    
    log "FTP server disabled" "SUCCESS"
    echo -e "\n${GREEN}FTP server has been stopped and disabled.${RESET}"
    echo -e "${YELLOW}To completely remove vsftpd, you can run: apt-get remove --purge vsftpd${RESET}"
}

# Function to print a menu header
print_header() {
    local title="$1"
    local width=60
    local padding=$(( (width - ${#title}) / 2 ))
    
    echo
    echo -e "${BLUE}$(printf '=%.0s' $(seq 1 $width))${RESET}"
    echo -e "${BLUE}$(printf ' %.0s' $(seq 1 $padding))${MAGENTA}$title${RESET}"
    echo -e "${BLUE}$(printf '=%.0s' $(seq 1 $width))${RESET}"
    echo
}

# Function to display the main menu
show_main_menu() {
    clear
    print_header "FTP SERVER MANAGEMENT"
    
    echo -e "${GREEN}1.${RESET} Installation and configuration"
    echo -e "${GREEN}2.${RESET} User management"
    echo -e "${GREEN}3.${RESET} Service management"
    echo -e "${GREEN}4.${RESET} Security and audit"
    echo -e "${GREEN}5.${RESET} Troubleshooting"
    echo
    echo -e "${RED}0.${RESET} Exit"
    echo
    
    read -p "Choose an option: " choice
    
    case $choice in
        1) show_installation_menu ;;
        2) show_user_menu ;;
        3) show_service_menu ;;
        4) show_security_menu ;;
        5) show_troubleshooting_menu ;;
        0) exit 0 ;;
        *) 
            echo -e "${RED}Invalid option${RESET}"
            sleep 2
            show_main_menu
            ;;
    esac
}

# Function to display the installation menu
show_installation_menu() {
    clear
    print_header "INSTALLATION AND CONFIGURATION"
    
    echo -e "${GREEN}1.${RESET} Install dependencies"
    echo -e "${GREEN}2.${RESET} Install and configure vsftpd"
    echo -e "${GREEN}3.${RESET} Configure fail2ban"
    echo -e "${GREEN}4.${RESET} Configure iptables"
    echo -e "${GREEN}5.${RESET} Complete installation (install everything)"
    echo
    echo -e "${GREEN}0.${RESET} Return to main menu"
    echo
    
    read -p "Choose an option: " choice
    
    case $choice in
        1)
            install_dependencies
            read -p "Press Enter to continue..."
            show_installation_menu
            ;;
        2)
            install_package "vsftpd"
            generate_ssl_cert
            configure_vsftpd
            manage_vsftpd_service "restart"
            read -p "Press Enter to continue..."
            show_installation_menu
            ;;
        3)
            install_package "fail2ban"
            configure_fail2ban
            read -p "Press Enter to continue..."
            show_installation_menu
            ;;
        4)
            install_package "iptables"
            configure_iptables
            read -p "Press Enter to continue..."
            show_installation_menu
            ;;
        5)
            install_dependencies
            generate_ssl_cert
            configure_vsftpd
            configure_fail2ban
            configure_iptables
            manage_vsftpd_service "restart"
            log "Complete installation finished" "SUCCESS"
            read -p "Press Enter to continue..."
            show_installation_menu
            ;;
        0)
            show_main_menu
            ;;
        *)
            echo -e "${RED}Invalid option${RESET}"
            sleep 2
            show_installation_menu
            ;;
    esac
}

# Function to display the user management menu
show_user_menu() {
    clear
    print_header "USER MANAGEMENT"
    
    echo -e "${GREEN}1.${RESET} Add FTP user (with secure password generation)"
    echo -e "${GREEN}2.${RESET} Delete FTP user"
    echo -e "${GREEN}3.${RESET} List FTP users"
    echo -e "${GREEN}4.${RESET} Change user password"
    echo -e "${GREEN}5.${RESET} Modify user permissions (read/write)"
    echo -e "${GREEN}6.${RESET} Change user access path"
    echo
    echo -e "${GREEN}0.${RESET} Return to main menu"
    echo
    
    read -p "Choose an option: " choice
    
    case $choice in
        1)
            clear
            print_header "ADD FTP USER"
            
            read -p "Username: " username
            read -p "Generate secure password? (y/n): " -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                generate_pwd="yes"
                password=""
            else
                generate_pwd="no"
                read -sp "Password: " password
                echo
                read -sp "Confirm password: " password_confirm
                echo
                
                if [[ "$password" != "$password_confirm" ]]; then
                    echo -e "${RED}Passwords do not match${RESET}"
                    read -p "Press Enter to continue..."
                    show_user_menu
                    return
                fi
            fi
            
            read -p "Home directory (leave empty for /home/$username): " home_dir
            
            if [[ -z "$home_dir" ]]; then
                home_dir="/home/$username"
            fi
            
            add_ftp_user "$username" "$password" "$home_dir" "$generate_pwd"
            read -p "Press Enter to continue..."
            show_user_menu
            ;;
        2)
            clear
            print_header "DELETE FTP USER"
            
            list_ftp_users
            echo
            read -p "Username to delete: " username
            read -p "Keep home directory? (y/n): " -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                delete_ftp_user "$username" "yes"
            else
                delete_ftp_user "$username" "no"
            fi
            
            read -p "Press Enter to continue..."
            show_user_menu
            ;;
        3)
            clear
            print_header "FTP USER LIST"
            
            list_ftp_users
            echo
            read -p "Press Enter to continue..."
            show_user_menu
            ;;
        4)
            clear
            print_header "CHANGE PASSWORD"
            
            list_ftp_users
            echo
            read -p "Username: " username
            read -p "Generate secure password? (y/n): " -n 1 -r
            echo
            
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                generate_pwd="yes"
                password=""
            else
                generate_pwd="no"
                read -sp "New password: " password
                echo
                read -sp "Confirm password: " password_confirm
                echo
                
                if [[ "$password" != "$password_confirm" ]]; then
                    echo -e "${RED}Passwords do not match${RESET}"
                    read -p "Press Enter to continue..."
                    show_user_menu
                    return
                fi
            fi
            
            change_user_password "$username" "$password" "$generate_pwd"
            read -p "Press Enter to continue..."
            show_user_menu
            ;;
        5)
            clear
            print_header "MODIFY USER PERMISSIONS"
            
            list_ftp_users
            echo
            read -p "Username: " username
            echo
            echo -e "Select permission type:"
            echo -e "${GREEN}1.${RESET} Read-only"
            echo -e "${GREEN}2.${RESET} Read-write"
            echo
            read -p "Choose an option: " perm_choice
            
            case $perm_choice in
                1)
                    modify_user_permissions "$username" "read-only"
                    ;;
                2)
                    modify_user_permissions "$username" "read-write"
                    ;;
                *)
                    echo -e "${RED}Invalid option${RESET}"
                    ;;
            esac
            
            read -p "Press Enter to continue..."
            show_user_menu
            ;;
        6)
            clear
            print_header "CHANGE USER ACCESS PATH"
            
            list_ftp_users
            echo
            read -p "Username: " username
            read -p "New access path: " new_path
            
            change_user_path "$username" "$new_path"
            
            read -p "Press Enter to continue..."
            show_user_menu
            ;;
        0)
            show_main_menu
            ;;
        *)
            echo -e "${RED}Invalid option${RESET}"
            sleep 2
            show_user_menu
            ;;
    esac
}

# Function to display the service management menu
show_service_menu() {
    clear
    print_header "SERVICE MANAGEMENT"
    
    echo -e "${GREEN}1.${RESET} Start vsftpd service"
    echo -e "${GREEN}2.${RESET} Stop vsftpd service"
    echo -e "${GREEN}3.${RESET} Restart vsftpd service"
    echo -e "${GREEN}4.${RESET} Show vsftpd service status"
    echo -e "${GREEN}5.${RESET} Disable FTP server (stop and disable)"
    echo
    echo -e "${GREEN}0.${RESET} Return to main menu"
    echo
    
    read -p "Choose an option: " choice
    
    case $choice in
        1)
            manage_vsftpd_service "start"
            read -p "Press Enter to continue..."
            show_service_menu
            ;;
        2)
            manage_vsftpd_service "stop"
            read -p "Press Enter to continue..."
            show_service_menu
            ;;
        3)
            manage_vsftpd_service "restart"
            read -p "Press Enter to continue..."
            show_service_menu
            ;;
        4)
            clear
            print_header "SERVICE STATUS"
            manage_vsftpd_service "status"
            read -p "Press Enter to continue..."
            show_service_menu
            ;;
        5)
            clear
            print_header "DISABLE FTP SERVER"
            disable_ftp_server
            read -p "Press Enter to continue..."
            show_service_menu
            ;;
        0)
            show_main_menu
            ;;
        *)
            echo -e "${RED}Invalid option${RESET}"
            sleep 2
            show_service_menu
            ;;
    esac
}

# Function to display the security menu
show_security_menu() {
    clear
    print_header "SECURITY AND AUDIT"
    
    echo -e "${GREEN}1.${RESET} Configure fail2ban"
    echo -e "${GREEN}2.${RESET} Configure iptables"
    echo -e "${GREEN}3.${RESET} Generate new SSL certificate"
    echo -e "${GREEN}4.${RESET} Test vsftpd configuration"
    echo
    echo -e "${GREEN}0.${RESET} Return to main menu"
    echo
    
    read -p "Choose an option: " choice
    
    case $choice in
        1)
            configure_fail2ban
            read -p "Press Enter to continue..."
            show_security_menu
            ;;
        2)
            configure_iptables
            read -p "Press Enter to continue..."
            show_security_menu
            ;;
        3)
            generate_ssl_cert
            read -p "Press Enter to continue..."
            show_security_menu
            ;;
        4)
            clear
            print_header "CONFIGURATION TEST"
            test_vsftpd_config
            read -p "Press Enter to continue..."
            show_security_menu
            ;;
        0)
            show_main_menu
            ;;
        *)
            echo -e "${RED}Invalid option${RESET}"
            sleep 2
            show_security_menu
            ;;
    esac
}

# Function to display the troubleshooting menu
show_troubleshooting_menu() {
    clear
    print_header "TROUBLESHOOTING"
    
    echo -e "${GREEN}1.${RESET} Fix common vsftpd issues"
    echo -e "${GREEN}2.${RESET} Diagnose user management tools"
    echo -e "${GREEN}3.${RESET} Check system logs"
    echo -e "${GREEN}4.${RESET} Verify SSL certificate"
    echo -e "${GREEN}5.${RESET} Verify user password"
    echo
    echo -e "${GREEN}0.${RESET} Return to main menu"
    echo
    
    read -p "Choose an option: " choice
    
    case $choice in
        1)
            clear
            print_header "FIX COMMON ISSUES"
            fix_vsftpd_issues
            read -p "Press Enter to continue..."
            show_troubleshooting_menu
            ;;
        2)
            clear
            print_header "USER MANAGEMENT DIAGNOSIS"
            diagnose_user_tools
            read -p "Press Enter to continue..."
            show_troubleshooting_menu
            ;;
        3)
            clear
            print_header "SYSTEM LOGS"
            echo -e "${CYAN}Last 20 lines of vsftpd log:${RESET}"
            if [ -f /var/log/vsftpd.log ]; then
                tail -n 20 /var/log/vsftpd.log
            else
                echo -e "${YELLOW}vsftpd log file not found${RESET}"
            fi
            
            echo -e "\n${CYAN}Last 20 lines of system log:${RESET}"
            tail -n 20 /var/log/syslog 2>/dev/null || tail -n 20 /var/log/messages 2>/dev/null || echo -e "${YELLOW}System log not found${RESET}"
            
            read -p "Press Enter to continue..."
            show_troubleshooting_menu
            ;;
        4)
            clear
            print_header "SSL CERTIFICATE VERIFICATION"
            local cert_file="/etc/ssl/private/vsftpd.pem"
            
            if [ -f "$cert_file" ]; then
                echo -e "${CYAN}Certificate information:${RESET}"
                openssl x509 -in "$cert_file" -text -noout | head -15
                echo -e "\n${GREEN}Certificate exists and is readable${RESET}"
            else
                echo -e "${RED}Certificate file not found${RESET}"
                read -p "Generate a new certificate? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    generate_ssl_cert
                fi
            fi
            
            read -p "Press Enter to continue..."
            show_troubleshooting_menu
            ;;
        5)
            clear
            print_header "VERIFY USER PASSWORD"
            read -p "Username to verify: " username
            verify_user_password "$username"
            read -p "Press Enter to continue..."
            show_troubleshooting_menu
            ;;
        0)
            show_main_menu
            ;;
        *)
            echo -e "${RED}Invalid option${RESET}"
            sleep 2
            show_troubleshooting_menu
            ;;
    esac
}

# Main function
main() {
    # Check for root privileges
    check_root
    
    # Create log file
    touch "$LOG_FILE"
    log "Script started" "INFO"
    
    # Display the main menu
    show_main_menu
}

# Execute the main function
main
