#!/bin/bash

# Author: [CodeD-Roger]

# ================================================
# Secure FTP Server Management with vsftpd and Fail2Ban
# ================================================

LOG_FILE="/var/log/ftp_manager.log"
BACKUP_DIR="/etc/ftp_manager_backups"

if [ "$EUID" -ne 0 ]; then
    echo "Please run this script as root."
    exit 1
fi

mkdir -p "$BACKUP_DIR"

log_action() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') : $message" >> "$LOG_FILE"
}

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file")_$(date '+%Y%m%d_%H%M%S')"
        log_action "Backup of file $file completed."
    fi
}

confirm_action() {
    read -p "$1 [y/N]: " confirmation
    if [[ "$confirmation" != "y" && "$confirmation" != "Y" ]]; then
        echo "Action canceled."
        return 1
    fi
    return 0
}

# ================================================
# FTP Section
# ================================================

install_vsftpd() {
    clear
    log_action "Installing vsftpd..."
    apt update && apt install -y vsftpd
    backup_file "/etc/vsftpd.conf"

    cat <<EOL > /etc/vsftpd.conf
listen=YES
anonymous_enable=NO
local_enable=YES
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
ssl_enable=YES
rsa_cert_file=/etc/ssl/certs/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.key
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log
log_ftp_protocol=YES
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=50000
pasv_address=$(hostname -I | awk '{print $1}')
userlist_enable=NO
local_umask=022
file_open_mode=0777
force_local_data_ssl=YES
force_local_logins_ssl=YES
EOL

    log_action "vsftpd configuration updated."

    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/vsftpd.key \
        -out /etc/ssl/certs/vsftpd.pem \
        -subj "/C=US/ST=State/L=City/O=Company/OU=IT/CN=ftp.local"
    log_action "SSL certificate generated."

    systemctl restart vsftpd
    log_action "vsftpd service restarted."
}

test_ftp_server() {
    apt install -y lftp
    echo "Testing FTP server connection..."
    read -p "Enter an existing FTP user: " test_user
    read -sp "Enter the user's password: " test_pass
    echo
    lftp -u "$test_user,$test_pass" -e "set ssl:verify-certificate no; ls; bye" "ftp://$(hostname -I | awk '{print $1}')"
    if [ $? -eq 0 ]; then
        echo "Connection successful."
        log_action "FTP connection test successful with user $test_user."
    else
        echo "Connection failed."
        log_action "FTP connection test failed."
    fi
}

ftp_menu() {
    while true; do
	echo "========== FTP =========="
        echo "1. Install/configure FTP server"
        echo "2. Test FTP server"
        echo "3. Return to main menu"
        read -p "Choose an option [1-3]: " ftp_choice

        case $ftp_choice in
            1) install_vsftpd ;;
            2) test_ftp_server ;;
            3) clear 
	       return ;;
            *) echo "Invalid option." ;;
        esac
    done
}

# ================================================
# Users Section
# ================================================

add_ftp_user() {
    read -p "Enter username: " username
    password=$(openssl rand -base64 12)

    useradd -m -s /bin/bash "$username"
    echo "$username:$password" | chpasswd

    mkdir -p /home/"$username"/ftp/upload
    chmod 555 /home/"$username"/ftp
    chmod 755 /home/"$username"/ftp/upload
    chown "$username:$username" /home/"$username"/ftp/upload

    echo "User $username created with password: $password"
    log_action "User $username created with FTP access."
}

delete_ftp_user() {
    read -p "Enter username to delete: " username
    if id "$username" &>/dev/null; then
        confirm_action "Are you sure you want to delete user $username?"
        if [ $? -eq 0 ]; then
            userdel -r "$username"
            echo "User $username successfully deleted."
            log_action "User $username deleted."
        fi
    else
        echo "User not found."
    fi
}

list_ftp_users() {
    echo "===== FTP Users ====="
    echo "FTP section:"
    grep "/ftp" /etc/passwd | awk -F: '{print $1, $6}'
    echo ""
    echo "Total section (all users):"
    awk -F: '{print $1, $6}' /etc/passwd
}

modify_user_permissions() {
    read -p "Enter username: " username
    if id "$username" &>/dev/null; then
        echo "1. Read-only"
        echo "2. Read/Write"
        read -p "Choose an option [1-2]: " permission_choice
        case $permission_choice in
            1)
                chmod 555 /home/"$username"/ftp
                chmod 555 /home/"$username"/ftp/upload
                log_action "Permissions updated for $username: Read-only."
                ;;
            2)
                chmod 755 /home/"$username"/ftp
                chmod 755 /home/"$username"/ftp/upload
                log_action "Permissions updated for $username: Read/Write."
                ;;
            *)
                echo "Invalid option."
                ;;
        esac
    else
        echo "User not found."
    fi
}

users_menu() {
    while true; do
        echo "====== Users ======"
        echo "1. Add FTP user"
        echo "2. Delete FTP user"
        echo "3. Modify user permissions"
        echo "4. List users"
        echo "5. Return to main menu"
        read -p "Choose an option [1-5]: " user_choice

        case $user_choice in
            1) add_ftp_user ;;
            2) delete_ftp_user ;;
            3) modify_user_permissions ;;
            4) list_ftp_users ;;
            5) clear
	       return ;;
            *) echo "Invalid option." ;;
        esac
    done
}

# ================================================
# Fail2Ban Section
# ================================================

install_fail2ban() {
    clear 
    log_action "Installing Fail2Ban..."
    apt update && apt install -y fail2ban
    backup_file "/etc/fail2ban/jail.local"

    cat <<EOL > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 4

[vsftpd]
enabled = true
port = ftp,ftp-data,40000-50000
filter = vsftpd
logpath = /var/log/vsftpd.log
EOL

    systemctl restart fail2ban
    log_action "Fail2Ban installed and configured."
}

modify_fail2ban_config() {
    read -p "Ban time (e.g., 10m): " bantime
    read -p "Max retries (e.g., 4): " maxretry
    read -p "Detection window (e.g., 10m): " findtime

    backup_file "/etc/fail2ban/jail.local"
    sed -i "s/^bantime = .*/bantime = $bantime/" /etc/fail2ban/jail.local
    sed -i "s/^maxretry = .*/maxretry = $maxretry/" /etc/fail2ban/jail.local
    sed -i "s/^findtime = .*/findtime = $findtime/" /etc/fail2ban/jail.local

    systemctl restart fail2ban
    log_action "Fail2Ban configuration updated: bantime=$bantime, maxretry=$maxretry, findtime=$findtime."
}
test_fail2ban() {
    systemctl status fail2ban &>/dev/null && echo "Fail2Ban is active." || echo "Fail2Ban is not active."
}

list_banned_ips() {
    fail2ban-client status vsftpd | grep "Banned IP list" | awk -F: '{print $2}' | xargs
}

show_banned_ip_details() {
    read -p "Enter the banned IP to search for: " ip
    echo "Details for IP $ip:"
    grep "$ip" /var/log/vsftpd.log
}

unban_ip() {
    read -p "Enter the IP to unban: " ip
    fail2ban-client unban "$ip"
    echo "IP $ip has been unbanned."
    log_action "IP $ip was manually unbanned."
}

unban_all_ips() {
    confirm_action "Are you sure you want to unban all IPs?"
    if [ $? -eq 0 ]; then
        for ip in $(list_banned_ips); do
            fail2ban-client unban "$ip"
        done
        echo "All IPs have been unbanned."
        log_action "All banned IPs have been unbanned."
    fi
}

banned_ips_menu() {
    while true; do
        echo "=== Banned IP Management ==="
        echo "1. List banned IPs"
        echo "2. Show details for a banned IP"
        echo "3. Unban an IP"
        echo "4. Unban all IPs"
        echo "5. Return"
        read -p "Choose an option [1-5]: " banned_choice

        case $banned_choice in
            1)
                echo "Currently banned IPs:"
                list_banned_ips
                ;;
            2)
                show_banned_ip_details
                ;;
            3)
                unban_ip
                ;;
            4)
                unban_all_ips
                ;;
            5)
                clear 
	        return ;;
            *)
                echo "Invalid option." ;;
        esac
    done
}

fail2ban_menu() {
    while true; do
        echo "====== Fail2Ban ======"
        echo "1. Install/configure Fail2Ban"
        echo "2. Modify Fail2Ban configuration"
        echo "3. Test Fail2Ban"
        echo "4. Manage banned IPs"
        echo "5. Return to main menu"
        read -p "Choose an option [1-5]: " fail2ban_choice

        case $fail2ban_choice in
            1) install_fail2ban ;;
            2) modify_fail2ban_config ;;
            3) test_fail2ban ;;
            4) banned_ips_menu ;;
            5) clear 
	      return ;;
            *) echo "Invalid option." ;;
        esac
    done
}

# ================================================
# Main Menu
# ================================================

main_menu() {
    	clear
    while true; do
        echo "==================================="
        echo "   Secure FTP Server Management"
        echo "==================================="
        echo "1. FTP: Install, configure, and test the FTP server"
        echo "2. Users: Add, delete, manage permissions"
        echo "3. Fail2Ban: Install, configure, test"
        echo "4. Quit"
        read -p "Choose a category [1-4]: " main_choice

        case $main_choice in
            1) ftp_menu ;;
            2) users_menu ;;
            3) fail2ban_menu ;;
            4)
                echo "Goodbye!"
                log_action "Script terminated."
                exit 0
                ;;
            *) echo "Invalid option." ;;
        esac
    done
}

main_menu

