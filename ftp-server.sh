#!/bin/bash

# Author: [CodeD-Roger]

# Vérification et installation des outils système
install_system_tools() {
    apt update
    apt install -y useradd passwd
}

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
    if ! command -v lftp &>/dev/null; then
        apt install -y lftp
    fi

    read -p "Nom d'utilisateur FTP : " test_user
    read -sp "Mot de passe : " test_pass
    echo

    # Test de connexion sécurisé
    lftp -u "$test_user,$test_pass" \
        -e "set ssl:verify-certificate yes; ls; bye" \
        "ftps://$(hostname -I | awk '{print $1}')"

    if [ $? -eq 0 ]; then
        echo "Connexion réussie"
        log_action "Test connexion FTP réussi pour $test_user"
    else
        echo "Échec de connexion"
        log_action "Échec test connexion FTP pour $test_user"
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

configure_password_policy() {
    read -p "Voulez-vous définir une politique de mot de passe personnalisée ? (o/n) [défaut: n]: " use_policy
    use_policy=${use_policy:-n}

    if [[ "$use_policy" != "o" ]]; then
        # Supprimer le fichier de configuration si existe
        rm -f /etc/ftp_password_policy.conf
        echo "Politique de mot de passe par défaut."
        log_action "Politique de mot de passe par défaut"
        return
    fi

}

generate_complex_password() {
    local password
    local policy_min_length=${MIN_LENGTH:-12}
    local policy_require_digits=${REQUIRE_DIGITS:-1}
    local policy_require_letters=${REQUIRE_LETTERS:-1}
    local policy_exclude_chars="${EXCLUDE_CHARS:-}"

    while true; do
        password=$(openssl rand -base64 16)

        if [ ${#password} -lt "$policy_min_length" ]; then
            continue
        fi

        if [ "$policy_require_digits" -eq 1 ] && [[ ! "$password" =~ [0-9] ]]; then
            continue
        fi

        if [ "$policy_require_letters" -eq 1 ] && [[ ! "$password" =~ [a-zA-Z] ]]; then
            continue
        fi

        if [ -n "$policy_exclude_chars" ] && [[ "$password" =~ [$policy_exclude_chars] ]]; then
            continue
        fi

        echo "$password"
        break
    done
}

add_ftp_user() {
    # Installer les outils système si nécessaire
    install_system_tools

    # Vérification du nom d'utilisateur
    read -p "Nom d'utilisateur : " username
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{2,31}$ ]]; then
        echo "Nom d'utilisateur invalide"
        return 1
    fi

    # Vérifier si l'utilisateur existe déjà
    if id "$username" &>/dev/null; then
        echo "L'utilisateur $username existe déjà"
        return 1
    fi

    # Génération du mot de passe
    if [ -f /etc/ftp_password_policy.conf ]; then
        source /etc/ftp_password_policy.conf
        password=$(generate_complex_password)
    else
        password=$(openssl rand -base64 12)
    fi

    # Création de l'utilisateur
    /usr/sbin/useradd -m -s /bin/bash "$username"
    echo "$username:$password" | /usr/bin/passwd "$username"

    # Création des répertoires FTP
    mkdir -p /home/"$username"/ftp/upload
    chmod 755 /home/"$username"/ftp
    chmod 755 /home/"$username"/ftp/upload
    chown "$username:$username" /home/"$username"/ftp/upload

    echo "Utilisateur $username créé avec le mot de passe : $password"
    log_action "Utilisateur $username créé avec accès FTP"
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
        echo "2. Configure password policy"  # Nouveau choix
        echo "3. Delete FTP user"
        echo "4. Modify user permissions"
        echo "5. List users"
        echo "6. Return to main menu"
        read -p "Choose an option [1-6]: " user_choice

        case $user_choice in
            1) add_ftp_user ;;
            2) configure_password_policy ;;  # Nouvelle option
            3) delete_ftp_user ;;
            4) modify_user_permissions ;;
            5) list_ftp_users ;;
            6) clear
               return ;;
            *) echo "Invalid option." ;;
        esac
    done
}

# ================================================
# Fail2Ban Section
# ================================================

install_fail2ban() {
    apt update && apt install -y fail2ban
    backup_file "/etc/fail2ban/jail.local"

    cat <<EOL > /etc/fail2ban/jail.local

[DEFAULT]
bantime = 10m
findtime = 10m
maxretry = 4
banaction = iptables-multiport
backend = auto

[vsftpd]
enabled = true
port = ftp,ftp-data,40000:50000
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = 4
bantime = 10m
findtime = 10m

[vsftpd-iptables]
enabled = true
filter = vsftpd
action = iptables[name=vsftpd, port="21,40000:50000", protocol=tcp]
logpath = /var/log/vsftpd.log
maxretry = 4
findtime = 10m
bantime = 10m

    systemctl restart fail2ban
    log_action "Fail2Ban installé et configuré de manière renforcée"
}

check_fail2ban_status() {
    echo "Checking Fail2Ban status..."
    echo "1. Service status:"
    systemctl status fail2ban | grep "Active:"
    echo
    echo "2. Jail status:"
    fail2ban-client status vsftpd
    echo
    echo "3. Log file check:"
    if [ -f /var/log/vsftpd.log ]; then
        echo "vsftpd log exists"
        tail -n 5 /var/log/vsftpd.log
    else
        echo "vsftpd log file not found!"
    fi
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
