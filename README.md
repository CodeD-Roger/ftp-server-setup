```
# Secure FTP Server with Fail2Ban

## Description
This script automates the setup and management of a secure FTP server using vsftpd, combined with Fail2Ban to protect against brute-force attacks. It includes options for user management, configuration of FTP permissions, and real-time IP banning.

## Features
- Install and configure vsftpd with SSL/TLS support.
- Set up Fail2Ban to secure the FTP server against unauthorized access.
- Manage FTP users (add, delete, modify permissions).
- Monitor and unban IPs with Fail2Ban.

## Requirements
- A Linux system (Debian-based distributions recommended).
- Root privileges for script execution.

## Installation
```bash
git clone https://github.com/BuggyTheDebugger/ftp-server-setup.git
cd ftp-server-setup
chmod +x ftp-server.sh
sudo ./ftp-server.sh
```
## USAGE
```bash
sudo ./ftp-server.sh
