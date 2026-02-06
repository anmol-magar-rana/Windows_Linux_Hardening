#!/bin/bash

# Linux Hardening Baseline Script for Ubuntu 
# Author: Anmol Rana
#This script is built by scourcing from publicly available sources from 
#Microsoft, CIS recommendations, and community tutorials. 
#All consolidation was done by me.
#Test thoroughly in non-production environments before deployment.


#check of script is run as root, if not, exit
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root."
    exit 1
fi

echo "===== LINUX HARDENING STARTED ====="

# 1. update all packages and install any updates
echo "Updating system packages..."
apt update && apt upgrade -y

#############################################################################

# 2. configure the uncomplicated firewall and enable it
echo "Configuring firewall..."
ufw default deny incoming       #deny all incoming connections
ufw default allow outgoing      #allow all outgoing connections
ufw allow ssh                   #allow port 22 for SSH 
ufw --force enable              #turn it on 

#############################################################################

# 3. disable unnecessary services
echo "Disabling unnecessary services..."

#create a list of services to diasble
services=(
    avahi-daemon     #multicast DNS service, not needed on servers
    cups             #for printing
    bluetooth        #not needed on servers
    rpcbind          #remote procedure call service used for network file system, NFS
                     #disabling it prevents DDOS attacks and reduces attack surface
)
#loop through all services in the list above and disable them
for svc in "${services[@]}"; do
    systemctl disable --now "$svc" 2>/dev/null
    echo "    - Disabled $svc"
done

#############################################################################

# 4. enforce password policies
echo "Enforcing password policies..."

#set minimum length to 14
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN   14/' /etc/login.defs

#configure password aging: 
chage --maxdays 90 root     #max 90 days before changing pw
chage --mindays 1 root      #minimun of 1 day before pw can be changed again
chage --warndays 7 root     #warn user 7 days before pw expires

#############################################################################

# 5. SSH hardening
echo "Hardening SSH..."

SSHD_CONFIG="/etc/ssh/sshd_config"

#backup first
cp "$SSHD_CONFIG" "${SSHD_CONFIG}.backup.$(date +%Y%m%d)"

#only disable password auth if keys exist. if not, user can be locked out, skip this
if [ -f /root/.ssh/authorized_keys ] || [ -f /home/*/.ssh/authorized_keys ]; then
    echo "Notice: SSH keys detected, disabling password auth"
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' $SSHD_CONFIG
else
    echo "Warning: No SSH keys found. Keeping password auth enabled."
fi

#disable root login
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $SSHD_CONFIG

#restart SSH
systemctl restart ssh


#############################################################################

# 6. remove SMB file sharing services
echo "Removing SMBv1/Samba packages..."
apt purge -y samba samba-common 2>/dev/null


#############################################################################

# 7. enable system auditing by installing audit daemon
echo "Enabling auditd..."

apt install -y auditd
systemctl enable --now auditd


#############################################################################

# 8. kernel hardening
echo "Applying kernel-level hardening..."

#first two lines 
cat <<EOF >/etc/sysctl.d/99-hardening.conf

#IP spoofing protection / DDOs attacks. checks if incoming packets source IP is reachable via the interface they arrived on
net.ipv4.conf.all.rp_filter = 1                 #enable reverse path filtering for all interfaces.
net.ipv4.conf.default.rp_filter = 1             #apply to new interfaces too

#disables ICMP redirect acceptance. prevents man in middle attacks via route manipulation
net.ipv4.conf.all.accept_redirects = 0          #ICMP redirects tell a host to use a different route/gateway
net.ipv4.conf.default.accept_redirects = 0

#prevents server from sending IMCP redirects as servers dont need to do it
#this stops information leakage (network topology and routing knowledge) and DoS and MITM attacks
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

#protects against syn flood DDoS attacks by turning on TCP syn cookies. turns TCP handshake stateless, only allocating resources if ACK is sent back
net.ipv4.tcp_syncookies = 1

#hides kernel address from bring printed by kernel pointers. hardens against attacks since its harder to know where the kernel is in memeory address
kernel.kptr_restrict = 2

#mazimises ASLR which is address space layout randomization. this randomizes memeory layout for everything, making buffer overflow attacks harder.
kernel.randomize_va_space = 2
EOF

sysctl -p /etc/sysctl.d/99-hardening.conf


#############################################################################

# 9. make cron jobs accessible to root only
echo "Restricting cron access to root..."
#make it so only root can do cron jobs. no unauthorised scheduled tasks carried out
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow


#############################################################################

# 10. set permissions on important files
echo "Securing sensitive files..."

#set file permissions to read and write by root only
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group


#############################################################################

# 11. disable core dumps that can store memeory dumps and other information
echo "Disabling system core dumps..."
echo "* hard core 0" >> /etc/security/limits.conf

#############################################################################

# 12. enable fial2ban. this automatically stops brute force attacks
echo "Installing fail2ban..."
apt install -y fail2ban
systemctl enable --now fail2ban

#############################################################################

# 13. enable log rotation. this ensures continuous logging even if disk is full
echo "Installing log rotation..."
apt install -y logrotate


#done
echo "===== HARDENING COMPLETE ====="
