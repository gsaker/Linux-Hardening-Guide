#### Updates
```bash
sudo -i
apt update -y
apt upgrade -y
apt autoclean -y
apt autoremove -y
apt install ufw gufw lynis auditd libpam-pwquality unhide fail2ban libpam-cracklib clamav software-properties-common apt-transport-https wget git chkrootkit rkhunter  apparmor apparmor-profiles unattended-upgrades -y
sudo apt-get remove --purge openjdk-\* -y
nano /etc/apt/apt.conf.d/50unattended-upgrades
#Add following
// Enable unattended-upgrades and set the desired frequency for updates
Unattended-Upgrade::Enable "true";
Unattended-Upgrade::Allowed-Origins "o=Debian,a=stable";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailOnlyOnError "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
// Schedule automatic updates to run every Sunday
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";

```
#### DO FIRST!!!
```bash
git clone https://github.com/kenneth-karlsson/Cisecurity
cd Cisecurity-master
./cis1804.sh -u #for example
apt install xorg open-vm-tools lightdm gdm 
```
#### Webmin
```bash
wget -q -O- http://www.webmin.com/jcameron-key.asc | sudo apt-key add
sudo nano /etc/apt/sources.list
```
In sources
```
deb http://download.webmin.com/download/repository sarge contrib
```

```bash
apt install webmin
```
#### Audit
```bash
auditctl -e 1 > /var/local/audit.log
```
#### Firewall
```
ufw default deny incoming
ufw allow ssh 
ufw allow 10000
ufw enable
ufw status
```

#### PAM
```bash
nano /etc/pam.d/common-password
```
After `pam_unix.so`
```
sha512 obscure use_authtok try_first_pass minlen=10 remeber=5 obscure rounds=5
```
After `pam_pwquailty.so`
```
retry=3 minlen=10 lcredit=-1 ucredit=-1 ocredit=-1 dcredit=-1 reject_username difok=3 enforce_for_root
```
After `pam_cracklib.so`
```
retry=3 minlen=10 difok=3 ucredit=-1 1credit=-1 ocredit=-1
```
Password lockout
```bash
nano /etc/pam.d/common-auth
```
Should be only thing in file 
```
auth required pam_tally2.so deny=3 onerr=fail unlock_time=1800
```
#### Password Ageing
```
nano /etc/login.defs
```
Find in file and **change**
```
PASS_MAX_DAYS	30
PASS_MIN_DAYS	2
PASS_MIN_LEN	10
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512

```

#### SSH Config
``` bash
nano /etc/ssh/sshd_config
```

```
PermitEmptyPasswords no
LoginGraceTime 20
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
UsePAM yes
MACs hmac-sha2-256,hmac-sha2-512
Ciphers aes256-ctr,aes192-ctr,aes128-ctr
Protocol 2
ClientAliveInterval 300
ClientAliveCountMax 0
MaxAuthTries 3
IgnoreRhosts yes
StrictModes yes
PermitEmptyPasswords no
MaxStartups 2
PubkeyAuthentication yes
PermitRootLogin no
Port 2222
PasswordAuthentication no
HostBasedAuthentication no
PubkeyAuthentication yes
LogLevel VERBOSE
```
#### LightDM
```
nano /etc/lightdm/lightdm.conf
```
Disable guest account
```
[SeatDefaults]
allow-guest=false
```
#### Media Files
```
find / -type f \( -name "*.mp3" -o -name "*.wav" -o -name "*.flac" -o -name "*.aac" -o -name "*.ogg" -o -name "*.wma" -o -name "*.m4a" -o -name "*.mp4" -o -name "*.avi" -o -name "*.mkv" -o -name "*.mov" -o -name "*.wmv" -o -name "*.webm" -o -name "*.3gp" -o -name "*.flv" -o -name "*.m4v" -o -name "*.asf" -o -name "*.ts" -o -name "*.ogg" \)
```
#### Antivirus
```bash
freshclam
clamscan -r /
chkrootkit -q
nano /etc/rkhunter.conf
#Add following to botton 
MIRRORS_MODE=0
UPDATE_MIRRORS=1
WEB_CMD=""

rkhunter --update
rkhunter --propupd
rkhunter -c --enable all --disable none
```
#### Port Check
```
lsof -i -P -n
ss -tuln
```
#### Cronjobs
See webmin to check for specific jobs
```bash
cat /etc/cron.d/cron.deny
nano /etc/cron.d/cron.allow
#add root to this file
```
#### Init Scripts
```bash
ls -la /etc/init/
ls -la /etc/init.d/
ls -la /etc/rc*.d
```
#### Firefox
- Pop up blocker disabled
#### File Inspection
```bash
nano /etc/resolv.conf #set nameserver to 8.8.8.8, look up an other things
nano /etc/hosts #checl for redirects
visudo #check for NOPASSWD
find / -type f -perm 777 2>/dev/null #find 777 files
nano /etc/apt/sources.list #ask george

```
#### /etc/sysctl.conf
```bash
#!/bin/bash
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w kernel.randomize_va_space=2
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.icmp_ratelimit=100
sysctl -w kernel.kptr_restrict=1
sysctl -w kernel.dmesg_restrict=1
sysctl -w fs.protected_hardlinks=1
sysctl -w fs.protected_symlinks=1
sysctl -w net.ipv4.icmp_echo_ignore_all=1
sysctl -w net.ipv4.tcp_max_syn_backlog=1280
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -p
```
#### Users
```bash
passwd #set new password for root
awk -F: '$3 == 0 { print "Username: " $1, "UID: " $3 }' /etc/passwd #UID of 0
#check for empty passwords
#!/bin/bash
empty_password_users=()
# Read the /etc/shadow file and check for empty passwords
while IFS=: read -r username password; do
    if [ -z "$password" ] || [ "$password" = "!" ] || [ "$password" = "*" ]; then
        empty_password_users+=("$username")
    fi
done < /etc/shadow
# Check if there are any users with empty passwords
if [ ${#empty_password_users[@]} -eq 0 ]; then
    echo "No users have empty passwords."
else
    echo "Users with empty passwords:"
    for user in "${empty_password_users[@]}"; do
        echo "- $user"
    done
fi

#check for hidden users
#!/bin/bash
# Define the minimum UID to consider as hidden (e.g., 1000)
MIN_UID=1000
# Iterate through /etc/passwd to find hidden users
while IFS=: read -r username password uid rest; do
    if [ "$uid" -lt "$MIN_UID" ]; then
        echo "Hidden User: $username (UID: $uid)"
    fi
done < /etc/passwd

```