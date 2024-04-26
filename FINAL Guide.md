# Steps to win 
Below steps are in rough order, see below sections for explanation on how to perform each step

**IMPORTANT NOTE:** All command should be run as the root user, that means either putting `sudo` in front of every command or by logging in as root using `sudo -i` (preferred option)
### All Images
- [[#Install Webmin]]
- [[#Run Cisecurity Script]]
- [[#User checks]]
- [[#Modify Kernel Things]]
- [[#Software Updates]]
- [[#Enable Firewall]]
- [[#Password Requirements]]
- [[#Removing Media Files]]
- [[#Check for cron/init jobs]]
- [[#Application Settings]]
- [[#Antivirus]]
- [[#Other Random Stuff]]
### Services
- [[#SSH]]
### Software
- 
# Guides

### Install Webmin
Update the sources
```bash
apt update
```
Install wget and nano
```
apt install wget nano
```
Add the webmin key
```bash
wget -q -O- http://www.webmin.com/jcameron-key.asc | sudo apt-key add
```
Edit the sources file with the following command
```bash
sudo nano /etc/apt/sources.list
```
Now using the arrow keys to scroll to the end of the file, add the following line 
```
deb http://download.webmin.com/download/repository sarge contrib
```
Press `Ctrl-X` followed by pressing `y` then `enter` to save and exit the file
Now update the sources again and install webmin
```bash
apt update
apt install webmin
```
Now navigate to [http://localhost:10000](http://localhost:10000) in firefox. Click advanced on the window that appears and click accept the risk and continue. Log in with the admin user and password. You are now in webmin!
### Run Cisecurity Script
==Very Important - Make sure george runs + watches the script whilst it is running since it sometimes does weird things==
Install git to download the repository
```bash
apt install git net-tools
```
Clone the script repository
```bash
git clone https://github.com/gsaker/Cisecurity/
```
Change directory to the script directory
```
cd Cisecurity
```
Allow the script to be executed
```
chmod +x *
```
Run the script once to generate the config file, run the script most relevant to your distribution (EG: Ivan run cisdebian.sh, dylan run cis2004.sh)
```
./cisdebian.sh
```
Now edit the config file using nano
```
nano .cisrc
```
Set the following parameters to yes, you may need to set more depending on the Cybercenturion readme file
`SX11="Y"`
`SSSHD="Y"`
Maybe also change the `sugroup` to something else
Now press `Ctrl-X` followed by pressing `y` then `enter` to save and exit the file. Make sure you have at least one other root shell open before running the script below
```bash
./cisdebian.sh -u
```
### Software Updates
Update and upgrade everything
```bash
apt update
apt upgrade
```
Install various other useful software
```bash
apt install ufw gufw lynis auditd libpam-pwquality unhide fail2ban clamav software-properties-common apt-transport-https wget git chkrootkit rkhunter  apparmor apparmor-profiles unattended-upgrades software-properties-gtk
```
Try enabling automatic updates from the GUI
```bash
software-properties-gtk
```
Enable automatic updates service
```bash
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades
```
Edit file to setup unattended updates, then uncomment Debian security etc ==Ask George==
```bash
nano /etc/apt/apt.conf.d/50unattended-upgrades
```
Now edit the apt file to enable the updates
```
nano /etc/apt/apt.conf.d/20auto-upgrades
```
Add the following to this file
```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
```
### Enable Firewall
Install the firewall
```bash
apt install ufw
```
Setup the firewall with reasonable requirements like this, you may need to allow additional stuff if it says so in the readme file
```
ufw default deny incoming
ufw allow ssh 
ufw allow 10000
ufw enable
ufw status
```
### Password Requirements
**Common Password**
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

**Common Auth**
```
nano /etc/pam.d/common-auth
```
Add this to bottom of ifile
```bash
auth required pam_faillock.so preauth deny=3 onerr=fail unlock_time=1800
auth required pam_faillock.so authfail deny=3 onerr=fail unlock_time=1800
```

**Login.defs**
```
PASS_MAX_DAYS	30
PASS_MIN_DAYS	2
PASS_MIN_LEN	10
PASS_WARN_AGE	7
ENCRYPT_METHOD SHA512
LOGIN_RETRIES 3
LOGIN_TIMEOUT 60

SYS_UID_MIN 100
SYS_UID_MAX 499
SYS_GID_MIN 100
SYS_GID_MAX 499

UID_MIN 1000
UID_MAX 60000
GID_MIN 1000
GID_MAX 60000

USERGROUPS_ENAB yes

UMASK 077
```
### Removing Media Files
Find audio/video files. You may need to replace `/` with `/home`  or `/usr/share` if there is lots of output
```bash
find /home -type f \( -name "*.mp3" -o -name "*.wav" -o -name "*.flac" -o -name "*.aac" -o -name "*.ogg" -o -name "*.wma" -o -name "*.m4a" -o -name "*.mp4" -o -name "*.avi" -o -name "*.mkv" -o -name "*.mov" -o -name "*.wmv" -o -name "*.webm" -o -name "*.3gp" -o -name "*.flv" -o -name "*.m4v" -o -name "*.asf" -o -name "*.ts" -o -name "*.ogg" \)
```
Find image files
```bash
find /home -type f \( -name "*.jpg" -o -name "*.jpeg" -o -name "*.png" -o -name "*.gif" -o -name "*.bmp" -o -name "*.tiff" -o -name "*.tif" -o -name "*.webp" -o -name "*.raw" -o -name "*.svg" \)
```
### Check for cron/init jobs
Look in Webmin for cron jobs, ask George before removing anything. Once that's done check who is allowed and not allowed to make cron jobs - again ask George
```bash
cat /etc/cron.d/cron.deny
nano /etc/cron.d/cron.allow
```
Make sure the correct people own the file
```bash
#add root to this file
chown root:root cron.allow
chmod 644 cron.allow
```
Now ask george about the output of the command below:
```bash
ls -la /etc/init/
ls -la /etc/init.d/
ls -la /etc/rc*.d
```
### Application Settings
Disable popup/ enable security features in Firefox
### Modify Kernel Things
Run the below and check nothing blows up
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
sysctl -w net.ipv6.conf.all.disable_ipv6 = 1
sysctl -w net.ipv6.conf.default.disable_ipv6 = 1
sysctl -w net.ipv6.conf.lo.disable_ipv6 = 1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.tcp_synack_retries=2
sysctl -w net.ipv4.tcp_syn_retries=5
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w vm.panic_on_oom=1
sysctl -w kernel.panic=10
sysctl -p
```
If that is all fine, then open this file
```
nano /etc/sysctl.conf
```
Add this to the file 
```
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.ip_forward=0
net.ipv4.tcp_syncookies=1
kernel.randomize_va_space=2
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_ratelimit=100
kernel.kptr_restrict=1
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
net.ipv4.icmp_echo_ignore_all=1
net.ipv4.tcp_max_syn_backlog=1280
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
net.ipv4.conf.all.log_martians=1
vm.panic_on_oom=1
kernel.panic=10
```

### User checks
Lock root user
```bash
passwd -l root
```
Check this directory for things 
```bash
ls /etc/sudoers.d
```
Check for users with UID 0, should be only one user shown
```bash
awk -F: '$3 == 0 { print "Username: " $1, "UID: " $3 }' /etc/passwd
```
Check for users with empty password (copy and paste this all in one go)
```bash
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
```
Look for hidden users, most of these will be system users who are fine but ask George
```bash
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

### Antivirus
NOTE: You will need to run the long install command in the [[#Software Updates]] section
==ASK GEORGE TO LOOK AT OUTPUT==
**Clamav**
Will take a long time
```
freshclam
clamscan -r /
```
**Chkrootkit**
```
chkrootkit -q
```
**Rkhunter**
First modify the config file 
```bash
gedit /etc/rkhunter.conf
```
Add the following to the bottom
```bash
MIRRORS_MODE=0
UPDATE_MIRRORS=1
WEB_CMD=""
```
Now run the check
```bash
rkhunter --update
rkhunter --propupd
rkhunter -c --enable all --disable none
```
### SSH
Open the config file 
```
nano /etc/ssh/sshd_config
```
Add/change this stuff
```bash
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

### Other Random Stuff
Disable systemd logging
```bash
systemctl stop systemd-journald.service
systemctl disable systemd-journald.service
systemctl mask systemd-journald.service

systemctl stop rsyslog.service
systemctl disable rsyslog.service
systemctl mask rsyslog.service
```
Check for running processes
```bash
ps axk start_time -o start_time,pid,user,cmd
```
Check sudoers file for NOPASSWD etc
```
visudo
```
Check all users have /bin/bash as login shell
```
gedit /etc/passwd
```
Check for backdoors
```bash
ss -an4
netstat -plunet
netstat -nwput
pgrep -a nc
```
Check PATH variable and environment stuff
```bash
echo $PATH
cat /etc/profile
cat /etc/environment
```
Check root directory for anything suspicious
```bash
ls /root/
```
Miscellaneous file inspection
```bash
nano /etc/resolv.conf
nano /etc/hosts
nano /etc/hosts.allow
nano /etc/hosts.deny
nano /etc/apt/sources.list
```
Check for world readable files
```bash
find / -type f -perm 777 2>/dev/null
```
Check for anything in home directories
```
ls /home/*/.bashrc
ls /home/*/.*
```
Check the skeleton directory
```bash
ls /etc/skel
```

### Ciphey 
To install Ciphey, first install docker
**Debian**
```bash
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
**Ubuntu**
```bash
# Add Docker's official GPG key:
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```
**Run Ciphey**
```bash
docker run -it --rm remnux/ciphey "=MXazlHbh5WQgUmchdHbh1EIy9mZgQXarx2bvRFI4VnbpxEIBBiO4VnbNVkU"
```


