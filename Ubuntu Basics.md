## Resources
Linux Manual From Cybercenturion website:
<https://cybersecuritychallenge.org.uk/linux-training-materials>

## Installing Packages
`sudo apt update`
`sudo apt install gufw` - where gufw is the package

## Firewall
Open gufw
Set incoming to deny
Outgoing to allow

## Checking Users:
- Settings
- Users and Groups
- Check users, delete if not on either list
- Check administrator rights, disable if not on list
- Change passwords if not secure ()
- Use password generator, more than 12 characters <https://www.lastpass.com/features/password-generator?length=12&encryption-style=all-characters&uppercase=on&lowercase=on&numbers=on&symbols=on>

## General Tips
No output = success
If you see permission denied:
- use sudo in front of command

## Check for Media Files
- `cd /home`
- `du -sh *`
- Look for users with more than roughly 4K of disk usage 
- `sudo nautilus`
- Use sidebar 'other locations' followed by 'Computer' to go to / directory
- Double Click /home folder
- Look in each folder that had lot sof space taken up and check for media files
- Media files could be jpg, png, mp4, mp3 etc

## Remove Prohibited Software
- Check desktop for any applications eg: nmap, wireshark
- `sudo apt install aptitude`
- `comm -23 <(aptitude search '~i !~M' -F '%p' | sed "s/ *$//" | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u)`
- List of packages will appear
- Look through each package use google to work out what it does
- Normally hacking tools or media applications are not allowed
- To remove them use `sudo apt remove {package name}`
### Possible Packages to Remove
		nmap
		wireshark
		ophcrack
		nbtscan
- If that gives 'package not found' make sure you copy the exact name from the long command above 

## Group Management:
- It might say in the scenario that a new group needs to be added or we need to add a user to a group
- To add a new group:
- `sudo groupadd {name of group}`
- To add a user to a group 
- `sudo usermod -a -G {group to add to} {username}`

**In the scenario there may be a list of essential services that should not be stopped**
## Service Management:
- This command lists the listening ports on the computer
- `lsof -i -P -n`
- Look up process on google in first column of each row in the list and decide whether it needs to be stopped
- `sudo systemctl | grep running`
- This command will show all running services
- Look through this list to find the service you need to stop
- `sudo systemctl status {service name}`
- If it says it's running, consider stopping it with:
- `sudo systemctl stop {service name}`
- `sudo systemctl start {service name}`
- This command start the service if you decide you need to later
### Possible Services to Disable
- ngnix (Web Server)
- smtp (Mail Server)
- ssh
- vsftpd
- nfs

`