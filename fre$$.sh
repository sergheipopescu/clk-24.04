#!/bin/bash

##
# Variables
##

set -a													# export all variables

scriptdir=$(dirname "$(realpath "$0")") 								# set script directory


##
# Start script
##

clear													# clear the screen

if [[ $# -eq 0 ]]; then											# if no argument
	echo
	echo
	echo
	read -r -p "$(echo -e "		Enter server hostname fqdn: \033[1;36m")" fqdn								# ask for domain and read input
else													# if argument exists
	fqdn=$1												# assign fqdn variable to first argument
fi

echo -e "\033[0m"											# color off
echo
echo

###################
## Customization ##
###################

# Set timezone and 24h clock
timedatectl set-timezone Europe/Bucharest
update-locale 'LC_TIME="C.UTF-8"'

# Add user with full name. Will be prompted for password
adduser noble --gecos "Clickwork IT Admin" --disabled-password

# Add user to the admin group
addgroup --system admin; echo "%admin ALL=(ALL) ALL" >> /etc/sudoers && adduser noble admin

# Copy root ssh key to user profile
cp -r /root/.ssh /home/noble
chown -R noble /home/noble/.ssh

# Set hostname
hostnamectl set-hostname "$fqdn"

# Install packages for customization and cleanup unneeded packages
apt-get update

DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confold" upgrade
DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y

apt-get install mc nano libwww-perl haveged fortune-mod software-properties-common dirmngr apt-transport-https argon2 btop -y &> /dev/null
apt-get --no-install-recommends -y install landscape-common

apt-get remove ufw -y

# Change ssh port
sed -i 's|#Port 22|Port 2282|' /etc/ssh/sshd_config

# Allow password authentication
sed -i 's|PasswordAuthentication no|PasswordAuthentication yes|' /etc/ssh/sshd_config

# Disable password authentication for root only
sed -i "/#MaxAuthTries/c\MaxAuthTries	3" /etc/ssh/sshd_config
sed -i 's|PermitRootLogin yes|PermitRootLogin prohibit-password|' /etc/ssh/sshd_config
sed -i "\$a\\\nMatch User root\n	PasswordAuthentication no" /etc/ssh/sshd_config

# motd cleanup
sed -i 's|ENABLED=1|ENABLED=0|' /etc/default/motd-news
sed -i '/Graph this data/d' /usr/lib/python3/dist-packages/landscape/sysinfo/landscapelink.py
sed -i '/landscape.canonical.com/d' /usr/lib/python3/dist-packages/landscape/sysinfo/landscapelink.py
sed -i 's|self._sysinfo.add_footnote(|self._sysinfo.add_footnote("")|' /usr/lib/python3/dist-packages/landscape/sysinfo/landscapelink.py
sed -i '/printf/i \echo' /etc/update-motd.d/00-header
sed -i '/printf/d' /etc/update-motd.d/10-help-text
sed -Ezi.orig \
  -e 's/(def _output_esm_service_status.outstream, have_esm_service, service_type.:\n)/\1    return\n/' \
  -e 's/(def _output_esm_package_alert.*?\n.*?\n.:\n)/\1    return\n/' \
  /usr/lib/update-notifier/apt_check.py
/usr/lib/update-notifier/update-motd-updates-available --force

# Customize login environment for user
sed -i '44,54 s/^/#/' /etc/bash.bashrc
sed -i '38,64 s/^/#/' /home/noble/.bashrc
sed -i "66i\\\tPS1='\${debian_chroot:+(\$debian_chroot)}\\\[\\\033[01;31m\\\]\\\u\\\[\\\033[01;32m\\\]@\\\[\\\033[01;34m\\\]\\\h\\\[\\\033[00m\\\]:\\\[\\\033[01;32m\\\]\\\w\\\[\\\033[00m\\\]# '\n" /home/noble/.bashrc
sed -i "\$a\\\necho\nif [ -x /usr/games/fortune ]; then\n    /usr/games/fortune -s\nfi\necho\necho\necho -e \"\\\033[01;30m                 Server maintained by \\\033[01;34mClickwork\\\033[37m|\\\033[01;34mClockwork IT\\\033[37m\!\"\necho" /home/noble/.bashrc

# Customize nanorc default text higlighting
cp -f "$scriptdir"/confs/env.default.nanorc /usr/share/nano/default.nanorc

# Download & Install CSF
cd /opt || { echo "Unable to change into /opt directory"; exit 1; }
wget https://download.configserver.com/csf.tgz &> /dev/null
tar xzvf csf.tgz &> /dev/null
cd csf || { echo "Unable to change into /opt/csf directory"; exit 1; }

./install.sh

# temporarily disable firewall
csf -x

hostname=$(hostname)

# Configure CSF
sed -i 's|TESTING = "1"|TESTING = "0"|' /etc/csf/csf.conf
sed -i '/TCP_IN =/c\TCP_IN = "2282"' /etc/csf/csf.conf
sed -i '/TCP_OUT =/c\TCP_OUT = "20,21,25,53,80,113,443,2282,11371"' /etc/csf/csf.conf
sed -i '/UDP_IN =/c\UDP_IN = ""' /etc/csf/csf.conf
sed -i '/UDP_OUT =/c\UDP_OUT = "20,21,53,113,123"' /etc/csf/csf.conf
#sed -i '/ICMP_IN =/c\ICMP_IN = "0"' /etc/csf/csf.conf
sed -i 's|IPV6 = "0"|IPV6 = "1"|' /etc/csf/csf.conf
sed -i '/TCP6_IN =/c\TCP6_IN = ""' /etc/csf/csf.conf
sed -i '/TCP6_OUT =/c\TCP6_OUT = ""' /etc/csf/csf.conf
sed -i '/UDP6_IN =/c\UDP6_IN = ""' /etc/csf/csf.conf
sed -i '/UDP6_OUT =/c\UDP6_OUT = ""' /etc/csf/csf.conf
sed -i '/LF_ALERT_TO =/c\LF_ALERT_TO = "alerts@clickwork.ro"' /etc/csf/csf.conf
sed -i "/LF_ALERT_FROM =/c\LF_ALERT_FROM = \"lfd@$hostname\"" /etc/csf/csf.conf
sed -i 's|RESTRICT_SYSLOG = "0"|RESTRICT_SYSLOG = "2"|' /etc/csf/csf.conf
sed -i 's|PS_INTERVAL = "0"|PS_INTERVAL = "60"|' /etc/csf/csf.conf
sed -i 's|PS_LIMIT = "10"|PS_LIMIT = "6"|' /etc/csf/csf.conf
sed -i 's|IPTABLES_LOG = "/var/log/messages"|IPTABLES_LOG = "/var/log/syslog"|' /etc/csf/csf.conf
sed -i 's|SYSLOG_LOG = "/var/log/messages"|SYSLOG_LOG = "/var/log/syslog"|' /etc/csf/csf.conf
sed -i 's|PS_PORTS = "0:65535,ICMP"|PS_PORTS = "0:65535,ICMP,BRD"|' /etc/csf/csf.conf
sed -i 's|LF_FTPD = "10"|LF_FTPD = "3"|' /etc/csf/csf.conf
sed -i 's|FTPD_LOG = "/var/log/messages"|FTPD_LOG = "/var/log/pure-ftpd/pure-ftpd.log"|' /etc/csf/csf.conf

# Whitelist gateway ip address
ip route show | grep -i 'default via'| awk '{print $3 }' | tee --append /etc/csf/csf.ignore >/dev/null

# Configure CSF/LFD Exclusions
cat "$scriptdir"/snips/csf.pignore.snip >> /etc/csf/csf.pignore

# Copy firewall messages from syslog to firewall logfile
mkdir /var/log/csf
touch /var/log/csf/csf.fw.log
chmod 640 /var/log/csf/csf.fw.log
chown syslog:adm /var/log/csf/csf.fw.log
echo -e "# Log kernel generated firewall log to file\n:msg,contains,\"Firewall:\" /var/log/csf/csf.fw.log" > /etc/rsyslog.d/22-firewall.conf

# logrotate firewall logs
echo -e '
/var/log/csf/*.log {
	daily
	missingok
	rotate 30
	compress
	delaycompress
	notifempty
	create 640 syslog adm
	dateext
}' > /etc/logrotate.d/csf

# Install clkcsf
cp -f "$scriptdir"/scripts/clkcsf /usr/sbin/clkcsf || fail
chmod +x /usr/sbin/clkcsf || fail

# Install crnkcln
cp -f "$scriptdir"/scripts/krnlcln /usr/sbin/krnlcln || fail
chmod +x /usr/sbin/krnlcln|| fail

###########################
## Last update & upgrade ##
###########################
apt-get update
apt-get upgrade -y
apt-get dist-upgrade -y


################################
## Enable firewall and reboot ##
################################
apt-get autoremove -y &> /dev/null & apt-get autoclean -y &> /dev/null
rm -rf "$scriptdir"
reboot