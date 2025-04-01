#!/bin/bash

set -a													# export all variables

if [[ $# -eq 0 ]]; then											# if no argument
	echo
	read -r -p "Enter domain name: " tld								# ask for domain and read input
else													# if argument exists
	tld=$1												# assign tld variable to first argument
fi



###################
## Customization ##
###################

# Set timezone and 24h clock
sudo timedatectl set-timezone Europe/Bucharest
sudo update-locale 'LC_TIME="C.UTF-8"'

# Set hostname
sudo hostnamectl set-hostname "$tld"

# Install packages for customization and cleanup unneeded packages
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confold" upgrade
sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y
sudo apt-get install mc nano libwww-perl haveged fortune-mod software-properties-common dirmngr apt-transport-https argon2 -y
sudo apt-get --no-install-recommends -y install landscape-common
sudo apt-get remove ufw -y

# Change ssh port
sudo sed -i 's|#Port 22|Port 2282|' /etc/ssh/sshd_config

# Allow password authentication
sudo sed -i 's|PasswordAuthentication no|PasswordAuthentication yes|' /etc/ssh/sshd_config

# Disable password authentication for root only
sudo sed -i "/#MaxAuthTries/c\MaxAuthTries	3" /etc/ssh/sshd_config
sudo sed -i 's|PermitRootLogin yes|PermitRootLogin prohibit-password|' /etc/ssh/sshd_config
sudo sed -i "\$a\\\nMatch User root\n	PasswordAuthentication no" /etc/ssh/sshd_config

# motd cleanup
sudo sed -i 's|ENABLED=1|ENABLED=0|' /etc/default/motd-news
sudo sed -i '/Graph this data/d' /usr/lib/python3/dist-packages/landscape/sysinfo/landscapelink.py
sudo sed -i '/landscape.canonical.com/d' /usr/lib/python3/dist-packages/landscape/sysinfo/landscapelink.py
sudo sed -i 's|self._sysinfo.add_footnote(|self._sysinfo.add_footnote("")|' /usr/lib/python3/dist-packages/landscape/sysinfo/landscapelink.py
sudo sed -i '/printf/i \echo' /etc/update-motd.d/00-header
sudo sed -i '/printf/d' /etc/update-motd.d/10-help-text
sudo sed -Ezi.orig \
  -e 's/(def _output_esm_service_status.outstream, have_esm_service, service_type.:\n)/\1    return\n/' \
  -e 's/(def _output_esm_package_alert.*?\n.*?\n.:\n)/\1    return\n/' \
  /usr/lib/update-notifier/apt_check.py
sudo /usr/lib/update-notifier/update-motd-updates-available --force

# Customize login environment for sudo user
sudo sed -i '44,54 s/^/#/' /etc/bash.bashrc
sudo sed -i '38,64 s/^/#/' /home/noble/.bashrc
sudo sed -i "66i\\\tPS1='\${debian_chroot:+(\$debian_chroot)}\\\[\\\033[01;31m\\\]\\\u\\\[\\\033[01;32m\\\]@\\\[\\\033[01;34m\\\]\\\h\\\[\\\033[00m\\\]:\\\[\\\033[01;32m\\\]\\\w\\\[\\\033[00m\\\]# '\n" /home/noble/.bashrc
sudo sed -i "\$a\\\necho\nif [ -x /usr/games/fortune ]; then\n    /usr/games/fortune -s\nfi\necho\necho\necho -e \"\\\033[01;30m                 Server maintained by \\\033[01;34mClickwork\\\033[37m|\\\033[01;34mClockwork IT\\\033[37m\!\"\necho" /home/noble/.bashrc

# Customize nanorc default text higlighting
sudo curl -s https://clickwork.ro/.down/_init/24.04/env.default.nanorc -o /usr/share/nano/default.nanorc

# Download & Install CSF
cd /opt || { echo "Unable to change directory"; exit 1; }
sudo wget https://download.configserver.com/csf.tgz
sudo tar xzvf csf.tgz
cd csf || { echo "Unable to change directory"; exit 1; }
sudo ./install.sh

# temporarily disable firewall
sudo csf -x

hostname=$(hostname)

# Configure CSF
sudo sed -i 's|TESTING = "1"|TESTING = "0"|' /etc/csf/csf.conf
sudo sed -i '/TCP_IN =/c\TCP_IN = "2282"' /etc/csf/csf.conf
sudo sed -i '/TCP_OUT =/c\TCP_OUT = "20,21,25,53,80,113,443,2282,11371"' /etc/csf/csf.conf
sudo sed -i '/UDP_IN =/c\UDP_IN = ""' /etc/csf/csf.conf
sudo sed -i '/UDP_OUT =/c\UDP_OUT = "20,21,53,113,123"' /etc/csf/csf.conf
sudo sed -i '/ICMP_IN =/c\ICMP_IN = "0"' /etc/csf/csf.conf
sudo sed -i 's|IPV6 = "0"|IPV6 = "1"|' /etc/csf/csf.conf
sudo sed -i '/TCP6_IN =/c\TCP6_IN = ""' /etc/csf/csf.conf
sudo sed -i '/TCP6_OUT =/c\TCP6_OUT = ""' /etc/csf/csf.conf
sudo sed -i '/UDP6_IN =/c\UDP6_IN = ""' /etc/csf/csf.conf
sudo sed -i '/UDP6_OUT =/c\UDP6_OUT = ""' /etc/csf/csf.conf
sudo sed -i '/LF_ALERT_TO =/c\LF_ALERT_TO = "alerts@clickwork.ro"' /etc/csf/csf.conf
sudo sed -i "/LF_ALERT_FROM =/c\LF_ALERT_FROM = \"lfd@$hostname\"" /etc/csf/csf.conf
sudo sed -i 's|RESTRICT_SYSLOG = "0"|RESTRICT_SYSLOG = "2"|' /etc/csf/csf.conf
sudo sed -i 's|PS_INTERVAL = "0"|PS_INTERVAL = "60"|' /etc/csf/csf.conf
sudo sed -i 's|PS_LIMIT = "10"|PS_LIMIT = "6"|' /etc/csf/csf.conf
sudo sed -i 's|IPTABLES_LOG = "/var/log/messages"|IPTABLES_LOG = "/var/log/syslog"|' /etc/csf/csf.conf
sudo sed -i 's|SYSLOG_LOG = "/var/log/messages"|SYSLOG_LOG = "/var/log/syslog"|' /etc/csf/csf.conf
sudo sed -i 's|PS_PORTS = "0:65535,ICMP"|PS_PORTS = "0:65535,ICMP,BRD"|' /etc/csf/csf.conf

# Configure CSF/LFD Exclusions
sudo curl -s https://clickwork.ro/.down/_init/24.04/csf.pignore.snip | sudo tee --append /etc/csf/csf.pignore > /dev/null

# Set firewall logfile and #dont# log to syslog
sudo mkdir /var/log/csf 
# echo -e "# Log kernel generated firewall log to file\n:msg,contains,\"Firewall:\" /var/log/csf/lfd.fw.log\n\n# Don't log messages to syslog\n& stop" | sudo tee /etc/rsyslog.d/22-firewall.conf
echo -e "# Log kernel generated firewall log to file\n:msg,contains,\"Firewall:\" /var/log/csf/csf.fw.log" | sudo tee /etc/rsyslog.d/22-firewall.conf > /dev/null

# logrotate firewall logs
echo -e '
/var/log/csf/* {
	daily
	missingok
	rotate 30
	compress
	delaycompress
	notifempty
	create 640 root adm
}' | sudo tee /etc/logrotate.d/csf > /dev/null



###########################
## Last update & upgrade ##
###########################

sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y



################################
## Enable firewall and reboot ##
################################
sudo csf -e
echo "You dungoofed! The server will self destruct!"
sudo reboot
