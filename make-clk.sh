#!/bin/bash

##
# Variables
##

set -a													# export all variables

scriptdir=$(dirname "$0")										# set script directory

okay () {
	echo -e "[\033[32m OK \033[0m]\n"								# print okay function
}	

fail () {
	echo -e "\n \033[1;91m[FAILED]\033[0m"; echo; exit 1						# print fail and exit function
}

spinny () {
	while :; do for c in / - \\ \|; do printf '%s\b' "$c"; sleep 0.1; done; done			# spinner
}


##
# Start script
##

clear													# clear the screen

if [[ $# -eq 0 ]]; then											# if no argument
	echo
	echo
	echo
	read -r -p "		Enter server hostname fqdn: \033[1;36m" fqdn								# ask for domain and read input
else													# if argument exists
	fqdn=$1												# assign tld variable to first argument
fi

tput civis 												# disable cursor
\033[0m													# color off

###################
## Customization ##
###################

# Set timezone and 24h clock
echo
echo -n "Setting timezone and 24h clock .................. "
timedatectl set-timezone Europe/Bucharest
update-locale 'LC_TIME="C.UTF-8"'
okay

# Set hostname
echo
echo -n "Setting hostname ................................ "
hostnamectl set-hostname "$fqdn"
okay

# Install packages for customization and cleanup unneeded packages
echo
echo -n "Running update .................................. "
spinny & apt-get update &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null
echo
echo -n "Running upgrades ................................ "
spinny & DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confold" upgrade &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null
echo
echo -n "Running more upgrades ........................... "
spinny & DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null
echo
echo -n "Installing misc software ........................ "
spinny & apt-get install mc nano libwww-perl haveged fortune-mod software-properties-common dirmngr apt-transport-https argon2 btop -y &> /dev/null
apt-get --no-install-recommends -y install landscape-common &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null
echo
echo -n "Uninstalling ufw ................................ " 
spinny & apt-get remove ufw -y &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null


# Change ssh port
echo
echo -n "Changing SSH server port ........................ " 
sed -i 's|#Port 22|Port 2282|' /etc/ssh/sshd_config
okay

# Allow password authentication
echo
echo -n "Configure SSH server password authentication .... "
sed -i 's|PasswordAuthentication no|PasswordAuthentication yes|' /etc/ssh/sshd_config

# Disable password authentication for root only
sed -i "/#MaxAuthTries/c\MaxAuthTries	3" /etc/ssh/sshd_config
sed -i 's|PermitRootLogin yes|PermitRootLogin prohibit-password|' /etc/ssh/sshd_config
sed -i "\$a\\\nMatch User root\n	PasswordAuthentication no" /etc/ssh/sshd_config
okay

# motd cleanup
echo
echo -n "Cleaning up motd ................................ "
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
okay

# Customize login environment for user
echo
echo -n "Customize bash & nano ........................... "
sed -i '44,54 s/^/#/' /etc/bash.bashrc
sed -i '38,64 s/^/#/' /home/noble/.bashrc
sed -i "66i\\\tPS1='\${debian_chroot:+(\$debian_chroot)}\\\[\\\033[01;31m\\\]\\\u\\\[\\\033[01;32m\\\]@\\\[\\\033[01;34m\\\]\\\h\\\[\\\033[00m\\\]:\\\[\\\033[01;32m\\\]\\\w\\\[\\\033[00m\\\]# '\n" /home/noble/.bashrc
sed -i "\$a\\\necho\nif [ -x /usr/games/fortune ]; then\n    /usr/games/fortune -s\nfi\necho\necho\necho -e \"\\\033[01;30m                 Server maintained by \\\033[01;34mClickwork\\\033[37m|\\\033[01;34mClockwork IT\\\033[37m\!\"\necho" /home/noble/.bashrc

# Customize nanorc default text higlighting
cp -f "$scriptdir"/confs/env.default.nanorc /usr/share/nano/default.nanorc
okay


# Download & Install CSF
echo
echo -n "Download and install CSF ........................ "
cd /opt || { echo "Unable to change into /opt directory"; exit 1; }
wget https://download.configserver.com/csf.tgz &> /dev/null
tar xzvf csf.tgz &> /dev/null
cd csf || { echo "Unable to change into /opt/csf directory"; exit 1; }

spinny & ./install.sh &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null

# temporarily disable firewall
echo
echo -n "Disable firewall temporarily .................... "
spinny & csf -x &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null


hostname=$(hostname)

# Configure CSF
echo
echo -n "Configure CSF ................................... "
sed -i 's|TESTING = "1"|TESTING = "0"|' /etc/csf/csf.conf
sed -i '/TCP_IN =/c\TCP_IN = "2282"' /etc/csf/csf.conf
sed -i '/TCP_OUT =/c\TCP_OUT = "20,21,25,53,80,113,443,2282,11371"' /etc/csf/csf.conf
sed -i '/UDP_IN =/c\UDP_IN = ""' /etc/csf/csf.conf
sed -i '/UDP_OUT =/c\UDP_OUT = "20,21,53,113,123"' /etc/csf/csf.conf
sed -i '/ICMP_IN =/c\ICMP_IN = "0"' /etc/csf/csf.conf
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
okay

# Configure CSF/LFD Exclusions
echo
echo -n "Configure LFD exclusions ........................ "
cat snips/csf.pignore.snip >> /etc/csf/csf.pignore || fail ; okay

# Copy firewall messages from syslog to firewall logfile
echo
echo -n "Create firewall log ............................. "
mkdir /var/log/csf 
echo -e "# Log kernel generated firewall log to file\n:msg,contains,\"Firewall:\" /var/log/csf/csf.fw.log" > /etc/rsyslog.d/22-firewall.conf || fail ; okay
okay

# logrotate firewall logs
echo
echo -n "Create logrotate for firewall logs .............. "
echo -e '
/var/log/csf/*.log {
	daily
	missingok
	rotate 30
	compress
	delaycompress
	notifempty
	create 640 syslog adm
}' > /etc/logrotate.d/csf || fail ; okay



###########################
## Last update & upgrade ##
###########################
echo
echo -n "Running update .................................. "
spinny & apt-get update &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null
echo
echo -n "Running upgrades ................................ "
spinny & apt-get upgrade -y &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null
echo
echo -n "Running more upgrades ........................... "
spinny & apt-get dist-upgrade -y &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null



################################
## Enable firewall and reboot ##
################################
echo
echo -n "Enabling firewall ............................... "
spinny &
csf -e &> /dev/null || fail ; { okay; kill $! && wait $!; } 2>/dev/null

echo
echo -n "Cleanup ......................................... "
rm -rf "$scriptdir" || fail ; okay

echo
echo -e "Rebooting ................................... \033[32m-->"

tput cnorm 													# enable cursor
reboot
