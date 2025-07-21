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

apt-get install mc nano libwww-perl haveged fortune-mod software-properties-common dirmngr apt-transport-https argon2 btop -y
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
cd /opt || { echo "Unable to change directory"; exit 1; }
wget https://download.configserver.com/csf.tgz
tar xzvf csf.tgz
cd csf || { echo "Unable to change directory"; exit 1; }

./install.sh

# temporarily disable firewall
csf -x

hostname=$(hostname)

# Configure CSF
sed -i 's|TESTING = "1"|TESTING = "0"|' /etc/csf/csf.conf
sed -i '/TCP_IN =/c\TCP_IN = "21,80,443,2282,40001:40128"' /etc/csf/csf.conf
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
cp -f "$scriptdir"/scripts/clkcsf /usr/sbin/clkcsf
chmod +x /usr/sbin/clkcsf

# Install crnkcln
cp -f "$scriptdir"/scripts/krnlcln /usr/sbin/krnlcln
chmod +x /usr/sbin/krnlcln|| fail


################################
## Install & configure Apache ##
################################

# Add ondrej repo for newest versions of apache
add-apt-repository ppa:ondrej/apache2 -y
apt-get update

# Install apache
apt-get install apache2 -y

# Download custom security configuration
cp -f "$scriptdir"/confs/a2.conf /etc/apache2/conf-available/clk.a2.conf


# Download deflate config
cp -f "$scriptdir"/confs/a2.deflate.conf /etc/apache2/conf-available/clk.a2.deflate.conf

# Enable configs
a2enconf clk.a2 clk.a2.deflate

# Enable modules
a2enmod alias rewrite headers deflate

# Disable modules
a2dismod status autoindex -f

## Security tweaks ##
sed -i 's|ServerTokens OS|ServerTokens Prod|' /etc/apache2/conf-enabled/security.conf
sed -i 's|ServerSignature On|ServerSignature Off|' /etc/apache2/conf-enabled/security.conf

## Apache optimization tweaks ##
sed -i 's|Timeout 300|Timeout 60|' /etc/apache2/apache2.conf
sed -i 's|KeepAliveTimeout 5|KeepAliveTimeout 3|' /etc/apache2/apache2.conf

## mpm-event config download and enable
# sed -i 's/^\([^#].*\)/# \1/g' /etc/apache2/mods-available/mpm_event.conf # older version of commenting out the current config
mv /etc/apache2/mods-available/mpm_event.conf /etc/apache2/mods-available/mpm_event.conf.bak
cp -f "$scriptdir"/confs/a2.mpm_event.conf /etc/apache2/mods-available/mpm_event.conf
a2enmod mpm_event

# change listening port and disable default website
mv /etc/apache2/ports.conf /etc/apache2/ports.conf.default
echo "Listen 9080" | tee /etc/apache2/ports.conf > /dev/null
a2dissite 000-default
rm /var/www/html/*
rmdir /var/www/html

# create apache blackhole
echo -e '
<VirtualHost *:9080>
	ServerName CygX1
	Redirect 403
	ErrorLog /var/log/apache2/error.log
	CustomLog /var/log/apache2/access.log loghost
</VirtualHost>
' | tee /etc/apache2/sites-available/0-blackhole.conf
a2ensite 0-blackhole

# Define loghost logging format
echo -e "\n# Define loghost logging format" | tee --append /etc/apache2/apache2.conf
echo -e 'LogFormat "%a %l %u %t \"%{Host}i\" \"%r\" %>s %O \"%{Referer}i\"" loghost' | tee --append /etc/apache2/apache2.conf

# Stop apache
systemctl stop apache2


#################################
## Install & configure MariaDB ##
#################################

# Add MariaDB repo
curl -sS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | bash -s -- --mariadb-server-version=11.4 --skip-maxscale

# Install MariaDB
apt-get update
apt-get install mariadb-server -y

# Enable error log
sed -i '/log_error/s/^#//g' /etc/mysql/mariadb.conf.d/50-server.cnf

# Security tweaks
echo -e "\n\nn\n\n\n\n\n" | mariadb-secure-installation

## create random mariadb password ##
mdbpass=$(openssl rand -base64 29 | tr -d "/" | cut -c1-20)
echo "The root mariaDB password is:	$mdbpass" | tee --append /root/salt > /dev/null

# change MariaDB root password
mariadb << END
ALTER USER 'root'@'localhost' IDENTIFIED BY '$mdbpass';
rename user 'root'@'localhost' to 'mariadmin'@'localhost';
FLUSH PRIVILEGES;
END

## Optimization tweaks ##

sed -i '/Fine Tuning/{N;N;s/$/\nquery_cache_size = 0/}' /etc/mysql/mariadb.conf.d/50-server.cnf
sed -i '/max_connections/c\max_connections         = 400' /etc/mysql/mariadb.conf.d/50-server.cnf
sed -i '/innodb_buffer_pool_size =/c\innodb_buffer_pool_size = 1G\nkey_buffer_size = 10M' /etc/mysql/mariadb.conf.d/50-server.cnf



####################################
## Install & configure PHP8.4-fpm ##
####################################

# Add ondrej repo for newest versions of php and refresh
add-apt-repository ppa:ondrej/php -y
apt-get update

# Set php version to install
phpvrs=8.4

# Install php-fpm + common extensions
apt-get install mcrypt php$phpvrs-{fpm,mysql,gd,mbstring,mcrypt,opcache,xml,zip} -y

# Install specific extensions for WordPress
apt-get install php$phpvrs-{curl,dom,exif,fileinfo,igbinary,imagick,intl,memcached} -y

# php-fpm optimization tweaks
sed -i 's|pm.max_children = 5|pm.max_children = 50|' /etc/php/$phpvrs/fpm/pool.d/www.conf
sed -i 's|upload_max_filesize = 2M|upload_max_filesize = 200M|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|post_max_size = 8M|post_max_size = 200M|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|memory_limit = 128M|memory_limit = 512M|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|max_execution_time = 30|max_execution_time = 300|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|max_input_time = 60|max_input_time = 300|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|;max_input_vars = 1000|max_input_vars = 20000|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|;realpath_cache_size = 4096k|realpath_cache_size = 4096k|' /etc/php/$phpvrs/fpm/php.ini

# enable opcache + optimization tweaks
sed -i '/opcache.enable=/c\opcache.enable=1' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.memory_consumption=/c\opcache.memory_consumption=256' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.max_accelerated_files=/c\opcache.max_accelerated_files=30000' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.max_wasted_percentage=/c\opcache.max_wasted_percentage=15' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.validate_timestamps=/c\opcache.validate_timestamps=1' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.revalidate_freq=/c\opcache.revalidate_freq=0' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.enable_file_override=/c\opcache.enable_file_override=1' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.interned_strings_buffer/c\opcache.interned_strings_buffer=64' /etc/php/$phpvrs/fpm/php.ini

# proxy error pages back to apache
sed -i '/AllowOverride All/{s/$/\n  ProxyErrorOverride On/}' /etc/apache2/conf-available/clk.a2.conf

# Enable php-fpm config
a2enconf php$phpvrs-fpm

# Disable modules, including php-mod to be able to use php-fpm
a2dismod php$phpvrs cgi -f

# move php logs
mkdir /var/log/php
sed -i "/error_log =/c\error_log = /var/log/php/php$phpvrs-fpm.log" /etc/php/$phpvrs/fpm/php-fpm.conf
sed -i "/\/var\/log/c\/var\/log\/php\/php$phpvrs-fpm.log {" /etc/logrotate.d/php$phpvrs-fpm

# Enable php-fpm and apache proxy modules to php-fpm
a2enmod proxy_fcgi setenvif



####################################
## Install & configure PHP7.4-fpm ##
####################################

# Set php version to install
phpvrs=7.4

# Install php-fpm + common extensions
apt-get install mcrypt php$phpvrs-{fpm,mysql,gd,mbstring,mcrypt,opcache,xml,zip} -y

# Install specific extensions for WordPress
apt-get install php$phpvrs-{curl,dom,exif,fileinfo,igbinary,imagick,intl,memcached} -y

# php-fpm optimization tweaks
sed -i 's|pm.max_children = 5|pm.max_children = 50|' /etc/php/$phpvrs/fpm/pool.d/www.conf
sed -i 's|upload_max_filesize = 2M|upload_max_filesize = 200M|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|post_max_size = 8M|post_max_size = 200M|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|memory_limit = 128M|memory_limit = 512M|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|max_execution_time = 30|max_execution_time = 300|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|max_input_time = 60|max_input_time = 300|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|;max_input_vars = 1000|max_input_vars = 20000|' /etc/php/$phpvrs/fpm/php.ini
sed -i 's|;realpath_cache_size = 4096k|realpath_cache_size = 4096k|' /etc/php/$phpvrs/fpm/php.ini

# enable opcache + optimization tweaks
sed -i '/opcache.enable=/c\opcache.enable=1' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.memory_consumption=/c\opcache.memory_consumption=256' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.max_accelerated_files=/c\opcache.max_accelerated_files=30000' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.max_wasted_percentage=/c\opcache.max_wasted_percentage=15' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.validate_timestamps=/c\opcache.validate_timestamps=1' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.revalidate_freq=/c\opcache.revalidate_freq=0' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.enable_file_override=/c\opcache.enable_file_override=1' /etc/php/$phpvrs/fpm/php.ini
sed -i '/opcache.interned_strings_buffer/c\opcache.interned_strings_buffer=64' /etc/php/$phpvrs/fpm/php.ini

# Enable php-fpm config // don't enable and let 8.4 be default. Include conf in vhost file to redirect php to 7.4
# a2enconf php$phpvrs-fpm

# Enable php-fpm and apache proxy modules to php-fpm // not needed, already enabled
# a2enmod proxy proxy_fcgi setenvif

# move php logs
sed -i "/error_log =/c\error_log = /var/log/php/php$phpvrs-fpm.log" /etc/php/$phpvrs/fpm/php-fpm.conf
sed -i "/\/var\/log/c\/var\/log\/php\/php$phpvrs-fpm.log {" /etc/logrotate.d/php$phpvrs-fpm



###################################
## Install & configure memcached ##
###################################

# Install memcached
#apt-get install memcached libmemcached-tools -y

# Get current php version
# phpverion=$(php -r 'echo PHP_MAJOR_VERSION;'&&echo -n .&&php -r 'echo PHP_MINOR_VERSION;')

# Install php extension
# apt-get install php$phpversion-memcached

# configure memcached max memory and logs
#mkdir /var/log/memcached
#sed -i '/logfile \/var\/log/c\logfile \/var\/log\/memcached\/memcached.log' /etc/memcached.conf
#sed -i '/-m /c\-m 1024' /etc/memcached.conf
#systemctl start memcached

# logrotate memcached logs
#echo -e '
#/var/log/memcached/*.log {
#	daily
#	missingok
#	rotate 30
#	compress
#	delaycompress
#	notifempty
#	create 640 root adm
#	dateext
#}' | tee /etc/logrotate.d/memcached > /dev/null



####################################
## Install & configure phpMyAdmin ##
####################################

cd /opt || { echo "Unable to change directory"; exit 1; }
wget https://www.phpmyadmin.net/downloads/phpMyAdmin-latest-english.tar.gz
tar xvf phpMyAdmin-latest-english.tar.gz
rm ./*.tar.gz
mv phpMyAdmin-* /usr/share/phpmyadmin
mkdir -p /var/lib/phpmyadmin/tmp
chown -R www-data:www-data /var/lib/phpmyadmin
mkdir /etc/phpmyadmin/
cp /usr/share/phpmyadmin/config.sample.inc.php /usr/share/phpmyadmin/config.inc.php

# Set pma db password and blowfish secret
pmadbpass=$(openssl rand -base64 29 | tr -d "/" | cut -c1-20)
echo "The pm--admin password is:	$pmadbpass" | tee --append /root/salt > /dev/null
pmabfish=$(openssl rand -base64 24)
echo "The phpMyAdmin blowfish is:	$pmabfish" | tee --append /root/salt > /dev/null

# customize phpMyAdmin
sed -i "/blowfish_secret/c\$cfg['blowfish_secret'] = '$pmabfish';" /usr/share/phpmyadmin/config.inc.php
sed -i "/controlhost/c\$cfg['Servers'][\$i]['controlhost'] = 'localhost';" /usr/share/phpmyadmin/config.inc.php
sed -i "/controluser/c\$cfg['Servers'][\$i]['controluser'] = 'pm--admin';" /usr/share/phpmyadmin/config.inc.php
sed -i "/controlpass/c\$cfg['Servers'][\$i]['controlpass'] = '$pmadbpass';" /usr/share/phpmyadmin/config.inc.php
sed -i '/pmadb/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/bookmarktable/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/relation/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/table_info/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/table_coords/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/pdf_pages/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/column_info/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/history/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/table_uiprefs/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/tracking/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/userconfig/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/recent/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/favorite/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/users/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/usergroups/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/navigationhiding/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/savedsearches/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/central_columns/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/designer_settings/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i '/export_templates/s/^...//' /usr/share/phpmyadmin/config.inc.php
sed -i "76i\$cfg['TempDir'] = '/var/lib/phpmyadmin/tmp';" /usr/share/phpmyadmin/config.inc.php
sed -i "/TempDir/{s/$/\n\$cfg['ThemeDefault'] = 'metro';/}" /usr/share/phpmyadmin/config.inc.php

# import schema
mariadb -umariadmin -p"$mdbpass" < /usr/share/phpmyadmin/sql/create_tables.sql

# create pma db admin
mariadb -umariadmin -p"$mdbpass" << END
GRANT ALL PRIVILEGES ON phpmyadmin.* TO 'pm--admin'@'localhost' IDENTIFIED BY '$pmadbpass';
END

# import phpmyadmin.conf
cp -f "$scriptdir"/confs/a2.pma.conf /etc/apache2/conf-available/clk.a2.pma.conf

a2enconf clk.a2.pma



#####################
## Wildcard config ##
#####################

mkdir /var/www/wildcard

echo -e '<?php\n\n	phpinfo( );\n\n?>' | tee /var/www/wildcard/info.php > /dev/null

# shellcheck disable=SC2016
echo -e '
<?php

$meminstance = new Memcached();

$meminstance->addServer("127.0.0.1",11211);

$result = $meminstance->get("test");

if ($result) {
    echo $result;
} else {
    echo "No matching key found. Refresh the browser to add it!";
    $meminstance->set("test", "Successfully retrieved the data!") or die("Could not save anything to memcached...");
}
?>' | tee /var/www/wildcard/cache.php > /dev/null

cd /opt || exit
git clone https://github.com/RobiNN1/phpCacheAdmin

mv phpCacheAdmin /var/www/wildcard/

rm -r /var/www/wildcard/phpCacheAdmin/.*

chown -R www-data /var/www/wildcard
chmod -R 0500 /var/www/wildcard
chmod -R 0700 /var/www/wildcard/phpCacheAdmin
find /var/www/wildcard -type f -print0 | xargs -0 chmod 400

echo -e '
	Alias /php.info /var/www/wildcard/info.php
	Alias /php.cache /var/www/wildcard/cache.php
	Alias /php.CA /var/www/wildcard/phpCacheAdmin/

	<Directory /var/www/wildcard>
	  Require ip 95.77.98.180
	</Directory>

' | tee /etc/apache2/conf-available/wildcard.conf > /dev/null

a2enconf wildcard



###############################
## Install & configure nginx ##
###############################

# Add ondrej repo for newest version
add-apt-repository ppa:ondrej/nginx -y

# Install nginx
apt-get update
apt-get install nginx -y

# Security | Remove defaults
rm /etc/nginx/sites-enabled/default
rm /var/www/html/*
rmdir /var/www/html

# Security | Create pem certificate for blackhole
mkdir /etc/nginx/ssl
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout /etc/nginx/ssl/blackhole.key -out /etc/nginx/ssl/blackhole.pem -sha256 -days 3650 -nodes -subj "/CN=Cyg X-1"
# deprecated RSA4096 key# openssl req -x509 -newkey rsa:4096 -keyout /etc/nginx/ssl/blackhole.key -out /etc/nginx/ssl/blackhole.pem -sha256 -days 3650 -nodes -subj "/CN=Cyg X-1"

# Security | Create vhost for blackhole
echo -e '
# Blackhole server for requests without SNI
server {
	
	listen		80 default_server;
	listen		443 default_server ssl;
	
	ssl_certificate     /etc/nginx/ssl/blackhole.pem;				# SSL certificate
	ssl_certificate_key /etc/nginx/ssl/blackhole.key;				# SSL Key
	access_log /var/log/nginx/blackhole.log loghost;				# logging with loghost

	return 444;
}
'| tee /etc/nginx/sites-available/blackhole > /dev/null

# Security | Enable blackhole srvblock
ln -s /etc/nginx/sites-available/blackhole /etc/nginx/sites-enabled/blackhole

# SSL | Create dhparam file
openssl dhparam -dsaparam -out /etc/nginx/ssl/dhparam.pem 4096

# SSL | Disable ssl protocols in default config
sed -i 's|ssl_protocols|# &|' /etc/nginx/nginx.conf
sed -i 's|ssl_prefer_server_ciphers|# &|' /etc/nginx/nginx.conf

# Security | Download custom conf 
cp -f "$scriptdir"/confs/ngx.conf /etc/nginx/conf.d/clk.ngx.conf

# Logging | Copy snippets
cp -f "$scriptdir"/snips/clk.ngx* /etc/nginx/snippets/

# Logging | Enable loghost on default settings
sed -i '/access_log/c\	include /etc/nginx/snippets/clk.ngx.loghost.snip;\n	access_log /var/log/nginx/access.log loghost;' /etc/nginx/nginx.conf


# Proxy | Enable mod_remoteip and change LogFormat to enable client IP logging
a2enmod remoteip
sed -i 's|LogFormat "%h|LogFormat "%a|' /etc/apache2/apache2.conf



#####################################################
## Install and configure Bad Bot Blocker for nginx ##
#####################################################

# download and run bbb installer
wget https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/install-ngxblocker -O /usr/local/sbin/install-ngxblocker
chmod +x /usr/local/sbin/install-ngxblocker
install-ngxblocker -x

# remove setup
rm /usr/local/sbin/setup-ngxblocker

# schedule ngxblocker
crontab -l | { cat; echo "0 5 * * 6 /usr/local/sbin/update-ngxblocker >/dev/null 2>&1"; } | crontab -

# Include in server{} block on each vhost
# include /etc/nginx/bots.d/blockbots.conf;
# include /etc/nginx/bots.d/ddos.conf;



#################################
## Install letsencrypt/certbot ##
#################################

# install certbot for nginx
apt-get install python3-certbot-nginx -y

# set hostname variable again
hostname=$(hostname)

# get certificate for hostname
certbot certonly --nginx --non-interactive --agree-tos --quiet --test-cert -m postmaster@"$hostname" -d "$hostname"

# install post renew hook
# shellcheck disable=SC2016
echo -e '
#!/bin/bash
hostname=$(hostname)
cat /etc/letsencrypt/live/"$hostname"/fullchain.pem /etc/letsencrypt/live/"$hostname"/privkey.pem | tee /etc/ssl/private/pure-ftpd.pem > /dev/null
lampstart
' | tee /etc/letsencrypt/renewal-hooks/post/clk.restack.sh > /dev/null
chmod +x /etc/letsencrypt/renewal-hooks/post/clk.restack.sh



############################################
## Install and configure posftix sendmail ##
############################################

# preseed answers
debconf-set-selections <<< "postfix postfix/mailname string $hostname"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"
apt-get install --assume-yes postfix

# modify listening ports
sed -i "/inet_interfaces/c\inet_interfaces = localhost" /etc/postfix/main.cf


#configure SSL certificates (for sending)
sed -i "/smtpd_tls_cert_file/c\smtpd_tls_cert_file=/etc/letsencrypt/live/$hostname/fullchain.pem" /etc/postfix/main.cf
sed -i "/smtpd_tls_key_file/c\smtpd_tls_key_file=/etc/letsencrypt/live/$hostname/privkey.pem" /etc/postfix/main.cf

# modify postfix logging
mkdir /var/log/postfix
postconf maillog_file=/var/log/postfix/mail.log

# logrotate postfix logs
echo -e '
/var/log/postfix/*.log {
	daily
	missingok
	rotate 30
	compress
	delaycompress
	notifempty
	create 640 root adm
	dateext
}' | tee /etc/logrotate.d/postfix > /dev/null



##################################
## Install & configure pureFTPd ##
##################################

apt-get -y install pure-ftpd-mysql

# Create pftpd user
groupadd -g 2001 pftpd
useradd -u 2001 -s /bin/false -d /bin/null -c "Pureftpd User" -g pftpd pftpd

# Generate ftp database password
ftpdbpass=$(openssl rand -base64 29 | tr -d "/" | cut -c1-20)
echo "The pftpd-admin password is:	$ftpdbpass" | tee --append /root/salt > /dev/null

# Create ftp database and schema
mariadb -umariadmin -p"$mdbpass" << END
CREATE DATABASE pftpd;
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP ON pftpd.* TO 'pftpd-admin'@'localhost' IDENTIFIED BY '$ftpdbpass';
FLUSH PRIVILEGES;
USE pftpd;
CREATE TABLE ftpd (User varchar(64) NOT NULL default '',
status enum('0','1') NOT NULL default '0',
Password varchar(160) NOT NULL default '',
Uid varchar(11) NOT NULL default '-1',
Gid varchar(11) NOT NULL default '-1',
Dir varchar(128) NOT NULL default '',
ULBandwidth smallint(5) NOT NULL default '0',
DLBandwidth smallint(5) NOT NULL default '0',
comment tinytext NOT NULL,
ipaccess varchar(15) NOT NULL default '*',
QuotaSize smallint(5) NOT NULL default '0',
QuotaFiles int(11) NOT NULL default 0,
PRIMARY KEY (User),UNIQUE KEY User (User)
) ENGINE=MyISAM;
END

# Backup original db connect config file
mv /etc/pure-ftpd/db/mysql.conf /etc/pure-ftpd/db/mysql.conf.orig

# Create db connect config file
cp -f "$scriptdir"/confs/pftpd.mysql.conf /etc/pure-ftpd/db/mysql.conf
sed -i "/MYSQLUser/{s/$/\nMYSQLPassword	$ftpdbpass/}" /etc/pure-ftpd/db/mysql.conf

# Enable chroot
echo "yes" | tee /etc/pure-ftpd/conf/ChrootEveryone > /dev/null

# Create homedir
echo "yes" | tee /etc/pure-ftpd/conf/CreateHomeDir > /dev/null

# Optimize by disabling hostname lookup
echo "yes" | tee /etc/pure-ftpd/conf/DontResolve > /dev/null

# Minimum UID
echo "33" | tee /etc/pure-ftpd/conf/MinUID > /dev/null

# Enable TLS
echo "1" | tee /etc/pure-ftpd/conf/TLS > /dev/null

# Set passive ports
echo "40001 40128" | tee /etc/pure-ftpd/conf/PassivePortRange > /dev/null

# Set passive IP
#curl -s ifconfig.me | tee /etc/pure-ftpd/conf/ForcePassiveIP  > /dev/null
curl -s ipinfo.io/ip | tee /etc/pure-ftpd/conf/ForcePassiveIP  > /dev/null

# Install SSL certificate
#mkdir -p /etc/ssl/private/
#openssl req -x509 -nodes -days 7300 -newkey rsa:2048 -keyout /etc/ssl/private/pure-ftpd.pem -out /etc/ssl/private/pure-ftpd.pem -subj "/C=RO/ST=Bucharest/L=Bucharest/O=Clickwork/OU=IT/CN=$hostname"
cat /etc/letsencrypt/live/"$hostname"/fullchain.pem /etc/letsencrypt/live/"$hostname"/privkey.pem | tee /etc/ssl/private/pure-ftpd.pem > /dev/null
chmod 600 /etc/ssl/private/pure-ftpd.pem

# Disable anon ftp and set idle time
sed -i "/NoAnonymous/c\NoAnonymous		yes" /etc/pure-ftpd/pure-ftpd.conf
sed -i "/MaxIdleTime/c\MaxIdleTime		5" /etc/pure-ftpd/pure-ftpd.conf


# Configure pureftpd logging
echo -e "# Log kernel generated FTP log to file\n:syslogtag, isequal, \"pure-ftpd:\" /var/log/pure-ftpd/pure-ftpd.log\n\n# Don't log messages to syslog\n& stop" | tee /etc/rsyslog.d/23-pftpd.conf > /dev/null
chown root:syslog /var/log/pure-ftpd
chmod 0770 /var/log/pure-ftpd

# logrotate ftp logs
echo -e '
/var/log/pure-ftpd/pure-ftpd.log {
        weekly
        missingok
        rotate 7
        compress
        delaycompress
        postrotate
                /usr/sbin/pure-ftpd-control restart >/dev/null
        endscript
        notifempty
}' | tee /etc/logrotate.d/pure-ftpd > /dev/null



#############################
## Download custom scripts ##
#############################

mkdir /etc/apache2/vhosts
mkdir /etc/nginx/blocks
cp -f "$scriptdir"/blocks/a2* /etc/apache2/vhosts
cp- f "$scriptdir"/blocks/ngx* /etc/nginx/blocks

cp -f "$scriptdir"/scripts/entld /usr/sbin/entld
cp -f "$scriptdir"/scripts/lampstart /usr/sbin/lampstart
cp -f "$scriptdir"/scripts/clkcsf /usr/sbin/clkcsf
cp -f "$scriptdir"/scripts/krnlcln /usr/sbin/krnlcln


chmod +x /usr/sbin/entld
chmod +x /usr/sbin/lampstart
chmod +x /usr/sbin/clkcsf
chmod +x /usr/sbin/krnlcln


###########################
## Last update & upgrade ##
###########################

apt-get update
apt-get upgrade -y
apt-get dist-upgrade -y



################################
## Enable firewall and reboot ##
################################
csf -e
echo "You dungoofed! The server will self destruct!"
reboot
