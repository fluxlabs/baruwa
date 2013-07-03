#!/bin/bash
chsh -s /bin/bash
# +--------------------------------------------------------------------+
# Install for Barwua 2.0 for Ubuntu 12.04 x86_64
# +--------------------------------------------------------------------+
#
# Author - Jeremy McSpadden
# Contact - jeremy@fluxlabs.net
# Copyright (C) 2013  http://www.fluxlabs.net
#
# This version by - Mohammed Alli
# Contact - roc1479 at yahoo dot com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# +--------------------------------------------------------------------+

# +---------------------------------------------------+
#	Automated Install
# 	If you would like a completely automated install
# 	Fill the required fields below.
# +---------------------------------------------------+

# Set 1 to Use the autocomplete. 0 to do prompts.
useauto=0

# Set 1 to pause after every step. (semi-debug?)
usepause=0

# Postgresql Password
pssqlpass=password123!

# RabbitMQ Password
rabbpass=password123!

# Baruwa Admin Email
admemail=admin@domain.net

# Baruwa Reports From Email
repemail=reports@domain.net

# Baruwa Error Reports From Email
erremail=errors@domain.net

# Baruwa URL
baruwadomain=baruwa.domain.net

# Baruwa Admin Username
baruwaadmin=admin

# Baruwa Admin Password - Must be Secure
adminpass=password123!

# Baruwa Admin Email
adminemail=admin@domain.net

# Time Zone
timezone=America/New_York

# MailScanner Organization Name - Short
orgname='Organization'

# MailScanner Organization Name - Long (No Spaces)
lorgname='YourOrganization'

# MailScanner Organization Website
web='www.domain.com'

# SSL Country Code
sslcountry='US'

# SSL Province/State Name
sslprovince='Your State'

# SSL City Name
sslcity='Your City'

# SSL Organization Name
sslorg='Your Organization'

# SSL Common Name
sslcommon=$baruwadomain

# SSL Email
sslemail=$adminemail

# Or, you can put your variables (as set above) in a file called local_vars
# And we'll try to load it here.
if [ -f ./local_vars ];
    then
    . ./local_vars
fi

# NOTHING TO EDIT BELOW HERE !!  NOTHING TO EDIT BELOW HERE !!

# +---------------------------------------------------+
# Version Tracking
# +---------------------------------------------------+

date="6-29-2013"                                        	# Latest Date
version="2.3.2"                                            	# Script Version
ubuntuver="12.04"                                            	# Script ID
baruwaver="2.0.1"                            			# Baruwa Version
rabbitmq="3.1.1"                                        	# Rabbit MQ Version
msver="4.84.6-1"                                        	# MailScanner Version
msver1="4.84.6"                                         	# MS Config Version
libmem="1.0.17"                                         	# LIB MEM Cache Version
pythonver="2.7"                                         	# Python Version
postgresver="9.1"						# PostgreSQL Version

# +---------------------------------------------------+
# More Stuff
# +---------------------------------------------------+

baruwagit="https://raw.github.com/akissa/baruwa2/2.0.1"       		# Extras from Baruwa
fluxlabsgit="https://raw.github.com/fluxlabs/baruwa/master/2.0"     	# Extras from Flux Labs
home="/home/baruwa" 							# Home Directory
etcdir="/etc/baruwa"                                   			# Baruwa etc
eximdir="/etc/exim4"                                   			# Exim Directory
track="/tmp/tracking"   						# Tracking Directory
logs="/tmp/baruwa2" 							# Logs Directory
builddir="/usr/src/b2build/"						# Build Directory
hosts=$(hostname -s)
hostf=$(hostname -f)
eth0ip=$(ifconfig eth0 | grep "inet addr" | awk '{ print $2 }' | sed 's/addr://')

# +---------------------------------------------------+
# Functions
# +---------------------------------------------------+

fn_confirm (){
        read -p "Press [Enter] key to continue..." fackEnterKey
        echo "------------------------------------------------------------------------------";
}

fn_pause (){
        echo ""
        echo "------------------------------------------------------------------------------";
        read -p "You are walking through the script. Press [Enter] to Continue"
        echo "------------------------------------------------------------------------------";
        fackEnterKey
}

fn_clear () {
        clear 2>/dev/null
}

fn_complete (){
        if [ $usepause = 1 ];
                then
                fn_pause
        else
                fn_clear
                echo "------------------------------------------------------------------------------";
                echo "C O M P L E T E";
                echo "------------------------------------------------------------------------------";
                sleep 2
        fi
}

fn_cleanup (){
        fn_clear
        echo "------------------------------------------------------------------------------";
        echo "I N S T A L L E R  C L E A N  U P";
        echo "------------------------------------------------------------------------------";
        echo "Cleaning up Installer files."; sleep 5
        rm -f $home/*.patch
        rm -rf {$track,$logs,$builddir}
}

# +---------------------------------------------------+
# Check System
# +---------------------------------------------------+

OS=`uname -s`
if [ ${OS} = "Linux" ]; then
    :
else
    echo "Sorry, but this installer does not support the ${OS} platform."
    exit 1
fi

DISTRO=`cat /etc/lsb-release | grep ID | head -n 1 | awk -F'=' {'print $2'}`
if [ ${DISTRO} = "Ubuntu" ]; then
    :
else
    echo "Sorry, but this installer does not support the ${DISTRO}
distribution."
    exit 1
fi
RELEASE=`cat /etc/lsb-release  | grep DISTRIB_RELEASE | awk -F'=' {'print $2'}`
if [ ${RELEASE} = "${ubuntuver}" ]; then
    :
else
    echo "Sorry, but this installer does not support the ${RELEASE} release."
    exit 1
fi

# +---------------------------------------------------+
# Start Script
# +---------------------------------------------------+

fn_clear
echo "------------------------------------------------------------------------------";
echo "  ___                                      ______    ______"
echo "  |  |--.---.-.----.--.--.--.--.--.---.-. |__    |  |      |"
echo "  |  _  |  _  |   _|  |  |  |  |  |  _  | |    __|__|  --  |"
echo "  |_____|___._|__| |_____|________|___._| |______|__|______|"
echo ""
echo "  Installer v$version for $DISTRO $RELEASE"
echo ""
echo "------------------------------------------------------------------------------";
echo ""
echo "Welcome to the Baruwa's $baruwaver Installer. (Unofficial Version)"
echo ""
echo "Before we begin: This installer was written for a virtual install of $DISTRO $RELEASE"
echo "This installer is meant to assist you in installing Baruwa $baruwaver "
echo ""
echo "You still need to know linux basics and have an understanding of how Baruwa $baruwaver operates."
echo "It is a complete re-write from 1.0 branch. Alot of changes were made to the code and how it"
echo "works."
echo ""
echo "Please take the time to review the code that I am using below so you understand what"
echo "it is doing. This script will prompt you for the minimal amount of questions needed "
echo "to get Baruwa $baruwaver installed and running. You will need to configure baruwa, your firewall,"
echo "spamassassin rules, greylisting, RBL, SPF .. etc on your own."
echo ""
echo "If you are un-sure that you can maintain a Baruwa install, I recommend going with the"
echo "commercial product at http://www.baruwa.com or the PAAS model at http://www.baruwa.net"
echo ""
echo "Please make sure you have added a hosts entry for your hostname of this server"
echo "into /etc/hosts or this script will fail. Please cancel if you have not. CTRL+C to Cancel"
echo ""
echo "Also, any bugs found in Baruwa itself should be reported to"
echo "the mailing list @ http://www.baruwa.org." 
echo "with any concerns or additions you would like to see/add to this script.";
echo ""
echo "I will assist you in installing Baruwa 2.0.";
echo ""
echo "------------------------------------------------------------------------------";
echo ""
fn_confirm

fn_directories () {
mkdir $track
mkdir $logs
mkdir $builddir
}


# +---------------------------------------------------+
# User Prompt Function
# +---------------------------------------------------+

fn_requirements () {

if [ $useauto = 1 ];
        then
        :
else
fn_clear

echo "------------------------------------------------------------------------------";
echo "B A R U W A   S E T T I N G S";
echo "------------------------------------------------------------------------------";

echo -n ""
while :
do
echo ""
echo "What email would you like Administrative Emails sent to?"
echo "ie: you@domain.com"
IFS= read -p "Email: " admemail
IFS= read -p "Email Again: " admemail2
[[ $admemail = "$admemail2" ]] && break
echo ''
echo 'Email does not match. Please try again.'
echo ''
done
while :
do
echo ""
echo "What email would you like Report Emails sent from?"
echo "ie: reports@domain.com"
IFS= read -p "Email: " repemail
IFS= read -p "Email Again: " repemail2
[[ $repemail = "$repemail2" ]] && break
echo ''
echo 'Email does not match. Please try again.'
echo ''
done
while :
do
echo ""
echo "What email would you like Error Emails sent from?"
echo "ie: errors@domain.com"
IFS= read -p "Email: " erremail
IFS= read -p "Email Again: " erremail2
[[ $erremail = "$erremail2" ]] && break
echo ''
echo 'Email does not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What hostname would you like nginx to listen on for Baruwa requests?"
echo "ie: baruwa.domain.com"
IFS= read -p "Domain: " baruwadomain
IFS= read -p "Domain Again: " bdomain2
[[ $baruwadomain = "$bdomain2" ]] && break
echo ''
echo 'Domain does not match. Please try again.'
echo ''
done

while :
do
fn_clear

echo "------------------------------------------------------------------------------";
echo "B A R U W A  A D M I N  U S E R";
echo "------------------------------------------------------------------------------";

echo ""
echo "What would you like your Baruwa admin username to be?"
echo "ie: admin"
IFS= read -p "Username: " baruwaadmin
IFS= read -p "Username Again: " adminuser2
[[ $baruwaadmin = "$adminuser2" ]] && break
echo ''
echo 'Usernames do not match. Please try again.'
echo ''
done
while :
do
echo ""
echo "What password would you like to use?"
echo "This must be a complex password! ie: spam1234"
IFS= read -p "Password: " adminpass
IFS= read -p "Password Again: " adminpass2
[[ $adminpass = "$adminpass2" ]] && break
echo ''
echo 'Passwords do not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What email would you like to use?"
echo "ie: you@domain.com"
IFS= read -p "Email: " adminemail
IFS= read -p "Email Again: " adminemail2
[[ $adminemail = "$adminemail2" ]] && break
echo ''
echo 'Emails do not match. Please try again.'
echo ''
done

while :
do
fn_clear

echo "------------------------------------------------------------------------------";
echo "M A I L S C A N N E R  O R G  C O N F I G ";
echo "------------------------------------------------------------------------------";

echo ""
echo "What would you like to use for your short orgname to be?"
echo "ie: Company"
IFS= read -p "Orgname: " orgname
IFS= read -p "Orgname Again: " orgname2
[[ $orgname = "$orgname2" ]] && break
echo ''
echo 'Orgnames does not match. Please try again.'
echo ''
done
while :
do
echo ""
echo "What would you like to use for your Long orgname?"
echo "ie: Your Company"
IFS= read -p "Long Orgname: " lorgname
IFS= read -p "Long Orgname Again: " lorgname2
[[ $lorgname = "$lorgname2" ]] && break
echo ''
echo 'Long Orgnames does not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What website address would you like to use?"
echo "ie: www.domain.com"
IFS= read -p "Website: " web
IFS= read -p "Webste Again: " web2
[[ $web = "$web2" ]] && break
echo ''
echo 'Websites do not match. Please try again.'
echo ''
done

fn_clear

if [[ -f $track/pssql ]];
        then
                echo "PostgreSQL seems to already be configured. Skipping." ; sleep 3
       	 else
            	while :
           	 do
               
		echo "------------------------------------------------------------------------------";
                echo "P O S T G R E S Q L  P A S S W O R D";
                echo "------------------------------------------------------------------------------";
                echo "Lets set a password for BaruwaDB/BayesDB in Postgres."
                echo "What would you like this super secret"
                echo "password to be?"
                 IFS= read -r -p "Password: " pssqlpass
                IFS= read -r -p "Password Again: " pssqlpass2
                echo ""
                [[ $pssqlpass = "$pssqlpass2" ]] && break
                echo ''
                echo 'Passwords did not match. Please try again.'
                echo ''
        done
       echo $pssqlpass > $track/pssqlp
fi
	fn_clear

if [[ -f $track/rabbit ]];
        then
        echo " This section has already been completed. Skipping."; sleep 3
        else
                while :
                do

echo "------------------------------------------------------------------------------";
                echo "R A B B I T M Q  P A S S W O R D";
echo "------------------------------------------------------------------------------";

	echo "Lets set a password for RabbitMQ."
                echo "What would you like this super secret"
                echo "password to be?"
           	IFS= read -r -p "Password: " rabbpass
           	IFS= read -r -p "Password Again: " rabbpass2
           	echo ""
           	[[ $rabbpass = "$rabbpass2" ]] && break
                echo ''
                echo 'Passwords did not match. Please try again.'
                echo ''
        done
        echo $rabbpass > $track/rabbitp
fi
fn_clear
        
        echo "------------------------------------------------------------------------------";
        echo "Ok, I've got all I've needed from you. Hopefully we'll have an install ready";
        echo "for you in a bit. The process from here on out is automated. I will prompt you"
        echo "shortly for some perl mod confirmations."
        echo "------------------------------------------------------------------------------";
        echo $admemail $repemail $erremail $baruwadomain $baruwaadmin $adminpass $adminemail $pssqlpass $rabbpass $orgname $lorgname $web > $track/answers
        fn_confirm
fi
}

# +---------------------------------------------------+
# Dependencies Function
# +---------------------------------------------------+

fn_dependencies (){
fn_clear

echo "------------------------------------------------------------------------------";
echo "R E Q U I R E D  D E P E N D E N C I E S";
echo "------------------------------------------------------------------------------";
sleep 3

if [[ -f $track/dependencies ]];
        then
        echo "Dependencies already been installed. Skipping."; sleep 3
else
echo "This process will take some time."; sleep 3
export DEBIAN_FRONTEND='noninteractive'

echo "Installing Baruwa repo."
wget -cq -O - http://apt.baruwa.org/baruwa-apt-keys.gpg | apt-key add - &> /dev/null
echo "deb http://apt.baruwa.org/ubuntu precise main" >> /etc/apt/sources.list
apt-get update

echo "Installing Dependencies."
apt-get install gcc g++ git subversion curl patch -y
fn_clear
echo "Installing libraries."
apt-get install libjpeg62-dev libxml2-dev libxslt1-dev cython libpq-dev libfreetype6-dev libldap2-dev libssl-dev swig libcrack2-dev libgeoip-dev python-dev libsasl2-dev libmysqlclient-dev libcloog-ppl0 libmemcached-dev zlib1g-dev libssl-dev python-dev build-essential liblocal-lib-perl libanyevent-perl libaprutil1-dbd-sqlite3 libaprutil1-ldap libart-2.0-2 libauthen-dechpwd-perl libauthen-passphrase-perl libcap2 libclass-mix-perl libcrypt-des-perl libcrypt-eksblowfish-perl libcrypt-mysql-perl libcrypt-passwdmd5-perl libcrypt-rijndael-perl libcrypt-unixcrypt-xs-perl libdata-entropy-perl libdata-float-perl libdata-integer-perl libdbd-mysql-perl libdbd-pg-perl libdigest-crc-perl libdigest-md4-perl libelf1 libev-perl libhttp-lite-perl liblcms1 liblua5.1-0 liblzo2-2 libmodule-runtime-perl libnspr4 libnss3 libopts25 libparams-classify-perl libscalar-string-perl libstring-crc32-perl -y
fn_clear

echo "Installing packages."
apt-get install python-setuptools python-virtualenv postgresql postgresql-plpython sphinxsearch memcached clamav-daemon clamav-unofficial-sigs apparmor libjs-dojo-core libjs-dojo-dijit libjs-dojo-dojox arj cabextract expect htop lzop nomarch ntp p7zip ripole tcl8.5 unrar-free zoo -y
fn_clear

echo "Installing mailscanner dependencies."
apt-get install libconvert-tnef-perl libdbd-sqlite3-perl libfilesys-df-perl libmailtools-perl libmime-tools-perl libmime-perl libnet-cidr-perl libsys-syslog-perl libio-stringy-perl libfile-temp-perl libole-storage-lite-perl libarchive-zip-perl libsys-hostname-long-perl libnet-cidr-lite-perl libhtml-parser-perl libdb-file-lock-perl libnet-dns-perl libncurses5-dev libdigest-hmac-perl libnet-ip-perl liburi-perl libfile-spec-perl spamassassin libnet-ident-perl libmail-spf-perl libmail-dkim-perl dnsutils libio-socket-ssl-perl -y
fn_clear

LIBDIGEST_URL="http://launchpadlibrarian.net/85191561/libdigest-sha1-perl_2.13-2build2_i386.deb"
LIBDIGEST_FILE="libdigest-sha1-perl_2.13-2build2_i386.deb"
if [ "$(uname -m)" = x86_64 ];
    then
    LIBDIGEST_URL="http://launchpadlibrarian.net/85191944/libdigest-sha1-perl_2.13-2build2_amd64.deb"
    LIBDIGEST_FILE="libdigest-sha1-perl_2.13-2build2_amd64.deb"
fi
wget $LIBDIGEST_URL && dpkg -i $LIBDIGEST_FILE
touch $track/dependencies
fn_complete
fi
}

# +---------------------------------------------------+
# Dnsmasq configuration
# +---------------------------------------------------+

fn_dnsmasq (){
fn_clear

if [[ -a $track/dnsmasq ]];
        then
        echo "Dnsmasq is already configured. Skipping."
else
      echo "Configuring dnsmasq."; sleep 3
apt-get install dnsmasq -y
sed -i s/"#listen-address="/"listen-address=127.0.0.1"/ /etc/dnsmasq.conf
echo "Disabling IPV6"
entries="# IPv6 \nnet.ipv6.conf.all.disable_ipv6 = 1 \nnet.ipv6.conf.default.disable_ipv6 = 1 \nnet.ipv6.conf.lo.disable_ipv6 = 1"
echo -e $entries >> /etc/sysctl.conf
sysctl -p
/etc/init.d/dnsmasq restart
touch $track/dnsmasq
       fn_complete
fi

}

# +---------------------------------------------------+
# Virtual Python Function
# +---------------------------------------------------+

fn_python (){
        fn_clear
echo "------------------------------------------------------------------------------";
echo "V I R T U A L  P Y T H O N  E N V I R O N M E N T";
echo "------------------------------------------------------------------------------";
sleep 3
if [[ -f $track/python ]];
        then
                echo "It looks as though the virtual environment already exists. Skipping."; sleep 3
        else
                echo "I am going to setup your Virtual Python Environment for Baruwa."
                echo "This process could take a while."; sleep 3
                mkdir -p $home && cd $home
virtualenv --no-site-packages --distribute px
source px/bin/activate
export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
curl -O $baruwagit/requirements.txt
sed -i -e 's:pyparsing<2.0:pyparsing==1.5.7:' /home/baruwa/requirements.txt
sed -i -e 's:SQLAlchemy:SQLAlchemy==0.7:' /home/baruwa/requirements.txt
pip install distribute
pip install -U distribute
pip install --timeout 60 -r requirements.txt
fn_clear
cd $home
curl http://sphinxsearch.googlecode.com/svn/trunk/api/sphinxapi.py -o px/lib/python$pythonver/site-packages/sphinxapi.py
fn_clear
curl -O $baruwagit/extras/patches/repoze.who-friendly-form.patch
curl -O $baruwagit/extras/patches/repoze-who-fix-auth_tkt-tokens.patch
cd px/lib/python$pythonver/site-packages/repoze/who/plugins/
patch -p3 -i $home/repoze.who-friendly-form.patch
patch -p4 -i $home/repoze-who-fix-auth_tkt-tokens.patch
cd $home
fn_clear

echo "Patching M2Crypto and installing from source"
cat >m2crypto.sh<< 'EOF'
#!/bin/sh -xe

# Sets up m2crypto on ubuntu architecture in virtualenv
# openssl 1.0 does not have sslv2, which is not disabled in m2crypto
# therefore this workaround is required

PATCH="
--- SWIG/_ssl.i 2011-01-15 20:10:06.000000000 +0100
+++ SWIG/_ssl.i 2012-06-17 17:39:05.292769292 +0200
@@ -48,8 +48,10 @@
 %rename(ssl_get_alert_desc_v) SSL_alert_desc_string_long;
 extern const char *SSL_alert_desc_string_long(int);

+#ifndef OPENSSL_NO_SSL2
 %rename(sslv2_method) SSLv2_method;
 extern SSL_METHOD *SSLv2_method(void);
+#endif
 %rename(sslv3_method) SSLv3_method;
 extern SSL_METHOD *SSLv3_method(void);
 %rename(sslv23_method) SSLv23_method;"

pip install --download="." m2crypto
tar -xf M2Crypto-*.tar.gz
rm M2Crypto-*.tar.gz
cd M2Crypto-*
echo "$PATCH" | patch -p0
python setup.py install
EOF

chmod +x m2crypto.sh
./m2crypto.sh
fn_clear

echo "Patching subprocess"
cd $home
curl -O $baruwagit/extras/patches/subprocess_timeout.patch
cd $home/px/lib/python$pythonver/site-packages/
patch -p1 -i $home/subprocess_timeout.patch
touch $track/python
fn_complete
fi
}

# +---------------------------------------------------+
# Postgresql Function
# +---------------------------------------------------+

fn_postgresql (){
        fn_clear
echo "------------------------------------------------------------------------------";
echo "P O S T G R E S Q L";
echo "------------------------------------------------------------------------------";
sleep 3

if [[ -a $track/pssql ]];
        then
        echo "PostgreSQL is already setup. Skipping."
else
cat > /etc/postgresql/$postgresver/main/pg_hba.conf << 'EOF'
# TYPE  DATABASE    USER        CIDR-ADDRESS          METHOD
local   all         postgres                          trust
local   all         sa_user                           trust
host    all         all         127.0.0.1/32          md5
host    all         all         ::1/128               md5
EOF

sed -e "s/^#timezone = \(.*\)$/timezone = 'UTC'/" -i /etc/postgresql/$postgresver/main/postgresql.conf

# restart the service
service postgresql restart
cd $home
su - postgres -c "psql postgres -c \"CREATE ROLE baruwa WITH LOGIN PASSWORD '$pssqlpass';\""
su - postgres -c 'createdb -E UTF8 -O baruwa -T template1 baruwa'
#su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpgsql;\""
su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpythonu;\""
curl -O $baruwagit/baruwa/config/sql/admin-functions.sql
su - postgres -c 'psql baruwa -f '$home'/admin-functions.sql'
service postgresql restart
curl -O $baruwagit/extras/config/sphinx/sphinx.conf
sed -i -e 's:sql_host =:sql_host = 127.0.0.1:' \
-e 's:sql_user =:sql_user = baruwa:' \
-e 's:sql_pass =:sql_pass = '$pssqlpass':' \
-e 's:sql_db =:sql_db = baruwa:' sphinx.conf
sed -i -e 's:START=no:START=yes:' /etc/default/sphinxsearch
sed -i -e 's:/var/log/sphinx:/var/log/sphinxsearch:' -e 's:/var/lib/sphinx:/var/lib/sphinxsearch:' sphinx.conf
cp sphinx.conf /etc/sphinxsearch/
service sphinxsearch start
touch $track/pssql
fn_complete
fi
}

# +---------------------------------------------------+
# Rabbit MQ Function
# +---------------------------------------------------+

fn_rabbitmq (){
        fn_clear
echo "------------------------------------------------------------------------------";
echo "R A B B I T M Q ";
echo "------------------------------------------------------------------------------";
sleep 3
if dpkg --list | grep rabbitmq-server;
        then
        echo "Good, It looks as though RABBITMQ is already installed. Skipping"; sleep 2
        else
                cd $builddir
                wget -cq -O - http://www.rabbitmq.com/rabbitmq-signing-key-public.asc | apt-key add - &> /dev/null
                echo "deb http://www.rabbitmq.com/debian/ testing main" >> /etc/apt/sources.list
                apt-get update
                apt-get install rabbitmq-server -y
fi

if [[ -a $track/rabbit ]];
        then
        echo "RabbitMQ has already been configured. Skipping."
else
        service rabbitmq-server start
        rabbitmqctl delete_user guest
        rabbitmqctl add_user baruwa $rabbpass
        rabbitmqctl add_vhost baruwa
        rabbitmqctl set_permissions -p baruwa baruwa ".*" ".*" ".*"
        touch $track/rabbit
        fn_complete
fi
}

# +---------------------------------------------------+
# Mailscanner Function
# +---------------------------------------------------+

fn_mailscanner (){
        fn_clear
echo "------------------------------------------------------------------------------";
echo "M A I L S C A N N E R ";
echo "------------------------------------------------------------------------------";
sleep 3
if dpkg --list | grep  mailscanner;
        then
                echo "I have detected a previous install of MailScanner." ; sleep 3
        else
                echo "Installing MailScanner. This process could take a while."; sleep 3
                cd $builddir
                apt-get install mailscanner exim4-daemon-heavy -y
                echo "Now let's patch it up."; sleep 3
                echo ""
        cd $home
        curl -O $baruwagit/extras/patches/mailscanner-baruwa-iwantlint.patch
        curl -O $baruwagit/extras/patches/mailscanner-baruwa-sql-config.patch
        cd /usr/sbin
        patch -i $home/mailscanner-baruwa-iwantlint.patch
        cd /usr/share/MailScanner/MailScanner
        patch -p3 -i $home/mailscanner-baruwa-sql-config.patch
        cd $home
        curl -O $baruwagit/extras/perl/BS.pm
        mv BS.pm /etc/MailScanner/CustomFunctions/
        cd /etc/MailScanner
        mv MailScanner.conf MailScanner.conf.orig
        cd $home
        curl -O $baruwagit/extras/config/mailscanner/MailScanner.conf
        curl -O $baruwagit/extras/config/mailscanner/scan.messages.rules
        curl -O $baruwagit/extras/config/mailscanner/nonspam.actions.rules
        curl -O $baruwagit/extras/config/mailscanner/filename.rules
        curl -O $baruwagit/extras/config/mailscanner/filetype.rules
        curl -O $baruwagit/extras/config/mailscanner/filename.rules.allowall.conf
        curl -O $baruwagit/extras/config/mailscanner/filetype.rules.allowall.conf
        mv /etc/MailScanner/spam.assassin.prefs.conf /etc/MailScanner/spam.assassin.prefs.conf.orig
        curl -O $fluxlabsgit/extras/config/spamassassin/spam.assassin.prefs.conf
        mv *.rules /etc/MailScanner/rules/
        mv *.conf /etc/MailScanner/
        chmod -R 777 /var/spool/MailScanner/
        ln -s /etc/MailScanner/spam.assassin.prefs.conf /etc/mail/spamassassin/mailscanner.cf

        sed -i 's:/usr/local:/usr/:' /etc/MailScanner/autoupdate/clamav-autoupdate
        sed -i 's:DB Password = verysecretpw:DB Password = '$pssqlpass':' /etc/MailScanner/MailScanner.conf
        sed -i s/"\/etc\/exim"/"\/etc\/exim4"/ /etc/MailScanner/MailScanner.conf
        sed -i s/"Run As User = exim"/"Run As User = Debian-exim"/ /etc/MailScanner/MailScanner.conf
        sed -i s/"Run As Group = exim"/"Run As Group = Debian-exim"/ /etc/MailScanner/MailScanner.conf
        sed -i s/"Quarantine User = exim"/"Quarantine User = Debian-exim"/ /etc/MailScanner/MailScanner.conf
        sed -i s/"Incoming Work User = exim"/"Incoming Work User = Debian-exim"/ /etc/MailScanner/MailScanner.conf
        sed -i s/"Incoming Work Group = clam"/"Incoming Work Group = clamav"/ /etc/MailScanner/MailScanner.conf
        sed -i 's:Virus Scanners = none:Virus Scanners = clamd:' /etc/MailScanner/MailScanner.conf
        sed -i 's:Custom Functions Dir = /usr/share/MailScanner/MailScanner/CustomFunctions:Custom Functions Dir = /etc/MailScanner/CustomFunctions:' /etc/MailScanner/MailScanner.conf
        #sed -i s/"4.84.3"/"4.84.5"/ /etc/MailScanner/MailScanner.conf
        sed -i s/"\/var\/spool\/exim\/input"/"\/var\/spool\/exim4\/input"/ /etc/MailScanner/MailScanner.conf
        sed -i s/"#run_mailscanner"/"run_mailscanner"/ /etc/default/mailscanner
        sed -i s/"\/var\/lock\/MailScanner.off"/"\/var\/lock\/MailScanner\/MailScanner.off"/ /etc/init.d/mailscanner
        sed -i s/"\/var\/lock\/subsys\/mailscanner"/"\/var\/lock\/MailScanner\/mailscanner"/ /etc/init.d/mailscanner
        sed -i 's:%org-name% = BARUWA:%org-name% = '$orgname':' /etc/MailScanner/MailScanner.conf
        sed -i 's:%org-long-name% = BARUWA MAILFW:%org-long-name% = '$lorgname':' /etc/MailScanner/MailScanner.conf
        sed -i 's:%web-site% = hosted.baruwa.net:%web-site% = '$web':' /etc/MailScanner/MailScanner.conf
        sed -i 's:CHANGE:'$pssqlpass':' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i 's:bayes_ignore_header X-Baruwa:bayes_ignore_header X-'$orgname'-BaruwaFW:' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i 's:bayes_ignore_header X-Baruwa-SpamCheck:bayes_ignore_header X-'$orgname'-BaruwaFW-SpamCheck:' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i 's:bayes_ignore_header X-Baruwa-SpamScore:bayes_ignore_header X-'$orgname'-BaruwaFW-SpamScore:' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i 's:bayes_ignore_header X-Baruwa-Information:bayes_ignore_header X-'$orgname'-BaruwaFW-Information:' /etc/MailScanner/spam.assassin.prefs.conf         
        mkdir -p /var/spool/exim.in/input
        chown -R Debian-exim:Debian-exim /var/spool/exim.in
        #Add '20i{clamd} to virus.scanners.conf
	sed -i '20i{clamd}\         /bin/false\                              /usr/local ' /etc/MailScanner/virus.scanners.conf
	#Fix file-command path to /usr/bin/file in MailScanner.conf
	sed -i 's:/usr/local/bin/file-wrapper:/usr/bin/file:' /etc/MailScanner/MailScanner.conf
	#Change clamd.socket to clamd.ctl in MailScanner.conf
	sed -i 's:clamd.socket:clamd.ctl:' /etc/MailScanner/MailScanner.conf
   
        #Setup Bayes Database
	echo "Creating role sa_user"
	su - postgres -c "psql -c\"create role sa_user login;\""
	echo "Setting password"
	su - postgres -c "psql -c\"alter role sa_user password '$pssqlpass';\""
	echo "Creating database sa_bayes"
	su - postgres -c "psql -c\"create database sa_bayes owner sa_user;\""
	echo "Importing tables"
	su - postgres -c "psql -d sa_bayes -U sa_user -c \"\i /usr/share/doc/spamassassin/sql/bayes_pg.sql;\""
	echo "Initializing sa_bayes database"
	sa-learn --sync
	echo "Restarting postgresql"
	service postgresql restart
	fn_clear
	echo "Updating spam.assassin.prefs.conf for sa_bayes."
	sed -i 's:CHANGE:'$pssqlpass':' /etc/MailScanner/spam.assassin.prefs.conf
	sed -i 's:6432:5432:' /etc/MailScanner/spam.assassin.prefs.conf
	sed -i 's:bayes_sql_override_username bayes:bayes_sql_override_username root:' /etc/MailScanner/spam.assassin.prefs.conf
	sed -i 's:bayes_sql_username bayes:bayes_sql_username sa_user:' /etc/MailScanner/spam.assassin.prefs.conf
	sed -i 's:baruwa:sa_bayes:' /etc/MailScanner/spam.assassin.prefs.conf
	#Comment out bayes awl whitelist entries in spam.assassin.prefs.conf
	sed -i 's:auto_whitelist:#auto_whitelist:' /etc/MailScanner/spam.assassin.prefs.conf
	sed -i 's:user_:#user_:' /etc/MailScanner/spam.assassin.prefs.conf
        
        touch $track/mailscanner
fn_complete
fi
}

fn_exim (){
fn_clear

echo "------------------------------------------------------------------------------";
echo "E X I M  I N S T A L L";
echo "------------------------------------------------------------------------------";
sleep 3

if dpkg --list | grep postfix
        then
        service postfix stop
        apt-get remove postfix -y
else
        echo "Good, Postfix is not installed."; sleep 3
fi
if  dpkg --list | grep exim4
        then
        echo "Exim is already installed. Skipping" ; sleep 3
else
        apt-get install exim4-daemon-heavy -y
fi

if [[ -f /etc/sudoers.d/baruwa ]];
        then
        echo "Baruwa sudoers file exists, skipping."; sleep 3
else
cat > /etc/sudoers.d/baruwa << 'EOF'
Defaults:baruwa   !requiretty, visiblepw

baruwa ALL=(exim) NOPASSWD: /usr/sbin/exim -C /etc/exim4/exim_out.conf -M *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mf *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mrm *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mg *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -Mar *, \
        /usr/sbin/exim -C /etc/exim4/exim_out.conf -qff, \
                /usr/sbin/exim -Mrm *, \
                /usr/sbin/exim -Mg *, \
                /usr/sbin/exim -Mar *

baruwa ALL = NOPASSWD: /bin/kill -s HUP *
EOF
chmod 0440 /etc/sudoers.d/baruwa
fi

if [[-f $track/exim && -f $eximdir/baruwa/exim-bcrypt.pl ]];
        then
        echo "Exim is already configured. Skipping"; sleep 3
else
        cd /etc/exim4
        curl -O $baruwagit/extras/config/exim/exim.conf
        curl -O $baruwagit/extras/config/exim/exim_out.conf
        curl -O $baruwagit/extras/config/exim/macros.conf
        curl -O $baruwagit/extras/config/exim/trusted-configs
        mv /etc/exim4/exim.conf /etc/exim4/exim4.conf
        sed -i s/"\/etc\/exim"/"\/etc\/exim4"/ /etc/exim4/exim4.conf
        #Comment out tls_advertise_hosts
        sed -i 's:tls_advertise:#tls_advertise:' /etc/exim4/exim4.conf
        #Comment out SPF Checks
        sed -i 's:deny\    message\       = SPF_MSG:#deny\    message\       = SPF_MSG:' /etc/exim4/exim4.conf
        sed -i -e 's/spf/#spf = /' /etc/exim4/exim4.conf
        sed -i s/"user = exim"/"user = Debian-exim"/ /etc/exim4/exim4.conf
        sed -i -e 's/verysecretpw/'$pssqlpass'/' /etc/exim4/macros.conf
        sed -i -e 's/dbl_/#dbl_/' /etc/exim4/exim_out.conf
        sed -i s/"\/etc\/exim"/"\/etc\/exim4"/ /etc/exim4/exim_out.conf
        sed -i s/"\/etc\/exim"/"\/etc\/exim4"/ /etc/exim4/trusted-configs
        #Update Clamd socket in exim4.conf
        sed -i s/"clamd.sock"/"clamd.ctl"/ /etc/exim4/exim4.conf
        
        mkdir $eximdir/baruwa
        cd $eximdir/baruwa
        curl -O $baruwagit/extras/config/exim/baruwa/exim-bcrypt.pl
        #add clamav user to Debian-exim group:
        usermod -a -G Debian-exim clamav
        touch $track/exim
        service exim4 start
fn_complete
fi
}

fn_perl (){
fn_clear
echo "------------------------------------------------------------------------------";
echo "P E R L  M O D S  I N S T A L L";
echo "------------------------------------------------------------------------------";
sleep 3
if [[ -f $track/perlmods ]];
        then
        echo "Perl modules were previously installed. Skipping."; sleep 3
else
        echo "We are now going to install a few Perl Modules"
        echo "Please press Yes/Enter throughout the questions."
        fn_confirm

        cpan -i Encoding::FixLatin AnyEvent::Handle EV IP::Country::Fast Encode::Detect Crypt::OpenSSL::RSA
        touch $track/perlmods
fn_complete
fi
}

# +---------------------------------------------------+
# Libmem Source Function
# +---------------------------------------------------+
fn_libmem (){
fn_clear
echo "------------------------------------------------------------------------------";
echo "C O M P I L E  L I B M E M  S O U R C E";
echo "------------------------------------------------------------------------------";
sleep 3

if [[ -d $builddir/libmemcached-$libmem && -f $track/libmem ]];
        then
        echo "It looks as though libmemcached was already compiled from source. Skipping."; sleep 3
else
        cd $builddir/
        wget https://launchpad.net/libmemcached/1.0/$libmem/+download/libmemcached-$libmem.tar.gz
        tar -zxvf libmemcached*.tar.gz && cd libmemcached*
        ./configure --with-memcached
        make && make install
        touch $track/libmem
fn_complete
fi
}

# +---------------------------------------------------+
# Baruwa Function
# +---------------------------------------------------+

fn_configuration (){
        fn_clear
echo "------------------------------------------------------------------------------";
echo "B U I L D I N G  B A R U W A";
echo "------------------------------------------------------------------------------";
sleep 3
if [[ -f $track/baruwa-build ]];
        then
                echo "It seems Baruwa 2 has already been built. Skipping." ; sleep 3
        else
        cd $home
        virtualenv --distribute px
        source px/bin/activate
        export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
        pip install -U distribute
        pip install baruwa
        touch $track/baruwa-build
fi

fn_clear
echo "------------------------------------------------------------------------------";
echo "C O N F I G U R I N G  B A R U W A";
echo "------------------------------------------------------------------------------";
sleep 3
if [[ -f $track/baruwaconfig ]];
        then
                echo "This section has been completed. Skipping. " ; sleep 3
        else
        cd $home
        px/bin/paster make-config baruwa production.ini
        touch $track/paster
        mkdir $etcdir
        mv $home/production.ini $etcdir/production.ini
        sed -i -e 's/exim/Debian-exim/' $etcdir/production.ini
        sed -i -e 's/sqlalchemy.url/#sqlalchemy.url/' $etcdir/production.ini
        sed -i "72i sqlalchemy.url = postgresql://baruwa:$pssqlpass@127.0.0.1:5432/baruwa" $etcdir/production.ini
        sed -i -e 's:broker.password =:broker.password = '$rabbpass':' \
               -e "s:snowy.local:$(hostname):g" \
               -e 's:^#celery.queues:celery.queues:' $etcdir/production.ini
        touch $track/baruwaconfig

fi

if [[ -f /etc/default/baruwa ]];
then
        echo "I see you already have an /etc/default/baruwa file. Skipping." ; sleep 3
else

#Create baruwa directories
mkdir -p /var/log/baruwa /var/run/baruwa /var/lib/baruwa/data/{cache,sessions,uploads,templates} /var/lock/baruwa /etc/MailScanner/baruwa/signatures /etc/MailScanner/baruwa/dkim /etc/MailScanner/baruwa/rules /var/lib/baruwa/data/templates/{general,accounts} 
#Create Baruwa user/group
getent group baruwa >/dev/null || addgroup --system baruwa
getent passwd baruwa >/dev/null || adduser --system --ingroup baruwa --home /var/lib/baruwa --no-create-home --gecos "Baruwa user" --disabled-login baruwa
#Assign proper permissions
chown baruwa.baruwa -R /var/lib/baruwa /var/run/baruwa /var/log/baruwa /var/lock/baruwa /etc/MailScanner/baruwa
#Add baruwa user to Debian-exim group
usermod -a -G Debian-exim baruwa

cat > /etc/default/baruwa << 'EOF'
CELERYD_CHDIR="/home/baruwa"
CELERYD="$CELERYD_CHDIR/px/bin/paster celeryd /etc/baruwa/production.ini"
CELERYD_LOG_LEVEL="INFO"
CELERYD_LOG_FILE="/var/log/baruwa/celeryd.log"
CELERYD_PID_FILE="/var/run/baruwa/celeryd.pid"
CELERYD_USER="baruwa"
CELERYD_GROUP="baruwa"
EOF

fi

if [[ -x /etc/init.d/baruwa ]];
        then
        echo "Skipping, as I already detect a baruwa init file." ; sleep 3
else
        cd $home
        curl -O $baruwagit/extras/scripts/init/debian/baruwa.init
        mv baruwa.init /etc/init.d/baruwa
        chmod +x /etc/init.d/baruwa
        update-rc.d baruwa defaults
        service baruwa start
fi
fn_complete
}

# +---------------------------------------------------+
# Baruwa Admin Function
# +---------------------------------------------------+

fn_administrator (){
        fn_clear
if [[ -a $track/baruwaadmin ]];
        then
        echo "I believe you have already created an admin-user. Skipping."
else
        cd $home
        virtualenv --distribute px
        source px/bin/activate
        export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
        $home/px/bin/paster setup-app $etcdir/production.ini
        indexer --all --rotate
$home/px/bin/paster create-admin-user -u "$baruwaadmin" -p "$adminpass" -e "$adminemail" -t UTC $etcdir/production.ini
        touch $track/baruwaadmin
fi
}

# +---------------------------------------------------+
# Nginx Function
# +---------------------------------------------------+

fn_nginx (){
fn_clear
echo "------------------------------------------------------------------------------";
echo "N G I N X  A N D  U W S G I  I N S T A L L A T I O N";
echo "------------------------------------------------------------------------------";
sleep 3
if dpkg --list | grep nginx;
        then
        echo "It looks like nginx is already installed. Skipping."; sleep 3
else
        echo "Installing nginx."
        apt-get install nginx -y
fi

if [[ -f /etc/nginx/sites-enabled/baruwa ]];
        then
        echo "It looks like nginx is already configured. Skipping."; sleep 3
else
        curl -O $baruwagit/extras/config/uwsgi/nginx.conf
        mv nginx.conf /etc/nginx/sites-enabled/baruwa
        rm -r /etc/nginx/sites-enabled/default
        sed -i s/"2.6"/"${pythonver}"/ /etc/nginx/sites-enabled/baruwa
        sed -i s/"ms.home.topdog-software.com"/"${baruwadomain}"/ /etc/nginx/sites-enabled/baruwa

fi
fn_clear

if dpkg --list | grep uwsgi;
        then
        echo "It looks like uwsgi is already installed. Skipping."; sleep 3
        else
        echo "Installing Uwsgi."
        apt-get install uwsgi uwsgi-plugin-python -y
fi
if [[ -f /etc/uwsgi/apps-enabled/production.ini ]];
        then
        echo "It looks like uwsgi is already configured. Skipping."; sleep 3
        else
        echo "Configuring Uwsgi."; sleep 3
        sed -i '/daemonize/ahome = /home/baruwa/px' /etc/baruwa/production.ini
        sed -i '/home/apaste = config:/etc/baruwa/production.ini' /etc/baruwa/production.ini
        sed -i '/paste/achmod-socket = 666' /etc/baruwa/production.ini
        ln -s /etc/baruwa/production.ini /etc/uwsgi/apps-enabled/

        fn_clear
        fn_complete
fi
}

# +---------------------------------------------------+
# Pyzor, Razor & DCC Install
# +---------------------------------------------------+
fn_pyzor_razor_dcc () {
        fn_clear
echo "------------------------------------------------------------------------------";
        echo "I N S T A L L  P Y Z O R  R A Z O R  & D C C";
echo "------------------------------------------------------------------------------";
        echo ""; sleep 3
        cd $buildir
        echo "Installing razor, pyzor and dcc."; sleep 3
        apt-get install razor pyzor -y
        wget http://ppa.launchpad.net/jonasped/ppa/ubuntu/pool/main/d/dcc/dcc-common_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb && dpkg -i dcc-common_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb
        wget http://ppa.launchpad.net/jonasped/ppa/ubuntu/pool/main/d/dcc/dcc-client_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb && dpkg -i dcc-client_1.3.144-0ubuntu1~ppa2~precise1_$(uname -m | sed -e 's/x86_64/amd64/' -e 's/i686/i386/').deb
        fn_clear
        echo "Configuring razor, pyzor and dcc."; sleep 3
        pyzor --homedir=/var/lib/MailScanner discover
        pyzor ping
        cd && rm -r /etc/razor/razor-agent.conf
        mkdir /var/lib/MailScanner/.razor
        razor-admin -home=/var/lib/MailScanner/.razor -create
        razor-admin -home=/var/lib/MailScanner/.razor -discover
        razor-admin -home=/var/lib/MailScanner/.razor -register
        sed -i '/razor-whitelist/arazorhome\              = /var/lib/MailScanner/.razor/' /var/lib/MailScanner/.razor/razor-agent.conf
        fn_clear
        echo "Updating spam.assassin.prefs.conf with settings."; sleep 3
        sed -i 's:= 3:= 0:' /var/lib/MailScanner/.razor/razor-agent.conf
        sed -i '25i loadplugin Mail::SpamAssassin::Plugin::DCC' /etc/mail/spamassassin/v310.pre
        sed -i 's:pyzor_options --homedir /var/lib/pyzor:pyzor_options --homedir /var/lib/MailScanner/:' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i 's:razor_config /var/lib/razor/razor-agent.conf:razor_config /var/lib/MailScanner/.razor/razor-agent.conf:' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i 's:envelope_sender_header X-Baruwa-Envelope-From:envelope_sender_header X-BaruwaFW-Envelope-From:' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i '25i ifplugin Mail::SpamAssassin::Plugin::DCC' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i 's:dcc_home /etc/dcc/:dcc_path /usr/sbin/dccproc:' /etc/MailScanner/spam.assassin.prefs.conf
        sed -i '27i endif' /etc/MailScanner/spam.assassin.prefs.conf

        service mailscanner restart
        fn_complete
}

# +---------------------------------------------------+
# CronJobs Function
# +---------------------------------------------------+
fn_cronjobs (){
fn_clear
if [[ -f /etc/cron.hourly/baruwa-updateindex ]];
        then
        echo "Hourly Cronjob exists. Skipping."; sleep 3
else
cat > /etc/cron.hourly/baruwa-updateindex << 'EOF'
#!/bin/bash
#
indexer auditlog lists domains accounts organizations --rotate &>/dev/null
EOF
chmod +x /etc/cron.hourly/baruwa-updateindex
fi

if [[ -f /etc/cron.d/baruwa ]];
        then
        echo "Baruwa Cronjobs exists. Skipping." ; sleep 3
else
cat > /etc/cron.d/baruwa << 'EOF'
*/3 * * * * exim /home/baruwa/px/bin/paster update-queue-stats /etc/baruwa/production.ini >/dev/null 2>&1
0 * * * * baruwa /home/baruwa/px/bin/paster update-sa-rules /etc/baruwa/production.ini >/dev/null 2>&1
0 * * * * root /home/baruwa/px/bin/paster update-delta-index --index messages --realtime /etc/baruwa/production.ini >/dev/null 2>&1
0 0 * * * baruwa /home/baruwa/px/bin/paster send-quarantine-reports /etc/baruwa/production.ini >/dev/null 2>&1
0 1 * * * baruwa /home/baruwa/px/bin/paster prunedb /etc/baruwa/production.ini >/dev/null 2>&1
9 1 * * * root /home/baruwa/px/bin/paster update-delta-index --index archive /etc/baruwa/production.ini >/dev/null 2>&1
0 2 * * * baruwa /home/baruwa/px/bin/paster prunequarantine /etc/baruwa/production.ini >/dev/null 2>&1
0 6 1 * * baruwa /home/baruwa/px/bin/paster send-pdf-reports /etc/baruwa/production.ini >/dev/null 2>&1
EOF
fi
if [[ -f /etc/cron.d/mailscanner ]];
        then
        echo "MailScanner Cronjob Exists. Skipping." ; sleep 3
else
cat > /etc/cron.d/mailscanner << 'EOF'
37 5 * * * /usr/sbin/update_phishing_sites
07 * * * * /usr/sbin/update_bad_phishing_sites
15 * * * * /usr/sbin/update_bad_phishing_emails
#58 23 * * * /usr/sbin/clean.quarantine
42 * * * * /usr/sbin/update_virus_scanners
3,23,43 * * * * /usr/sbin/check_mailscanner
EOF
fi

#Check if check_mailscanner exists, if not create it.
if [[ -f /usr/sbin/check_mailscanner ]];
        then
        echo "check_mailscanner exists Skipping." ; sleep 3
else
curl $fluxlabsgit/ubuntu12/check_mailscanner -o /usr/sbin/check_mailscanner
chmod +x /usr/sbin/check_mailscanner
fi

#Check if update_bad_phishing_sites exists, if not create it.
if [[ -f /usr/sbin/update_bad_phishing_sites ]];
        then
        echo " update_bad_phishing_sites exists Skipping." ; sleep 3
else
curl $fluxlabsgit/ubuntu12/update_bad_phishing_sites -o /usr/sbin/update_bad_phishing_sites
chmod +x /usr/sbin/update_bad_phishing_sites
fi

#Check if update_bad_phishing_emails exists, if not create it.
if [[ -f /usr/sbin/update_bad_phishing_emails ]];
        then
        echo " update_bad_phishing_emails exists Skipping." ; sleep 3
else
curl $fluxlabsgit/ubuntu12/update_bad_phishing_emails -o /usr/sbin/update_bad_phishing_emails
chmod +x /usr/sbin/update_bad_phishing_emails
fi

if [[ -f /etc/cron.d/mailscanner && -f /etc/cron.d/baruwa ]];
        then
fn_clear

echo "------------------------------------------------------------------------------";
echo "A D D E D  C R O N J O B S";
echo "------------------------------------------------------------------------------";
echo -n "We have created cron entries for you."
echo ""
echo "Your Baruwa Cronjobs are setup as:"
echo ""
cat /etc/cron.d/baruwa
echo ""
echo "Your MailScanner Cronjobs are setup as:"
echo ""
cat /etc/cron.d/mailscanner
echo ""
fn_confirm

else
        fn_clear
        echo "It seems I was unable to create your cronjobs. Please look into this"; sleep 5
fi
}

# +---------------------------------------------------+
# Services Function
# +---------------------------------------------------+

fn_services (){
fn_clear
echo "------------------------------------------------------------------------------";
echo "S E R V I C E  R E S T A R T";
echo "------------------------------------------------------------------------------";
echo "Restarting necessary services for final time."
echo "We are also adding services to startup."
echo ""; sleep 3
if [[ -f $track/service ]];
        then
        echo "Sphinx has already Indexed & Rotated. Skipping."; sleep 3
else

service nginx restart
service uwsgi restart
service memcached restart
service postgresql restart
service sphinxsearch restart
service rabbitmq-server restart
service baruwa restart
service mailscanner restart
rm -r /var/log/exim4/paniclog
service exim4 restart
touch $track/service
fi

fn_clear
echo -n "Configure Clamav for Apparmor profile"
echo ""; sleep 3
echo "/var/spool/MailScanner/** rw," >> /etc/apparmor.d/local/usr.sbin.clamd
echo "/var/spool/MailScanner/incoming/** rw," >> /etc/apparmor.d/local/usr.sbin.clamd
sed -i '/exim4/a/var/spool/exim.in/** rw,' /etc/apparmor.d/usr.sbin.clamd
service apparmor restart &> /dev/null
echo "Apparmor Updated & Restarted"
freshclam
/usr/sbin/clamav-unofficial-sigs
service clamav-daemon restart
}
fn_generate_key () {
if [[ $useauto = 1 ]];
                then
        openssl req -x509 -newkey rsa:2048 -days 9999 -nodes -x509 -subj "/C=$sslcountry/ST=$sslprovince/L=$sslcity/O=$msorgname/CN=$baruwadomain" -keyout baruwa.key -out baruwa.pem -nodes
        mkdir /etc/pki{baruwa} && mv baruwa.* /etc/pki/baruwa/.
else
        openssl req -x509 -newkey rsa:2048 -keyout baruwa.key -out baruwa.pem -days 9999 -nodes
        mkdir /etc/pki && mkdir /etc/pki/baruwa && mv baruwa.* /etc/pki/baruwa/.
fi
fn_clear
}

# +---------------------------------------------------+
# Finish Up
# +---------------------------------------------------+
fn_finish (){
sed -i 's:error_email_from = baruwa@localhost:error_email_from = '$erremail':' $etcdir/production.ini
sed -i 's:baruwa.reports.sender = baruwa@ms.home.topdog-software.com:baruwa.reports.sender = '$repemail':' $etcdir/production.ini
sed -i 's:email_to = baruwa@localhost:email_to = '$admemail':' $etcdir/production.ini
sed -i 's:Africa/Johannesburg:'$timezone':' $etcdir/production.ini
sed -i 's|baruwa.default.url = http://localhost|baruwa.default.url = http://'$baruwadomain'|' $etcdir/production.ini

echo "Applying Taskids Patch"
cd /home/baruwa/px/lib/python2.7/site-packages/baruwa/controllers/
cat >taskids.sh<< 'EOF'
#!/bin/sh -xe

PATCH="
--- domains.py  2013-06-25 12:49:47.000000000 -0400
+++ domains.py  2013-06-25 13:26:18.169758564 -0400
@@ -476,6 +476,8 @@
                                     server.id,
                                     3])
             taskid = task.task_id
+            if not 'taskids' in session:
+                session['taskids'] = []
             session['taskids'].append(taskid)
             session['testdest-count'] = 1
             session.save()"
echo "$PATCH" | patch -p0
EOF
chmod +x taskids.sh
./taskids.sh

fn_clear

# +---------------------------------------------------+
# Display Results
# +---------------------------------------------------+
echo "Ok, We are all done! It looks like you now have an installed"
echo "version of Baruwa $baruwaver up and running."
echo ""
echo "Your Postgres Password is : $pssqlpass"
echo "Your RabbitMQ Password is : $rabbpass"
echo ""
echo "Your Reports will be sent from: $repemail"
echo "Your Errors wil be sent from: $erremail"
echo ""
echo "You can login at http://$baruwadomain"
echo "If you do not have DNS setup yet, you can use"
echo "http://$eth0ip"
echo  ""
echo "Username: $baruwaadmin"
echo "Password: $adminpass"
echo ""
echo "Let's send an email to $admemail with these instructions."
fn_confirm

# +---------------------------------------------------+
# Email Results
# +---------------------------------------------------+
cat >> /tmp/message << EOF
Thanks for installing Baruwa $baruwaver
----------------------------------
We have successfully installed Baruwa $baruwaver onto $baruwadomain.

Your Postgres Password is : $pssqlpass
Your Rabbit-MQ Password is : $rabbpass

Your Reports will be sent from : $repemail
Your Errors wil be sent from : $erremail

You can now login at http://$baruwadomain
If you do not have DNS setup yet, you can use
http://$eth0ip

Username: $baruwaadmin
Password: $adminpass

When you add this node. Please use $hostf as the hostname.

Please visit http://baruwa.org/docs/2.0/guide/admin/index.html
and follow the guide on how to configure your install.
--

Please support the Baruwa project by donating at
http://pledgie.com/campaigns/12056

Baruwa $baruwaver Installer by Jeremy McSpadden (jeremy at fluxlabs dot net)

This version by - Mohammed Alli
Contact - roc1479 at yahoo dot com

EOF

/usr/bin/mail -s "Baruwa $baruwaver Install for ${HOSTNAME}" < /tmp/message $admemail
cp /tmp/message ~/baruwa2_install.log
rm /tmp/message

fn_clear
echo ""
echo "An email has been sent to "$admemail"."
echo ""
echo "Please visit http://baruwa.org/docs/2.0/guide/admin/index.html"
echo "and follow the guide on how to configure your install."
echo ""``
echo "Please support the Baruwa project by donating at"
echo "http://pledgie.com/campaigns/12056"
echo ""
fn_confirm
}

# +---------------------------------------------------+
# Display menus
# +---------------------------------------------------+

menu_main() {
        clear
        echo "------------------------------"
        echo "Welcome to the Baruwa 2.0 Installer for $DISTRO $ubuntuver!"
        echo ""
        echo "Please make a choice:"
        echo ""
        echo "a) Install Baruwa"
        #echo "b) Install Pyzor, Razor & DCC"
        echo "b) Cleanup Installer"
        echo " "
        echo "x) Exit"
}

# +---------------------------------------------------+
# Choices
# +---------------------------------------------------+

read_main() {
        local choice
        read -p "Enter Choice: " choice
        case $choice in
                a) fn_directories
                     fn_requirements
                     fn_dependencies
                     fn_dnsmasq
                     fn_python
                     fn_postgresql
                     fn_rabbitmq
                     fn_mailscanner
                     fn_exim
                     fn_perl
                     fn_libmem
                     fn_configuration
                     fn_administrator
                     fn_nginx
                     fn_pyzor_razor_dcc
                     fn_cronjobs
                     fn_services
	     	     fn_generate_key
                     fn_finish ;;
                b) fn_cleanup ;;
                x) exit 0;;
                *) echo -e "Error \"$choice\" is not an option..." && sleep 2
        esac
}

# +---------------------------------------------------+
# Be sure we're root
# +---------------------------------------------------+
if [ `whoami` = root ]; then
        menu="1"
                while [ $menu = "1" ]
                do
                        menu_main
                        read_main
                done
        else
                echo "Sorry, but you are not root."
                echo "Please su - then try again."
                exit 0
        fi
# +---------------------------------------------------+


