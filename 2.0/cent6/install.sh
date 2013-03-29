#!/bin/sh
# +--------------------------------------------------------------------+
# Install for Barwua 2.0 for Cent OS/RHEL x86_64
# +--------------------------------------------------------------------+
#
# Author - Jeremy McSpadden
# Contact - jeremy@fluxlabs.net
# Copyright (C) 2013  http://www.fluxlabs.net
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
# Automated Install
# 	If you would like a completely automated install
#   Fill below out
# +---------------------------------------------------+
# Set 1 to Use the autocomplete. 0 to do prompts.
useauto=1
# Postgresql Password
pssqlpass1=passw0rd
# RabbitMQ Password
rabbpass1=passw0rd
# Baruwa Admin Email
admemail1=jeremy@fluxlabs.net
# Baruwa Reports From Email
repemail1=jeremy@fluxlabs.net
# Baruwa Error Reports From Email
erremail1=jeremy@fluxlabs.net
# Baruwa URL
bdomain1=baruwa.fluxlabs.net
# Baruwa Admin Username
adminuser1=jeremy
# Baruwa Admin Password - Must be Secure
adminpass1=M0nk3ym4n123$
# Baruwa Admin Email
adminemail1=jeremy@fluxlabs.net
# Time Zone
timezone=America/Chicago

# NOTHING TO EDIT BELOW HERE !!  NOTHING TO EDIT BELOW HERE !!

# +---------------------------------------------------+
# Information
# +---------------------------------------------------+

date="3-13-2013"						# Date
version="2.0"							# Version
osver="Cent OS/RHEL x86_64"				# Script ID
baruwa="2.0"							# Baruwa Version
centalt="6-1"							# CenAlt Version
epel="6-8"								# EPEL Version
rpmforge="0.5.2-2"						# RPM Forge Version
rabbitmq="3.0.2"						# Rabbit MQ Version
msver="4.84.5-3"						# MailScanner Version
msver1="4.84.5"							# MS Config Version
libmem="1.0.15"                      	# LIB MEM Cache Version
pythonver="2.6"							# Python Version
pyzorver="0.5.0"						# Pyzor Version
home="/home/baruwa"						# Home Directory
etcdir="/etc/baruwa"					# Baruwa etc
eximdir="/etc/exim"						# Exim Directory
track="/tmp/tracking"					# Dir for tracking
logs="/tmp/baruwa2"						# Dir for Logs

# +---------------------------------------------------+
# More Stuff
# +---------------------------------------------------+

baruwa_extras="https://raw.github.com/akissa/baruwa2/2.0.0/extras"	# Extras from Baruwa
fluxlabs_extras="https://raw.github.com/fluxlabs/baruwa/master/2.0/extras"	# Extras from Flux Labs 
hosts=$(hostname -s)
hostf=$(hostname -f)

# +---------------------------------------------------+
# Functions
# +---------------------------------------------------+

function_show_confirm(){
	read -p "Press [Enter] key to continue..." fackEnterKey
}

function_show_complete(){
	clear 2>/dev/null
	echo "------------------------------------------------------------------------------";
	echo "S E C T I O N  C O M P L E T E";
	echo "------------------------------------------------------------------------------";
	sleep 2
}

function_cleanup(){
	clear 2>/dev/null
	echo "------------------------------------------------------------------------------";
	echo "I N S T A L L E R  C L E A N  U P";
	echo "------------------------------------------------------------------------------";
	echo "Cleaning up Installer files."; sleep 5
	rm -f $home/*.patch
	rm -rf {$track,$logs}
	rm -rf /usr/src/libmemcached-$libmem
}

# +---------------------------------------------------+
# Check System
# +---------------------------------------------------+

case $(uname -s) in
    Linux) os=linux ;;
    *[oO][pP][eE][nN][bB][sS][dD]*) os=openbsd ;;
    *[Dd][Aa][Rr][Ww][Ii][Nn]*) os=darwin ;;
    *[Nn][Ee][Tt][Bb][Ss][Dd]*) os=netbsd ;;
    *[fF][rR][eE][eE][bB][sS][dD]*)
        bsdversion=`uname -r | tr -cd '0-9' | cut -b 1-2`
        if [ $bsdversion -ge 52 ]; then
           os=freebsd5
        else
           os=freebsd4
        fi
        ;;
    *)
        echo "Sorry, but this installer does not support the $(uname -s) platform."
        echo "Please verify you have downloaded the correct installer script."
        exit 1
        ;;
esac

# +---------------------------------------------------+
# Check SE Linux
# +---------------------------------------------------+

if sestatus | grep enabled;
	then
	clear 2>/dev/null
	echo "------------------------------------------------------------------------------";
	echo "S E L I N U X  D E T E C T E D";
	echo "------------------------------------------------------------------------------";
	echo "I have detected that SELinux is running and in enforce mode."
	echo "You will have to work out the necessary permissions in SELinux "
	echo "for Baruwa $ver to work properly. I cannot guarantee anything."
	echo ""
	echo "You can disable it by typing:"
	echo "sed -i -e 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config"
	echo "Then reboot and try running this script again."
	echo ""
else
	:
fi

# +---------------------------------------------------+
# Check IPTables
# +---------------------------------------------------+

if service iptables status | grep REJECT;
	then
	clear 2>/dev/null
	echo "------------------------------------------------------------------------------";
	echo "I P T A B L E S  D E T E C T E D";
	echo "------------------------------------------------------------------------------";
	echo "It looks as though iptables is enabled. It will be up to you"
	echo "to punch the appropriate holes. If port 25 is blocked, your Welcome"
	echo "email will not be sent from this installer."; sleep 10
else
	:
fi

# +---------------------------------------------------+
# Start Script
# +---------------------------------------------------+

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	___                                      ______    ______"
echo "	|  |--.---.-.----.--.--.--.--.--.---.-. |__    |  |      |"
echo "	|  _  |  _  |   _|  |  |  |  |  |  _  | |    __|__|  --  |"
echo "	|_____|___._|__| |_____|________|___._| |______|__|______|"
echo ""
echo "	Installer v$version for $osver"
echo ""
echo "------------------------------------------------------------------------------";
echo ""
echo "Welcome to the Baruwa's $baruwa Installer. (Unofficial Version)"
echo ""
echo "Before we begin: This installer was written for a minimal install of $osver"
echo "This installer is meant to assist you in installing Baruwa $baruwa "
echo ""
echo "You still need to know linux basics and have an understanding of how Baruwa $baruwa operates."
echo "It is a complete re-write from 1.0 branch. Alot of changes were made to the code and how it"
echo "works."
echo ""
echo "Please take the time to review the code that I am using below so you understand what"
echo "it is doing. This script will prompt you for the minimal amount of questions needed "
echo "to get Baruwa $baruwa installed and running. You will need to configure baruwa, your firewall,"
echo "spamassassin rules, greylisting, RBL, SPF .. etc on your own."
echo ""
echo "If you are un-sure that you can maintain a Baruwa install, I recommend going with the"
echo "commercial product at http://www.baruwa.com; or the PAAS model at http://www.baruwa.net"
echo ""
echo "Any bugs found in Baruwa itself should be reported to"
echo "the mailing list @ http://www.baruwa.org. You can contact me at jeremy@fluxlabs.net"
echo "with any concerns or additions you would like to see/add to this script."
echo ""
echo "------------------------------------------------------------------------------";
echo ""
function_show_confirm

function_directories(){
	
	if [[ -d $track && -d $logs ]];
		then
		:
	else
		mkdir $track; mkdir $logs
	fi
}

# +---------------------------------------------------+
# User Prompt Function
# +---------------------------------------------------+
function_requirements () {

if useauto=1;
	then
	:
else
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "B A R U W A   S E T T I N G S";
echo "------------------------------------------------------------------------------";
echo -n ""
while :
do
echo ""
echo "What email would you like Administrative Emails sent to?"
echo "ie: you@domain.com"
IFS= read -p "Email: " admemail1
IFS= read -p "Email Again: " admemail2
[[ $admemail1 = "$admemail2" ]] && break
echo ''
echo 'Email does not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What email would you like Report Emails sent from?"
echo "ie: reports@domain.com"
IFS= read -p "Email: " repemail1
IFS= read -p "Email Again: " repemail2
[[ $repemail1 = "$repemail2" ]] && break
echo ''
echo 'Email does not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What email would you like Error Emails sent from?"
echo "ie: errors@domain.com"
IFS= read -p "Email: " erremail1
IFS= read -p "Email Again: " erremail2
[[ $erremail1 = "$erremail2" ]] && break
echo ''
echo 'Email does not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What hostname would you like Apache to listen on for Baruwa requests?"
echo "ie: baruwa.domain.com"
IFS= read -p "Domain: " bdomain1
IFS= read -p "Domain Again: " bdomain2
[[ $bdomain1 = "$bdomain2" ]] && break
echo ''
echo 'Domain does not match. Please try again.'
echo ''
done

while :
do
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "B A R U W A  A D M I N  U S E R";
echo "------------------------------------------------------------------------------";
echo ""
echo "What would you like your username to be?"
IFS= read -p "Username: " adminuser1
IFS= read -p "Username Again: " adminuser2
[[ $adminuser1 = "$adminuser2" ]] && break
echo ''
echo 'Username deos not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What password would you like to use?"
echo "This must be a complex password!"
IFS= read -p "Password: " adminpass1
IFS= read -p "Password Again: " adminpass2
[[ $adminpass1 = "$adminpass2" ]] && break
echo ''
echo 'Passwords do not match. Please try again.'
echo ''
done

while :
do
echo ""
echo "What email would you like to use?"
IFS= read -p "Email: " adminemail1
IFS= read -p "Email Again: " adminemail2
[[ $adminemail1 = "$adminemail2" ]] && break
echo ''
echo 'Passwords do not match. Please try again.'
echo ''
done

clear 2>/dev/null
if [ -f $track/pssql ];
	then
		echo "PostgreSQL seems to already be configured. Skipping." ; sleep 3
	else
	    while :
	    do
		echo "------------------------------------------------------------------------------";
		echo "P O S T G R E S Q L  P A S S W O R D";
		echo "------------------------------------------------------------------------------";
		echo "Lets set a password for Postgres."
		echo "What would you like this super secret"
		echo "password to be?"
	    IFS= read -r -p "Password: " pssqlpass1
	    IFS= read -r -p "Password Again: " pssqlpass2
	    echo ""
	    [[ $pssqlpass1 = "$pssqlpass2" ]] && break
		echo ''
		echo 'Passwords did not match. Please try again.'
		echo ''
	done
	echo $pssqlpass1 > $track/pssqlp
fi

clear 2>/dev/null	
if [ -f $track/rabbit ];
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
	    IFS= read -r -p "Password: " rabbpass1
	    IFS= read -r -p "Password Again: " rabbpass2
	    echo ""
	    [[ $rabbpass1 = "$rabbpass2" ]] && break
		echo ''
		echo 'Passwords did not match. Please try again.'
		echo ''
	done
	echo $rabbpass1 > $track/rabbitp
fi

	clear 2>/dev/null
	echo "------------------------------------------------------------------------------";
	echo "Ok, I've got all I've needed from you. Hopefully we'll have an install ready";
	echo "for you in a bit. The process from here on out is automated. I will prompt you"
	echo "shortly for some perl mod confirmations."
	echo "------------------------------------------------------------------------------";
	echo $admemail1 $repemail1 $erremail1 $bdomain1 $adminuser1 $adminpass1 $adminemail1 $pssqlpass1 $rabbpass1 > $track/answers
	function_show_confirm	
fi
}

# +---------------------------------------------------+
# Dependencies Function
# +---------------------------------------------------+

function_dependencies(){
	clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "R E Q U I R E D  D E P E N D E N C I E S";
echo "------------------------------------------------------------------------------";
sleep 3

if [ -f $track/dependencies ];
	then
	echo "Dependencies have already been installed. Skipping."
else
	
	if rpm -q --quiet epel-release-$epel;
		then
			echo "Good, It looks as though EPEL $epel is already installed. Skipping"; sleep 2
		else
			rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-$epel.noarch.rpm
	fi

	if rpm -q --quiet centalt-release-$centalt;
		then
			echo "Good, It looks as though CENTALT $centalt is already intalled. Skipping"; sleep 2
		else
			rpm -Uvh http://centos.alt.ru/repository/centos/6/x86_64/centalt-release-$centalt.noarch.rpm
			echo -n "exclude=openssh-server openssh openssh-client" >> /etc/yum.repos.d/centalt.repo
	fi

	if rpm -q --quiet rpmforge-release-$rpmforge.el6.rf.x86_64;
		then
		echo "Good, It looks as though RPMFORGE $rpmforge is already installed. Skipping"; sleep 2
		else
			rpm -Uvh http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-$rpmforge.el6.rf.x86_64.rpm
			sed -i "12i exclude=perl-File-Temp perl" /etc/yum.repos.d/rpmforge.repo
		fi
		
	if rpm -q --quiet rabbitmq-server-$rabbitmq; 
		then
		echo "Good, It looks as though RABBITMQ $rabbitmq is already installed. Skipping"; sleep 2
		else
			rpm --import http://www.rabbitmq.com/rabbitmq-signing-key-public.asc
			cd /usr/src; wget http://www.rabbitmq.com/releases/rabbitmq-server/v$rabbitmq/rabbitmq-server-$rabbitmq-1.noarch.rpm
			yum install rabbitmq-server-$rabbitmq-1.noarch.rpm -y
	fi

	yum install gcc git gcc-c++ svn curl patch wget libxml2-devel libxslt-devel Cython postgresql-devel perl-CGI \
    freetype-devel libjpeg-devel zlib-devel openldap-devel openssl-devel swig multitail perl-DBD-Pg perl-DBD-MySQL \
    cracklib-devel GeoIP-devel mysql-devel perl-CPAN rpm-build binutils glibc-devel perl-String-CRC32  perl-YAML \
    gcc zip tar nano sudo kernel-headers ntp sed perl-DBD-Pg sphinx mlocate postgresql-server postgresql-plpython  \
    memcached spamassassin python-setuptools python-virtualenv tnef mailx clamd libmemcached-devel \
    perl-Net-CIDR perl-Sys-SigAction perl-Compress-Raw-Zlib make perl-Archive-Zip perl-Compress-Raw-Zlib \
    perl-Compress-Zlib perl-Convert-BinHex perl-Convert-TNEF perl-DBD-SQLite perl-DBI perl-Digest-HMAC \
    perl-Digest-SHA1 perl-ExtUtils-MakeMaker perl-Filesys-Df perl-File-Temp \
    perl-HTML-Parser perl-HTML-Tagset perl-IO-stringy perl-MailTools unzip \
    perl-MIME-tools perl-Net-CIDR perl-Net-DNS perl-Net-IP perl-OLE-Storage_Lite perl-Pod-Escapes \
    perl-Pod-Simple perl-Sys-Hostname-Long perl-Sys-SigAction unrar \
    perl-Test-Harness perl-Test-Pod perl-Test-Simple perl-TimeDate perl-Time-HiRes -y
	touch $track/dependencies
	clear 2>/dev/null
function_show_complete
fi
}

# +---------------------------------------------------+
# Virtual Python Function
# +---------------------------------------------------+

function_python(){
	clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "V I R T U A L  P Y T H O N  E N V I R O N M E N T";
echo "------------------------------------------------------------------------------";
sleep 3

if [ -f $track/python ];
	then
		echo "It looks as though the virtual environment already exists. Skipping."; sleep 3
	else
		echo "I am going to setup your Virtual Python Environment for Baruwa."
		echo "This process could take a while."; sleep 3
		mkdir -p $home; cd $home
python -c 'import virtualenv'; virtualenv --distribute px
source px/bin/activate; export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/requirements.txt
pip install distribute
pip install -U distribute
pip install python-memcached
pip install pyparsing==1.5.7
pip install --timeout 60 -r requirements.txt
cd $home	
curl https://sphinxsearch.googlecode.com/svn/trunk/api/sphinxapi.py -o px/lib/python$pythonver/site-packages/sphinxapi.py
curl -O $baruwa_extras/patches/repoze.who-friendly-form.patch
curl -O $baruwa_extras/patches/repoze-who-fix-auth_tkt-tokens.patch
cd $home/px/lib/python$pythonver/site-packages/repoze/who/plugins/
patch -p3 -i $home/repoze.who-friendly-form.patch
patch -p4 -i $home/repoze-who-fix-auth_tkt-tokens.patch
cd $home
curl -O $baruwa_extras/patches/subprocess_timeout.patch
cd $home/px/lib/python$pythonver/site-packages/
patch -p1 -i $home/subprocess_timeout.patch
touch $track/python
function_show_complete
fi
}

# +---------------------------------------------------+
# Postgresql Function
# +---------------------------------------------------+

function_postgresql(){
	clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "P O S T G R E S Q L";
echo "------------------------------------------------------------------------------";
sleep 3

if [ -a $track/pssql ];
	then
	echo "PostgreSQL is already setup. Skipping."
else
service postgresql initdb
service postgresql start
cat > /var/lib/pgsql/data/pg_hba.conf << 'EOF'
# TYPE  DATABASE    USER        CIDR-ADDRESS          METHOD
local   all         postgres                          trust
host    all         all         127.0.0.1/32          md5
host    all         all         ::1/128               md5
EOF

sed -e "s/^#timezone = \(.*\)$/timezone = 'UTC'/" -i /var/lib/pgsql/data/postgresql.conf
service postgresql restart
cd $home
su - postgres -c "psql postgres -c \"CREATE ROLE baruwa WITH LOGIN PASSWORD '$pssqlpass1';\""
su - postgres -c 'createdb -E UTF8 -O baruwa -T template1 baruwa'
su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpgsql;\""
su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpythonu;\""
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/baruwa/config/sql/admin-functions.sql
su - postgres -c 'psql baruwa -f '$home'/admin-functions.sql'
service postgresql restart
cd /etc/sphinx; mv /etc/sphinx/sphinx.conf /etc/sphinx/sphinx.conf.orig
curl -O $baruwa_extras/config/sphinx/sphinx.conf
sed -i -e 's:sql_host =:sql_host = 127.0.0.1:' \
-e 's:sql_user =:sql_user = baruwa:' \
-e 's:sql_pass =:sql_pass = '$pssqlpass1':' \
-e 's:sql_db =:sql_db = baruwa:' sphinx.conf
touch $track/pssql
function_show_complete
fi
}

# +---------------------------------------------------+
# Rabbit MQ Function
# +---------------------------------------------------+

function_rabbitmq(){
	clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "R A B B I T M Q ";
echo "------------------------------------------------------------------------------";
sleep 3

if [ -a $track/rabbit ];
	then
	echo "RabbitMQ has already been configured. Skipping."
else
	service rabbitmq-server start
	rabbitmqctl delete_user guest
	rabbitmqctl add_user baruwa $rabbpass1
	rabbitmqctl add_vhost $hosts
	rabbitmqctl set_permissions -p $hosts baruwa ".*" ".*" ".*"
	touch $track/rabbit
	function_show_complete
fi
}

# +---------------------------------------------------+
# Mailscanner Function
# +---------------------------------------------------+

function_mailscanner(){
	clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "M A I L S C A N N E R ";
echo "------------------------------------------------------------------------------";
sleep 3
if rpm -q --quiet mailscanner;
	then
		echo "I have detected a previous install of MailScanner." ; sleep 3
	else
		echo "This process could take a while. Go make a cup of coffee"; sleep 3
		cd /usr/src; wget http://mailscanner.info/files/4/rpm/MailScanner-$msver.rpm.tar.gz
		tar -zxvf MailScanner-$msver.rpm.tar.gz; cd MailScanner-$msver
		clear 2>/dev/null
		sh install.sh fast
		clear 2>/dev/null
		echo ""
		echo "Now let's patch it up."; sleep 3
		echo ""
	cd $home
	curl -O $baruwa_extras/patches/mailscanner-baruwa-iwantlint.patch
	curl -O $baruwa_extras/patches/mailscanner-baruwa-sql-config.patch
	cd /usr/sbin
	patch -i $home/mailscanner-baruwa-iwantlint.patch
	cd /usr/lib/MailScanner/MailScanner
	patch -p3 -i $home/mailscanner-baruwa-sql-config.patch
	cd $home
	curl -O $baruwa_extras/perl/BS.pm
	mv BS.pm /usr/lib/MailScanner/MailScanner/CustomFunctions
	cd /etc/MailScanner
	mv MailScanner.conf MailScanner.conf.orig
	cd $home
	curl -O $fluxlabs_extras/config/mailscanner/MailScanner.conf
	curl -O $baruwa_extras/config/mailscanner/scan.messages.rules
	curl -O $baruwa_extras/config/mailscanner/nonspam.actions.rules
	curl -O $baruwa_extras/config/mailscanner/filename.rules
	curl -O $baruwa_extras/config/mailscanner/filetype.rules
	curl -O $baruwa_extras/config/mailscanner/filename.rules.allowall.conf
	curl -O $baruwa_extras/config/mailscanner/filetype.rules.allowall.conf
	mv *.rules /etc/MailScanner/rules/
	mv *.conf /etc/MailScanner/
	chmod -R 777 /var/spool/MailScanner/

	sed -i 's:/usr/local:/usr/:' /usr/lib/MailScanner/clamav-autoupdate
	sed -i 's:use_auto_whitelist 0:#use_auto_whitelist 0:' /etc/mail/spamassassin/mailscanner.cf
	sed -i 's:DB Password = verysecretpw:DB Password = '$pssqlpass1':' /etc/MailScanner/MailScanner.conf
	sed -i 's:EXIM:#EXIM:' /etc/sysconfig/MailScanner
	echo EXIM=/usr/sbin/exim >> /etc/sysconfig/MailScanner
	echo EXIMINCF=$eximdir/exim.conf >> /etc/sysconfig/MailScanner
	echo EXIMSENDCF=$eximdir/exim_out.conf >> /etc/sysconfig/MailScanner
	touch $track/mailscanner
	rm -rf /usr/src/MailScanner-$msver
function_show_complete
fi
}

function_exim(){
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "E X I M  I N S T A L L";
echo "------------------------------------------------------------------------------";
sleep 3

if rpm -q --quiet postfix
	then
	service postfix stop
	yum remove postfix -y
else
	echo "Good, Postfix is not installed."; sleep 3
fi

if  rpm -q --quiet exim
	then
	echo "Exim is already installed. Skipping" ; sleep 3
else
	yum install exim  -y
fi

if rpm -q --quiet exim-pgsql && rpm -q --quiet cronie
then
	echo "Exim Dependencies are already installed. Skipping"; sleep 3
else
	yum install exim-pgsql cronie -y
fi

if [ -f /etc/sudoers.d/baruwa ];
	then
	echo "Baruwa sudoers file exists, skipping."; sleep 3
else
cat > /etc/sudoers.d/baruwa << 'EOF'
Defaults:baruwa   !requiretty, visiblepw

baruwa ALL=(exim) NOPASSWD: /usr/sbin/exim -C $eximdir/exim_out.conf -M *, \
        /usr/sbin/exim -C $eximdir/exim_out.conf -Mf *, \
        /usr/sbin/exim -C $eximdir/exim_out.conf -Mrm *, \
        /usr/sbin/exim -C $eximdir/exim_out.conf -Mg *, \
        /usr/sbin/exim -C $eximdir/exim_out.conf -Mar *, \
        /usr/sbin/exim -C $eximdir/exim_out.conf -qff, \
                /usr/sbin/exim -Mrm *, \
                /usr/sbin/exim -Mg *, \
                /usr/sbin/exim -Mar *

baruwa ALL = NOPASSWD: /bin/kill -s HUP *
EOF
chmod 0440 /etc/sudoers.d/baruwa
fi

if [[ -f $track/exim && -f $eximdir/baruwa/exim-bcrypt.pl ]];
	then
	echo "Exim is already configured. Skipping"; sleep 3
else
	
	cd $eximdir; mv $eximdir/exim.conf $eximdir/exim.conf.orig
	curl -O $fluxlabs_extras/config/exim/exim.conf
	curl -O $fluxlabs_extras/config/exim/exim_out.conf
	curl -O $baruwa_extras/config/exim/macros.conf
	curl -O $baruwa_extras/config/exim/trusted-configs
#	sed -i -e 's/spf/#spf = /' $eximdir/exim.conf
#	sed -i -e 's/dbl_/#dbl_/' $eximdir/exim_out.conf
	sed -i -e 's/verysecretpw/'$pssqlpass1'/' $eximdir/macros.conf
	mkdir $eximdir/baruwa; cd $eximdir/baruwa
	curl -0 $baruwa_extras/config/exim/baruwa/exim-bcrypt.pl
	touch $track/exim
function_show_complete
fi
}

function_perl(){
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "P E R L  M O D S  I N S T A L L";
echo "------------------------------------------------------------------------------";
sleep 3

if [ -f $track/perlmods ];
	then
	echo "Perl modules were previously installed. Skipping."; sleep 3
else
	echo "We are now going to install a few Perl Modules"
	echo "that are not available via Yum Repo's."
	echo "Please press Yes/Enter throughout the questions."
	function_show_confirm

	perl -MCPAN -e  'install Encoding::FixLatin'
	perl -MCPAN -e  'install AnyEvent::Handle'
	perl -MCPAN -e  'install EV'
	touch $track/perlmods
function_show_complete
fi
}

# +---------------------------------------------------+
# Libmem Source Function
# +---------------------------------------------------+

function_libmem(){
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "C O M P I L E  L I B M E M  S O U R C E";
echo "------------------------------------------------------------------------------";
sleep 3

if [[ -d /usr/src/libmemcached-$libmem && -f $track/libmem ]];
	then
	echo "It looks as though libmemcached $libmem was already compiled from source. Skipping."; sleep 3
else
	yum remove libmemcached -y
	cd /usr/src/; wget https://launchpad.net/libmemcached/1.0/1.0.15/+download/libmemcached-$libmem.tar.gz
	tar -zxvf libmemcached*.tar.gz; cd libmemcached*; ./configure --with-memcached=/usr/bin/memcached
	make && make install
	touch $track/libmem
function_show_complete
fi
}

# +---------------------------------------------------+
# Baruwa Function
# +---------------------------------------------------+

function_configuration(){
	clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "B U I L D I N G  B A R U W A";
echo "------------------------------------------------------------------------------";
sleep 3

if [ -f $track/baruwa-build ];
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

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "C O N F I G U R I N G  B A R U W A";
echo "------------------------------------------------------------------------------";
sleep 3

if [ -f $track/baruwaconfig ];
	then
		echo "This section has been completed. Skipping. " ; sleep 3
	else
	cd $home
	px/bin/paster make-config baruwa production.ini
	touch $track/paster
	mkdir $etcdir
	mv $home/production.ini $etcdir/production.ini
	sed -i -e 's/sqlalchemy.url/#sqlalchemy.url/' $etcdir/production.ini
	sed -i "72i sqlalchemy.url = postgresql://baruwa:$pssqlpass1@127.0.0.1:5432" $etcdir/production.ini
	sed -i -e 's:broker.password =:broker.password = '$rabbpass1':' \
		   -e 's:broker.vhost =:broker.vhost = '$hosts':' \
		   -e "s:snowy.local:$(hostname):g" \
	       -e 's:^#celery.queues:celery.queues:' $etcdir/production.ini
	touch $track/baruwaconfig

fi

if [ -f /etc/sysconfig/baruwa ];
	then
	echo "I see you already have an /etc/sysconfig/baruwa file. Skipping." ; sleep 3
else
cat > /etc/sysconfig/baruwa << 'EOF'
CELERYD_CHDIR="/etc/baruwa"
CELERYD="'$CELERYD_CHDIR'/px/bin/paster celeryd /etc/baruwa/production.ini"
CELERYD_LOG_LEVEL="INFO"
CELERYD_LOG_FILE="/var/log/baruwa/celeryd.log"
CELERYD_PID_FILE="/var/run/baruwa/celeryd.pid"
CELERYD_USER="baruwa"
CELERYD_GROUP="baruwa"
EOF
fi

if [ -x /etc/init.d/baruwa ];
	then
	echo "Skipping, as I already detect a baruwa init file." ; sleep 3
else
	cd $home
	curl -O $baruwa_extras/scripts/init/centos/baruwa.init
	mv baruwa.init /etc/init.d/baruwa
	chmod +x /etc/init.d/baruwa
fi

function_show_complete
}

# +---------------------------------------------------+
# Baruwa Admin Function
# +---------------------------------------------------+

function_administrator(){
	clear 2>/dev/null
if [ -a $track/baruwaadmin ];
	then
	echo "I believe you have already created an admin-user. Skipping."
else
	mv $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py.orig
	cd $home/px/lib/python$pythonver/site-packages/baruwa/
	curl -O https://raw.github.com/fluxlabs/scripting/build/baruwa/cent6/websetup.py
	cd $home
	virtualenv --distribute px
	source px/bin/activate
	export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
	$home/px/bin/paster setup-app $etcdir/production.ini
	$home/px/bin/paster create-admin-user -u "$adminuser1" -p "$adminpass1" -e "$adminemail1" -t UTC $etcdir/production.ini
	rm -f $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py; mv $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py.orig $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py
	touch $track/baruwaadmin
fi
}

# +---------------------------------------------------+
# Apache2 Function
# +---------------------------------------------------+

function_apache(){
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "A P A C H E  I N S T A L L A T I O N";
echo "------------------------------------------------------------------------------";
sleep 3

if rpm -q --quiet httpd;
	then
	echo "It looks like Apache is already installed. Skipping."; sleep 3
else
	yum install httpd mod_wsgi -y
fi

if [ -f /etc/httpd/conf.d/baruwa.conf ];
	then
	echo "It looks as though you already have a baruwa.conf file for Apache, Skipping."; sleep 3
else
	curl -O $baruwa_extras/config/mod_wsgi/apache.conf
	mv apache.conf /etc/httpd/conf.d/baruwa.conf
	clear 2>/dev/null
	function_show_complete
fi
}

# +---------------------------------------------------+
# CronJobs Function
# +---------------------------------------------------+

function_cronjobs(){
clear 2>/dev/null
if [ -f /etc/cron.hourly/baruwa-updateindex ];
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

if [ -f /etc/cron.d/baruwa ];
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

if [ -f /etc/cron.d/mailscanner ];
	then
	echo "MailScanner Cronjob Exists. Skipping." ; sleep 3
else
cat > /etc/cron.d/mailscanner << 'EOF'
37 5 * * * /usr/sbin/update_phishing_sites
07 * * * * /usr/sbin/update_bad_phishing_sites
58 23 * * * /usr/sbin/clean.quarantine
42 * * * * /usr/sbin/update_virus_scanners
3,23,43 * * * * /usr/sbin/check_mailscanner
EOF
fi

if grep baruwa /etc/passwd ;
	then
	:
else
getent group baruwa >/dev/null || groupadd -r baruwa
getent passwd baruwa >/dev/null || \
    useradd -r -g baruwa -d /var/lib/baruwa \
    -s /sbin/nologin -c "Baruwa User" baruwa
chown baruwa.baruwa -R /var/lib/baruwa \
        /var/run/baruwa /var/log/baruwa \
        /var/lock/baruwa /etc/MailScanner/baruwa
fi

if [[ -f /etc/cron.d/mailscanner && -f /etc/cron.d/baruwa ]];
	then
clear 2>/dev/null
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
function_show_confirm

else
	clear 2>/dev/null
	echo "It seems I was unable to create your cronjobs. Please look into this"; sleep 10
fi
}

# +---------------------------------------------------+
# Services Function
# +---------------------------------------------------+

function_services(){
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "S E R V I C E  R E S T A R T";
echo "------------------------------------------------------------------------------";
echo "Restarting necessary services for final time."
echo "We are also adding services to startup."
echo ""; sleep 3

if [ -f $track/sphinx ];
	then
	echo "Sphinx has already Indexed & Rotated. Skipping."; sleep 3
else
	indexer --all --rotate
	mkdir -p /var/log/baruwa /var/run/baruwa /var/lib/baruwa/data/{cache,sessions,uploads} \
	/var/lock/baruwa /etc/MailScanner/baruwa/signatures /etc/MailScanner/baruwa/dkim \
	/etc/MailScanner/baruwa/rules
	touch $track/sphinx
fi

mkdir /var/run/MailScanner
chmod 755 /var/run/MailScanner
chown -R baruwa: /var/log/baruwa
chown -R baruwa: /var/run/baruwa
chown -R apache: /var/lib/baruwa/data
usermod -G exim baruwa

service httpd start
chkconfig --level 345 httpd on
service memcached start
chkconfig --level 345 memcached on
service postgresql restart
chkconfig --level 345 postgresql on
service rabbitmq-server restart
chkconfig --level 345 rabbitmq-server on
service searchd restart
chkconfig --level 345 searchd on
service baruwa start
chkconfig --level 345 baruwa on
service crond start
chkconfig --level 345 crond on
service MailScanner start
chkconfig --level 345 MailScanner on
service spamassassin start
chkconfig --level 345 spamassassin on

clear 2>/dev/null
echo -n "Let's update our Clam Definitions real quick."
echo ""; sleep 3
touch /var/log/freshclam.log
chown clamav /var/log/freshclam.log
chmod 660 /var/log/freshclam.log
freshclam
chkconfig --level 345 clamd on
service clamd start
}

# +---------------------------------------------------+
# Finish Up
# +---------------------------------------------------+

function_finish(){
sed -i 's:error_email_from = baruwa@localhost:error_email_from = '$erremail1':' $etcdir/production.ini
sed -i 's:baruwa.reports.sender = baruwa@ms.home.topdog-software.com:baruwa.reports.sender = '$repemail1':' $etcdir/production.ini
sed -i 's:ServerName ms.home.topdog-software.com:ServerName '$bdomain1':' /etc/httpd/conf.d/baruwa.conf
sed -i 's:email_to = baruwa@localhost:email_to = '$admemail1':' $etcdir/production.ini
sed -i 's:Africa/Johannesburg:'$timezone':' $etcdir/production.ini
sed -i 's:baruwa.default.url = http:\/\/localhost:baruwa.default.url = http:\/\/'${hosts}':' $etcdir/production.ini

clear 2>/dev/null
# +---------------------------------------------------+
# Display Results
# +---------------------------------------------------+
echo "Your Postgres Password is : $pssqlpass1"
echo "Your RabbitMQ Password is : $rabbpass1"
echo ""
echo "Your Reports will be sent from: $repemail1"
echo "Your Errors wil be sent from: $erremail1"
echo ""
echo "You can login at http://$bdomain1"
echo "Username: $adminuser1"
echo "Password: $adminpass1"
echo ""
echo "Let's send an email to $admemail1 with these instructions."
function_show_confirm

# +---------------------------------------------------+
# Email Results
# +---------------------------------------------------+

cat >> /tmp/message << EOF
Thanks for installing Baruwa 2.0
----------------------------------
Your Postgres Password is : $pssqlpass1
Your Rabbit-MQ Password is : $rabbpass1

Your Reports will be sent from : $repemail1
Your Errors wil be sent from : $erremail1

You can now login at http://$bdomain1
Username: $adminuser1
Password: $adminpass1

Please visit http://baruwa.org/docs/2.0/guide/admin/index.html
and follow the guide on how to configure your install.

When you add this node. Please use $hosts as the hostname.

--
Baruwa 2.0 Installer

Please support the Baruwa project by donating at
http://pledgie.com/campaigns/12056

EOF

/bin/mail -s "Baruwa 2.0 Install for ${HOSTNAME}" < /tmp/message $admemail1
cp /tmp/message $logs/setup.log
rm /tmp/message

clear 2>/dev/null
echo ""
echo "An email has been sent to "$admemail1"."
echo ""
echo "Please visit http://baruwa.org/docs/2.0/guide/admin/index.html"
echo "and follow the guide on how to configure your install."
echo ""
echo "Please support the Baruwa project by donating at"
echo "http://pledgie.com/campaigns/12056"
echo ""
function_show_confirm
}

# +---------------------------------------------------+
# Pyzor, Razor & DCC Install from Atomic Repo
# +---------------------------------------------------+

function_pyzor_razor_dcc () {
	clear 2>/dev/null
	echo "------------------------------------------------------------------------------";
	echo "I N S T A L L  P Y Z O R  R A Z O R  & D C C";
	echo "------------------------------------------------------------------------------";
	echo ""; sleep 3
	cd /usr/src; curl -O http://www.atomicorp.com/installers/atomic
	sed -i "31,83d #" atomic
	sh atomic
	yum install pyzor razor-agents dcc -y
	chmod -R a+rX /usr/share/doc/pyzor-$pyzorver /usr/bin/pyzor /usr/bin/pyzord
	chmod -R a+rX /usr/lib/python2.6/site-packages/pyzor
	pyzor discover
	razor-admin -create
	razor-admin -register
	clear 2>/dev/null
	sed -i 's:= 3:= 0:' /root/.razor/razor-agent.conf
	sed -i 's:dcc_path /usr/local/bin/dccproc:dcc_path /usr/bin/dccproc:' /etc/mail/spamassassin/mailscanner.cf
	sed -i '25i loadplugin Mail::SpamAssassin::Plugin::DCC' /etc/mail/spamassassin/v310.pre
	sed -i '1i pyzor_options --homedir /var/lib/MailScanner/' /etc/MailScanner/spam.assassin.prefs.conf
	sed -i '2i razor_config /var/lib/MailScanner/.razor/razor-agent.conf' /etc/MailScanner/spam.assassin.prefs.conf
	sed -i '92i bayes_path /var/spool/MailScanner/spamassassin/bayes' /etc/MailScanner/spam.assassin.prefs.conf
	cp -R /root/.pyzor /var/lib/MailScanner
	cp -R /root/.razor /var/lib/MailScanner
	chown -R exim: /var/spool/MailScanner/
	chown -R exim: /var/lib/MailScanner/
	service MailScanner restart
	function_show_complete
}

# ---------------------------------------------------
### SECTION INCOMPLETE !!! SECTION INCOMPLETE !!! SECTION INCOMPLETE !!!

# +---------------------------------------------------+
# RabbitMQ Cluster 
# +---------------------------------------------------+

# Master
function_rabbit_master () {
while :
do
echo ""
echo "What would you like your baruwa vhost password to be?"
echo "ie: B4ruw$"
IFS= read -p "Primary Server: " baruwap1
IFS= read -p "Primary Server Again: " baruwap2
[[ $baruwap1 = "$baruwap2" ]] && break
echo ''
echo 'Password does not match.'
echo ''
done
clear 2>/dev/null

rabbitmqctl add_user baruwa $baruwap1
rabbitmqctl add_vhost $cluster1a
rabbitmqctl set_permissions -p $cluster1a baruwa ".*" ".*" ".*"
rabbitmqctl list_vhosts
rabbitmqctl stop_app
rabbitmqctl start_app

}

# Slave
function_rabbit_slave () {
	while :
	do
	echo ""
	echo "What is the hostname of your primary server?"
	echo "ie: mailsrv01"
	IFS= read -p "Primary Server: " cluster2a
	IFS= read -p "Primary Server Again: " cluster2b
	[[ $cluster2a = "$cluster2b" ]] && break
	echo ''
	echo 'Name does not match, please try again.'
	echo ''
	done
	clear 2>/dev/null
	
rabbitmqctl add_user baruwa $baruwap1
rabbitmqctl add_vhost $cluster2a
rabbitmqctl set_permissions -p $cluster2a baruwa ".*" ".*" ".*"
rabbitmqctl list_vhosts
rabbitmqctl stop_app
rabbitmqctl join_cluster --disk rabbit@$cluster2a
rabbitmqctl start_app

}

function_erlang () {
	get_key=$(cat /var/lib/rabbitmq/.erlang.cookie | awk '{ print $1 }';)
	echo "Your erlang KEY is : $get_key";
	function_show_confirm
}

function_rabbit_status () {
	clear 2>/dev/null
	rabbitmqctl status
	function_show_confirm
}

function_cluster_status () {
	clear 2>/dev/null
	rabbitmqctl cluster_status
	function_show_confirm
}


# +---------------------------------------------------+
# Display menus
# +---------------------------------------------------+

menu_main() {
	clear
	echo "------------------------------"
	echo "Welcome to the Baruwa 2.0 Installer for $osver!"
	echo ""
	echo "Please make a choice:"
	echo ""
	echo "a) Install Baruwa"
	echo "b) Install Pyzor, Razor & DCC"
	#echo "c) Setup a Cluster"
	echo "c) Cleanup Installer"
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
		a)  function_directories
			function_required
			function_dependencies
			function_python
			function_postgresql
			function_rabbitmq
			function_mailscanner
			function_exim
			function_perl
			function_libmem
			function_configuration
			function_administrator
			function_apache
			function_cronjobs
			function_services
			function_finish ;;
		b) function_pyzor_razor_dcc ;;
		#c) menu_cluster ;;
		c) function_cleanup ;;
		x) exit 0;;
		*) echo -e "Error \"$choice\" is not an option..." && sleep 2
	esac
}

menu_cluster(){
	menu=0
	clustermenu=1
	while [ $clustermenu == "1" ]
		do
			clear
	echo "------------------------------"
	echo "Cluster Options"
	echo ""
	echo "Please make a choice:"
	echo ""
	echo "a) Create Master"
	echo "b) Setup Slave"
	echo "c) Show ERLANG Key"
	echo "d) RabbitMQ Status"
	echo "e) Cluster Status"
	echo " "
	echo "x) Exit"

			local choice
			read -p "Enter Choice: " choice
			case $choice in
				a) function_master ;;
				b) function_slave ;;
				c) function_erlang ;;
				d) function_rabbit_status ;;
				e) function_cluster_status ;
					clustermenu=1
					;;
				x) menu=1 && return ;;
				*) echo -e "Error \"$choice\" is not an option..." && sleep 2
			esac
	done
}


# +---------------------------------------------------+
# Be sure we're root
# +---------------------------------------------------+

if [ `whoami` == root ]
	then
		menu="1"
		while [ $menu == "1" ]
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
