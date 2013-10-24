#!/bin/sh
# +--------------------------------------------------------------------+
# Install for Barwua 2.0 for Cent OS/RHEL x86_64
# +--------------------------------------------------------------------+
#
# Author - Jeremy McSpadden
# Contact - jeremy@fluxlabs.net
# Copyright (C) 2013  http://www.fluxlabs.net
#
# Sourced at https://github.com/fluxlabs/baruwa/blob/master/2.0/cent6/install.sh
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
#   If you would like a completely automated install
#   Fill the required fields below.
# +---------------------------------------------------+

# Set 1 to Use the autocomplete. 0 to do prompts.
useauto=0

# Set 1 to pause after every step. (semi-debug?)
usepause=0

# Postgresql Password
pssqlpass=passw0rd123!

# RabbitMQ Password
rabbpass=passw0rd321!

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
adminpass=Passw0rd123!

# Baruwa Admin Email
adminemail=admin@domain.net

# Time Zone
timezone=America/Chicago

# MailScanner Organization Name - Long
msorgnamelong='Your Organization'

# MailScanner Organization Name - Short (No Spaces)
msorgname='YourOrganization'

# SSL Country Code
sslcountry='US'

# SSL Province/State Name
sslprovince='Illinois'

# SSL City Name
sslcity='Chicago'

# +=====================================================================+

# DONE EDITING >>>> DONE EDITING >>>>> DONE EDITING >>>>> DONE EDITING

# +---------------------------------------------------+
# Version Tracking
# +---------------------------------------------------+

date="10-23-2013"						# Last Updated On
version="2.4.9"							# Script Version

osver="Cent OS/RHEL x86_64"				# Script ID
baruwaver="2.0.1"						# Baruwa Version
centalt="6-1"							# CenAlt Version
epel="6-8"								# EPEL Version
rpmforge="0.5.2-2"						# RPM Forge Version
rabbitmq="3.2.0-1"						# Rabbit MQ Version
msver="4.84.6-1"						# MailScanner Version
msver1="4.84.6"							# MS Config Version
libmem="1.0.17"							# LIB MEM Cache Version
pythonver="2.6"							# Python Version
pyzorver="0.5.0"						# Pyzor Version
postgresver="9.1"						# PostgreSQL Version
spamassver="3.3.2"						# Spamasassin Version

# +---------------------------------------------------+
# More Stuff
# +---------------------------------------------------+

baruwagit="https://raw.github.com/akissa/baruwa2/master/"			# Extras from Baruwa
fluxlabsgit="https://raw.github.com/fluxlabs/baruwa/master/2.0/"	# Extras from Flux Labs
home="/home/baruwa"						# Home Directory
etcdir="/etc/baruwa"					# Baruwa etc
eximdir="/etc/exim"						# Exim Directory
track="/tmp/tracking"					# Tracking Directory
logs="/tmp/baruwa2"						# Logs Directory
builddir="/usr/src/b2build/"			# Build Directory
hosts=$(hostname -s)
hostf=$(hostname)
eth0ip=$(ifconfig eth0 | grep "inet addr" | awk '{ print $2 }' | sed 's/addr://')
export LANG=C

# SSL Organization Name
sslorg=$msorgname

# SSL Common Name
sslcommon=$baruwadomain

# SSL Email
sslemail=$adminemail

# +---------------------------------------------------+
# Functions
# +---------------------------------------------------+

f_confirm (){
	read -p "Press [Enter] key to continue..." fackEnterKey
	echo "------------------------------------------------------------------------------";
}

f_pause (){
	echo ""
	echo "------------------------------------------------------------------------------";
	read -p "You are walking through the script. Press [Enter] to Continue" fackEnterKey
	echo "------------------------------------------------------------------------------";
}

f_exit (){
	echo ""
	echo "------------------------------------------------------------------------------";
	echo "Sorry, but it looks like I have run into an error. I am going to exit now."
	echo "------------------------------------------------------------------------------";
	read -p "Please press enter to Exit. " fackEnterKey
	exit
}

f_clear () {
	clear 2>/dev/null
}
 
f_complete (){
	if [ $usepause == 1 ];
		then
		f_pause
	else
		f_clear
		echo "------------------------------------------------------------------------------";
		echo "C O M P L E T E";
		echo "------------------------------------------------------------------------------";
		sleep 2
	fi
}

f_cleanup (){
	f_clear
	echo "------------------------------------------------------------------------------";
	echo "I N S T A L L E R  C L E A N  U P";
	echo "------------------------------------------------------------------------------";
	echo "Cleaning up Installer files."; sleep 5
	rm -f $home/*.patch; rm -f /tmp/*.sql; rm -rf /tmp/*tmp*; rm -rf /root/rpmbuild
	rm -rf {$track,$logs,$builddir}
}

# +---------------------------------------------------+
# Check hosts file entry
# +---------------------------------------------------+

if grep $eth0ip /etc/hosts ;
	then
	:
else
	f_clear
	echo "------------------------------------------------------------------------------";
	echo "M I S S I N G  H O S T  E N T R Y";
	echo "------------------------------------------------------------------------------";
	echo "It seems as though you are missing a hostname entry for $eth0ip"
	echo "I will go ahead and add it for you. For now I am just adding eth0."
	echo "If you have multiple interfaces, you can add those later."
	sleep 5
	echo $eth0ip $hostf $hosts >> /etc/hosts
	echo ""
	echo "I've added '$eth0ip $hostf $hosts' to your hosts file."
	echo "Resuming in 5 seconds ... "; sleep 5
fi

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
	f_clear
	echo "------------------------------------------------------------------------------";
	echo "S E L I N U X  D E T E C T E D";
	echo "------------------------------------------------------------------------------";
	echo "I have detected that SELinux is running and in enforce mode."
	echo "You will have to work out the necessary permissions in SELinux "
	echo "for Baruwa $baruwaver to work properly. I cannot guarantee anything."
	echo ""
	echo "You can disable it by typing:"
	echo "sed -i -e 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config"
	echo "Then reboot and try running this script again."
	echo ""
	echo "Resuming in 10 seconds ..."; sleep 10
else
	:
fi

# +---------------------------------------------------+
# Check IPTables
# +---------------------------------------------------+

if service iptables status | grep REJECT;
	then
	f_clear
	echo "------------------------------------------------------------------------------";
	echo "I P T A B L E S  D E T E C T E D";
	echo "------------------------------------------------------------------------------";
	echo "It looks as though iptables is enabled. It will be up to you"
	echo "to punch the appropriate holes. If port 25 is blocked, your Welcome"
	echo "email will not be sent from this installer."
	echo "Resuming in 10 seconds ..."; sleep 10
else
	:
fi

# +---------------------------------------------------+
# Start Script
# +---------------------------------------------------+

f_clear
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
echo "Welcome to the Baruwa's $baruwaver Installer. (Unofficial Version)"
echo ""
echo "Before we begin: This installer was written for a minimal install of $osver"
echo "This installer is meant to assist you in installing Baruwa $baruwaver "
echo ""
echo "You still need to know linux basics and have an understanding of how Baruwa $baruwaver operates."
echo "It is a complete re-write from 1.0 branch. Alot of changes were made to the code and how it"
echo "works."
echo ""
echo "This script will prompt you for the minimal amount of questions needed "
echo "to get Baruwa $baruwaver installed and running."
echo ""
echo "If you are un-sure that you can maintain a Baruwa install, I recommend going with the"
echo "commercial product at http://www.baruwa.com or the PAAS model at http://www.baruwa.net"
echo ""
echo "Any bugs found in Baruwa itself should be reported to"
echo "the mailing list @ http://www.baruwa.org. You can contact me at jeremy@fluxlabs.net"
echo "with any concerns or additions you would like to see/add to this script."
echo ""
echo "------------------------------------------------------------------------------";
echo ""
f_confirm

f_directories (){

	if [[ -d $track && -d $logs && -d $builddir ]];
		then
		:
	else
		mkdir {$track,$logs,$builddir}
	fi
}

# +---------------------------------------------------+
# User Prompt Function
# +---------------------------------------------------+

f_requirements (){

if [ $useauto == 1 ];
	then
	:
else
	
f_clear
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
	
	baruwadomain = $(hostname)
	
	#while :
	#do
	#echo ""
	#echo "What hostname would you like Apache to listen on for Baruwa requests?"
	#echo "ie: baruwa.domain.com"
	#IFS= read -p "Domain: " baruwadomain
	#IFS= read -p "Domain Again: " bdomain2
	#[[ $baruwadomain = "$bdomain2" ]] && break
	#echo ''
	#echo 'Domain does not match. Please try again.'
	#echo ''
	#done
		
while :
	do
		f_clear
		echo "------------------------------------------------------------------------------";
		echo "B A R U W A  A D M I N  U S E R";
		echo "------------------------------------------------------------------------------";
		echo ""
		echo "What would you like your username to be?"
		IFS= read -p "Username: " baruwaadmin
		IFS= read -p "Username Again: " adminuser2
		[[ $baruwaadmin = "$adminuser2" ]] && break
		echo ''
		echo 'Username deos not match. Please try again.'
		echo ''
	done

while :
	do
		echo ""
		echo "What password would you like to use?"
		echo "This must be a complex password!"
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
		IFS= read -p "Email: " adminemail
		IFS= read -p "Email Again: " adminemail2
		[[ $adminemail = "$adminemail2" ]] && break
		echo ''
		echo 'Passwords do not match. Please try again.'
		echo ''
	done
	
while :
	do
		f_clear
		echo "------------------------------------------------------------------------------";
		echo "P O S T G R E S Q L  P A S S W O R D";
		echo "------------------------------------------------------------------------------";
		echo ""
		echo "Lets set a password for Postgres."
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

		while :
		do
		f_clear
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

	f_clear
	echo "------------------------------------------------------------------------------";
	echo "Ok, I've got all I've needed from you. Hopefully we'll have an install ready";
	echo "for you in a bit. The process from here on out is automated."
	echo "------------------------------------------------------------------------------";
	echo $admemail $repemail $erremail $baruwadomain $baruwaadmin $adminpass $adminemail $pssqlpass $rabbpass > $track/answers
f_confirm
fi
}

# +---------------------------------------------------+
# Dependencies Function
# +---------------------------------------------------+

f_dependencies (){
	f_clear
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
			rpm -Uvh http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-$epel.noarch.rpm
	fi

	if rpm -q --quiet centalt-release-$centalt;
		then
			echo "Good, It looks as though CENTALT $centalt is already intalled. Skipping"; sleep 2
		else
			rpm -Uvh http://centos.alt.ru/repository/centos/6/x86_64/centalt-release-$centalt.noarch.rpm
			echo -n "exclude=openssh-server openssh openssh-clients perl-Razor-Agent razor-agents clamav clamav-db clamd bind-chroot sphinx mariadb* mysql* perl-DBD-MySQL*" >> /etc/yum.repos.d/centalt.repo
	fi

	if rpm -q --quiet rpmforge-release-$rpmforge.el6.rf.x86_64;
		then
		echo "Good, It looks as though RPMFORGE $rpmforge is already installed. Skipping"; sleep 2
		else
			rpm -Uvh http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-$rpmforge.el6.rf.x86_64.rpm
			sed -i "12i exclude=openssh openssh-clients perl-File-Temp perl perl-Razor-Agent razor-agents" /etc/yum.repos.d/rpmforge.repo
		fi

	yum install gcc git gcc-c++ svn curl patch wget libxml2-devel libxslt-devel Cython postgresql-devel perl-CGI \
    freetype-devel libjpeg-devel zlib-devel openldap-devel openssl-devel swig multitail perl-DBD-Pg perl-DBD-MySQL \
    cracklib-devel GeoIP-devel mysql-devel perl-CPAN rpm-build binutils glibc-devel perl-String-CRC32  perl-YAML \
    gcc zip tar nano sudo kernel-headers ntp sed perl-DBD-Pg sphinx libsphinxclient mlocate postgresql-server postgresql-plpython  \
    memcached spamassassin python-setuptools python-virtualenv tnef mailx clamd libmemcached-devel \
    perl-Net-CIDR perl-Sys-SigAction perl-Compress-Raw-Zlib make perl-Archive-Zip perl-Compress-Raw-Zlib \
    perl-Compress-Zlib perl-Convert-BinHex perl-Convert-TNEF perl-DBD-SQLite perl-DBI perl-Digest-HMAC \
    perl-Digest-SHA1 perl-ExtUtils-MakeMaker perl-Filesys-Df perl-File-Temp \
    perl-HTML-Parser perl-HTML-Tagset perl-IO-stringy perl-MailTools unzip clamav perl-IP-Country \
    perl-MIME-tools perl-Net-CIDR perl-Net-DNS perl-Net-IP perl-OLE-Storage_Lite perl-Pod-Escapes \
    perl-Pod-Simple perl-Sys-Hostname-Long perl-Sys-SigAction unrar perl-Mail-SPF \
    perl-Test-Harness perl-Test-Pod perl-Test-Simple perl-TimeDate perl-Time-HiRes perl-Net-Ident re2c -y
	if [ $? -eq 0 ];
		then
    touch $track/dependencies
    f_complete
	else
        echo ""
        echo "Ooops !"
        echo "It seems I've run into an error installing the dependencies."
        echo "Please send the package dependency error to jeremy@fluxlabs.net"
        echo ""
        f_exit
	fi
fi
}
# +---------------------------------------------------+
# Virtual Python Function
# +---------------------------------------------------+

f_python (){
	f_clear
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
curl -O https://raw.github.com/akissa/baruwa2/master/requirements.txt
pip install distribute
pip install -U distribute
pip install python-memcached
pip install --timeout 120 -r requirements.txt
pip install babel==0.9.6
cd $home
cp /usr/share/doc/libsphinxclient-*/sphinxapi.py px/lib/python$pythonver/site-packages/sphinxapi.py
curl -O $baruwagit/extras/patches/repoze.who-friendly-form.patch
curl -O $baruwagit/extras/patches/repoze-who-fix-auth_tkt-tokens.patch
cd $home/px/lib/python$pythonver/site-packages/repoze/who/plugins/
patch -p3 -i $home/repoze.who-friendly-form.patch
patch -p4 -i $home/repoze-who-fix-auth_tkt-tokens.patch
touch $track/python
f_complete
fi
}

# +---------------------------------------------------+
# Postgresql Function
# +---------------------------------------------------+

f_postgresql (){
	f_clear
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
local	all         baruwa                            trust
host    all         all         127.0.0.1/32          md5
host    all         all         ::1/128               md5
EOF

sed -e "s/^#timezone = \(.*\)$/timezone = 'UTC'/" -i /var/lib/pgsql/data/postgresql.conf
service postgresql restart
cd $home
su - postgres -c "psql postgres -c \"CREATE ROLE baruwa WITH LOGIN PASSWORD '$pssqlpass';\""
su - postgres -c 'createdb -E UTF8 -O baruwa -T template0 baruwa'
su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpgsql;\""
su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpythonu;\""
curl -O $baruwagit/baruwa/config/sql/admin-functions.sql
su - postgres -c 'psql baruwa -f '$home'/admin-functions.sql'

# Bayes/AWL DB
cd /tmp; curl -O $fluxlabsgit/extras/bayes/bayes-postgres.sql
cd /tmp; curl -O $fluxlabsgit/extras/bayes/awl-postgres.sql
cd /tmp; curl -O $fluxlabsgit/extras/bayes/grants.sql
su - postgres -c 'psql baruwa -f /tmp/bayes-postgres.sql'
su - postgres -c 'psql baruwa -f /tmp/awl-postgres.sql'
su - postgres -c 'psql baruwa -f /tmp/grants.sql'

service postgresql restart

cd /etc/sphinx; mv /etc/sphinx/sphinx.conf /etc/sphinx/sphinx.conf.orig
curl -O $baruwagit/extras/config/sphinx/sphinx.conf
sed -i -e 's:sql_host =:sql_host = 127.0.0.1:' \
-e 's:sql_user =:sql_user = baruwa:' \
-e 's:sql_pass =:sql_pass = '$pssqlpass':' \
-e 's:sql_db =:sql_db = baruwa:' sphinx.conf
touch $track/pssql
f_complete
fi
}

# +---------------------------------------------------+
# Rabbit MQ Function
# +---------------------------------------------------+

f_rabbitmq (){
	f_clear
echo "------------------------------------------------------------------------------";
echo "R A B B I T M Q ";
echo "------------------------------------------------------------------------------";
sleep 3

if rpm -q --quiet rabbitmq-server-$rabbitmq;
	then
	echo "Good, It looks as though RABBITMQ $rabbitmq is already installed. Skipping"; sleep 2
	else
		rpm --import http://www.rabbitmq.com/rabbitmq-signing-key-public.asc
		cd $builddir; wget http://www.rabbitmq.com/releases/rabbitmq-server/current/rabbitmq-server-$rabbitmq.noarch.rpm
		yum install rabbitmq-server-$rabbitmq.noarch.rpm -y
fi

if [ -a $track/rabbit ];
	then
	echo "RabbitMQ has already been configured. Skipping."
else
	service rabbitmq-server start
	rabbitmqctl delete_user guest
	rabbitmqctl add_user baruwa $rabbpass
	rabbitmqctl add_vhost $hosts
	rabbitmqctl set_permissions -p $hosts baruwa ".*" ".*" ".*"
	touch $track/rabbit
	f_complete
fi
}

# +---------------------------------------------------+
# Mailscanner Function
# +---------------------------------------------------+

f_mailscanner (){
	f_clear
echo "------------------------------------------------------------------------------";
echo "M A I L S C A N N E R ";
echo "------------------------------------------------------------------------------";
sleep 3
if rpm -q --quiet mailscanner;
	then
		echo "I have detected a previous install of MailScanner." ; sleep 3
	else
		echo "This process could take a while. Go make a cup of coffee"; sleep 3
		cd $builddir; wget https://github.com/fluxlabs/baruwa/raw/master/2.0/extras/centos/MailScanner-$msver.rpm.tar.gz
		tar -zxvf MailScanner-$msver.rpm.tar.gz; cd MailScanner-$msver
		f_clear
		sh install.sh fast
		f_clear
		echo ""
		echo "Now let's patch it up."; sleep 3
		echo ""
	cd $home
	curl -O $baruwagit/extras/patches/mailscanner-baruwa-iwantlint.patch
	curl -O $baruwagit/extras/patches/mailscanner-baruwa-sql-config.patch
	cd /usr/sbin
	patch -i $home/mailscanner-baruwa-iwantlint.patch
	cd /usr/lib/MailScanner/MailScanner
	patch -p3 -i $home/mailscanner-baruwa-sql-config.patch
	cd $home
	curl -O $baruwagit/extras/perl/BS.pm
	mv BS.pm /usr/lib/MailScanner/MailScanner/CustomFunctions
	cd /etc/MailScanner
	mv MailScanner.conf MailScanner.conf.orig
	cd $home
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/MailScanner.conf
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/spam.assassin.prefs.conf
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/scan.messages.rules
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/nonspam.actions.rules
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/filename.rules
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/filetype.rules
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/filename.rules.allowall.conf
	curl -O $fluxlabsgit/extras/centos/config/mailscanner/filetype.rules.allowall.conf
	rm -f /etc/mail/spamassassin/local.cf
	ln -s /etc/MailScanner/spam.assassin.prefs.conf /etc/mail/spamassassin/local.cf
	mv *.rules /etc/MailScanner/rules/
	mv *.conf /etc/MailScanner/
	chmod -R 777 /var/spool/MailScanner/

	sed -i 's:/usr/local:/usr/:' /usr/lib/MailScanner/clamav-autoupdate
	sed -i 's:DB Password = verysecretpw:DB Password = '$pssqlpass':' /etc/MailScanner/MailScanner.conf
	sed -i 's:EXIM:#EXIM:' /etc/sysconfig/MailScanner
	echo EXIM=/usr/sbin/exim >> /etc/sysconfig/MailScanner
	echo EXIMINCF=$eximdir/exim.conf >> /etc/sysconfig/MailScanner
	echo EXIMSENDCF=$eximdir/exim_out.conf >> /etc/sysconfig/MailScanner
	rm -f /etc/mail/spamassassin/mailscanner.cf
	sed -i '1d' /usr/sbin/MailScanner
	sed -i '1i #!/usr/bin/perl -I/usr/lib/MailScanner -U' /usr/sbin/MailScanner
	touch $track/mailscanner
	rm -rf $builddir/MailScanner-$msver
f_complete
fi
}

# +---------------------------------------------------+
# Exim Function
# +---------------------------------------------------+

f_exim (){
f_clear
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

baruwa ALL=(exim) NOPASSWD: /usr/sbin/exim -C /etc/exim/exim_out.conf -M *, \
        /usr/sbin/exim -C /etc/exim/exim_out.conf -Mf *, \
        /usr/sbin/exim -C /etc/exim/exim_out.conf -Mrm *, \
        /usr/sbin/exim -C /etc/exim/exim_out.conf -Mg *, \
        /usr/sbin/exim -C /etc/exim/exim_out.conf -Mar *, \
        /usr/sbin/exim -C /etc/exim/exim_out.conf -qff, \
                /usr/sbin/exim -Mrm *, \
                /usr/sbin/exim -Mg *, \
                /usr/sbin/exim -Mar *

baruwa ALL = NOPASSWD: /bin/kill -s HUP *
EOF
chmod 0440 /etc/sudoers.d/baruwa
fi

if [[ -f $track/exim ]];
	then
	echo "Exim is already configured. Skipping"; sleep 3
else
	cd $eximdir; mv $eximdir/exim.conf $eximdir/exim.conf.orig
	curl -O $fluxlabsgit/extras/centos/config/exim/exim.conf
	curl -O $fluxlabsgit/extras/centos/config/exim/exim_out.conf
	curl -O $baruwagit/extras/config/exim/macros.conf
	curl -O $baruwagit/extras/config/exim/trusted-configs
	sed -i -e 's/verysecretpw/'$pssqlpass'/' $eximdir/macros.conf
	mkdir $eximdir/baruwa; cd $eximdir/baruwa
	curl -0 $baruwagit/extras/config/exim/baruwa/exim-bcrypt.pl
	touch $track/exim
f_complete
fi
}

# +---------------------------------------------------+
# Perl Function
# +---------------------------------------------------+

f_perl (){
f_clear
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
	sleep 3

	yes, y, yes | cpan String::CRC32 Encoding::FixLatin AnyEvent::Handle EV DBD::mysql DBD::Pg
	touch $track/perlmods
f_complete
fi
}

# +---------------------------------------------------+
# Libmem Source Function
# +---------------------------------------------------+

f_libmem (){
f_clear
echo "------------------------------------------------------------------------------";
echo "C O M P I L E  L I B M E M  S O U R C E";
echo "------------------------------------------------------------------------------";
sleep 3

if [[ -d $builddir/libmemcached-$libmem && -f $track/libmem ]];
	then
	echo "It looks as though libmemcached $libmem was already compiled from source. Skipping."; sleep 3
else
	yum remove libmemcached -y
	cd $builddir/; wget https://launchpad.net/libmemcached/1.0/$libmem/+download/libmemcached-$libmem.tar.gz
	tar -zxvf libmemcached*.tar.gz; cd libmemcached*; ./configure --with-memcached
	make && make install
	touch $track/libmem
f_complete
fi
}

# +---------------------------------------------------+
# Baruwa Configuration Function
# +---------------------------------------------------+

f_configuration (){
	f_clear
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

f_clear
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
	sed -i "72i sqlalchemy.url = postgresql://baruwa:$pssqlpass@127.0.0.1:5432/baruwa" $etcdir/production.ini
	sed -i -e 's:broker.password =:broker.password = '$rabbpass':' \
           -e 's:broker.vhost = baruwa:broker.vhost = '$hosts':' \
           -e "s:snowy.local:$(hostname):g" \
           -e 's:^#celery.queues:celery.queues:' $etcdir/production.ini
	touch $track/baruwaconfig

fi

if [ -f /etc/sysconfig/baruwa ];
	then
	echo "I see you already have an /etc/sysconfig/baruwa file. Skipping." ; sleep 3
else
cat > /etc/sysconfig/baruwa << 'EOF'
CELERYD_CHDIR="/home/baruwa"
CELERYD="$CELERYD_CHDIR/px/bin/paster celeryd /etc/baruwa/production.ini"
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
	curl -O $baruwagit/extras/scripts/init/centos/baruwa.init
	mv baruwa.init /etc/init.d/baruwa
	chmod +x /etc/init.d/baruwa
fi
f_complete
}

# +---------------------------------------------------+
# Baruwa Admin Function
# +---------------------------------------------------+

f_administrator (){
	f_clear
if [ -a $track/baruwaadmin ];
	then
	echo "I believe you have already created an admin-user. Skipping."
else
	mv $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py.orig
	cd $home/px/lib/python$pythonver/site-packages/baruwa/
	curl -O $fluxlabsgit/extras/websetup.py
	cd $home
	virtualenv --distribute px
	source px/bin/activate
	export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
	$home/px/bin/paster setup-app $etcdir/production.ini
	$home/px/bin/paster create-admin-user -u "$baruwaadmin" -p "$adminpass" -e "$adminemail" -t UTC $etcdir/production.ini
	rm -f $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py; mv $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py.orig $home/px/lib/python$pythonver/site-packages/baruwa/websetup.py
	touch $track/baruwaadmin
fi
}

# +---------------------------------------------------+
# HTTP Function
# +---------------------------------------------------+

f_http (){
f_clear
echo "------------------------------------------------------------------------------";
echo "H T T P  I N S T A L L A T I O N";
echo "------------------------------------------------------------------------------";
sleep 3

# Work in Progress - Still need to tweak the NGINX/WSGI configs .. no variable defined for $vps
#if [ $vps == 1 ];
#	then
#	yum install python-pip
#	pip install uwqsgi
#	mkdir -p /var/log/uwsgi; touch /var/log/uwsgi/uwsgi-baruwa.log
#	curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/uwsgi/nginx.conf
#	mv nginx.conf /etc/nginx/conf.d/baruwa.conf
#	sed -i -e 's:ms.home.topdog-software.com:'$baruwadomain':' /etc/nginx/conf.d/baruwa.conf
#	service nginx restart
#else
	
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
	curl -O $baruwagit/extras/config/mod_wsgi/apache.conf
	mv apache.conf /etc/httpd/conf.d/baruwa.conf
	f_complete
fi
}

# +---------------------------------------------------+
# Pyzor, Razor & DCC Install from Atomic Repo
# +---------------------------------------------------+

f_pyzor_razor_dcc (){
	f_clear
	if [ -a $track/pyzor ];
		then
		echo "I believe these are already installed. Skipping."
	else
	echo "------------------------------------------------------------------------------";
	echo "I N S T A L L  P Y Z O R  R A Z O R  & D C C";
	echo "------------------------------------------------------------------------------";
	echo ""; sleep 3
	
	cd $builddir; curl -O http://www.atomicorp.com/installers/atomic
	sed -i "48,93d #" atomic
	sh atomic
	yum install pyzor razor-agents -y
	chmod -R a+rX /usr/share/doc/pyzor-$pyzorver /usr/bin/pyzor /usr/bin/pyzord
	chmod -R a+rX /usr/lib/python2.6/site-packages/pyzor
	mkdir /var/lib/pyzor; mkdir /var/lib/razor; cd /var/lib/pyzor
	pyzor discover
	mkdir /etc/mail/spamassassin/.razor
	razor-admin -home=/etc/mail/spamassassin/.razor -register
	razor-admin -home=/etc/mail/spamassassin/.razor -create
	razor-admin -home=/etc/mail/spamassassin/.razor -discover
	f_clear
	cd /usr/src
	wget http://www.rhyolite.com/dcc/source/dcc.tar.Z
	gzip -d dcc.tar.Z
	tar -xf dcc.tar*
	cd dcc-*
	./configure && make && make install
	f_clear
	sed -i "13i exclude=mysql mariadb-libs mariadb-devel mysql-libs mysql-devel mariadb" /etc/yum.repos.d/atomic.repo
	sed -i "24i exclude=mysql mariadb-libs mariadb-devel mysql-libs mysql-devel mariadb" /etc/yum.repos.d/atomic.repo
	sed -i "34i exclude=mysql mariadb-libs mariadb-devel mysql-libs mysql-devel mariadb" /etc/yum.repos.d/atomic.repo
	yum update -y
	sed -i 's:= 3:= 0:' /etc/mail/spamassassin/.razor/razor-agent.conf
	sed -i '25i loadplugin Mail::SpamAssassin::Plugin::DCC' /etc/mail/spamassassin/v310.pre
	sed -i '92i bayes_path /var/spool/MailScanner/spamassassin/bayes' /etc/MailScanner/spam.assassin.prefs.conf
	echo loadplugin Mail::SpamAssassin::Plugin::AWL >> /etc/mail/spamassassin/v310.pre
	echo loadplugin Mail::SpamAssassin::Plugin::Rule2XSBody >> /etc/mail/spamassassin/v320.pre
	echo loadplugin Mail::SpamAssassin::Plugin::RelayCountry >> /etc/mail/spamassassin/init.pre
	sed -i '1d' /usr/bin/pyzor
	sed -i '1i #!/usr/bin/python -Wignore::DeprecationWarning' /usr/bin/pyzor
	echo "root $adminemail" >> /etc/aliases
	newaliases
	touch $track/pyzor
	f_complete
fi
}

# +---------------------------------------------------+
# Clam Function
# +---------------------------------------------------+

f_clam (){
	if [ -f $track/sphinx ];
		then
		echo "Sphinx has already Indexed & Rotated. Skipping."; sleep 3
	else
		indexer --all --rotate
		touch $track/sphinx
	fi

	if [ -f $track/clam ];
		then
		echo "I believe you have already executed this portion. Skipping."
	else
		usermod -a -G clamav exim
		usermod -a -G clamav mail
		usermod -a -G exim clamav
		rm -rf /var/lib/clamav; mkdir -p /var/lib/clamav
		ln -s /var/lib/clamav /var/clamav
		chown -R clamav:clamav /var/lib/clamav
		touch /var/log/clamav/freshclam.log
		cd /etc; rm -f clamd.conf; wget $fluxlabsgit/extras/centos/config/clamd.conf
		sed -i -e 's:var/clamav:var/lib/clamav:' /etc/clamd.conf
		sed -i -e 's:var/clamav:var/lib/clamav:' /etc/freshclam.conf
		sed -i -e 's:CHANGE:'$pssqlpass':' /etc/MailScanner/spam.assassin.prefs.conf
		sed -i -e '19 s:usr/local:usr:' /etc/MailScanner/virus.scanners.conf
		f_clear
		echo -n ""
		echo -n ""
		echo -n "Let's update our Clam Definitions real quick."
		echo -n ""
		echo -n ""
		echo ""; sleep 3
		chown -R clamav:clamav /var/log/clamav
		service clamd start
		freshclam
		service MailScanner restart
		sa-learn --sync /usr/share/doc/spamassassin-$spamassver/sample-spam.txt
		f_clear
		echo ""
		echo "Now lets compile some SA Rules."
		echo ""
		sa-compile
		yum update -y
		touch $track/clam
	fi
}

# +---------------------------------------------------+
# Generate SSL Function
# +---------------------------------------------------+

f_generate_key (){
if [ $useauto == 1 ];
		then
	openssl req -x509 -newkey rsa:2048 -days 9999 -nodes -x509 -subj "/C=$sslcountry/ST=$sslprovince/L=$sslcity/O=$msorgname/CN=$baruwadomain" -keyout baruwa.key -out baruwa.pem -nodes
	mkdir /etc/pki/baruwa; mv baruwa.* /etc/pki/baruwa/.
else
	f_clear
	echo "------------------------------------------------------------------------------";
	echo "G E N E R A T E  C E R T I F I C A T E";
	echo "------------------------------------------------------------------------------";
	echo "Let's generate an ssl certificate for exim."
	echo "Please answer the questions appropriately."
	echo ""; sleep 3
	openssl req -x509 -newkey rsa:2048 -keyout baruwa.key -out baruwa.pem -days 9999 -nodes
	mkdir /etc/pki/baruwa; mv baruwa.* /etc/pki/baruwa/.
fi
f_clear
}

# +---------------------------------------------------+
# CronJobs Function
# +---------------------------------------------------+

f_cronjobs (){
f_clear
if [ -f /etc/cron.d/baruwa ];
	then
	echo "Baruwa Cronjobs exists. Skipping." ; sleep 3
else
cat > /etc/cron.d/baruwa << 'EOF'
*/3 * * * * exim /home/baruwa/px/bin/paster update-queue-stats /etc/baruwa/production.ini >/dev/null 2>&1
0 * * * * baruwa /home/baruwa/px/bin/paster update-sa-rules /etc/baruwa/production.ini >/dev/null 2>&1
0 * * * * root /home/baruwa/px/bin/paster update-delta-index --index messages --realtime /etc/baruwa/production.ini >/dev/null 2>&1
0 0 * * * baruwa /home/baruwa/px/bin/paster send-quarantine-reports /etc/baruwa/production.ini >/dev/null 2>&1
0 1 * * * baruwa /home/baruwa/px/bin/paster prune-database /etc/baruwa/production.ini >/dev/null 2>&1
9 1 * * * root /home/baruwa/px/bin/paster update-delta-index --index archive /etc/baruwa/production.ini >/dev/null 2>&1
0 2 * * * baruwa /home/baruwa/px/bin/paster prune-quarantine /etc/baruwa/production.ini >/dev/null 2>&1
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
fi
}

# +---------------------------------------------------+
# Permissions Function
# +---------------------------------------------------+

f_permissions (){
f_clear
echo "------------------------------------------------------------------------------";
echo "S E T  P E R M I S S I O N S";
echo "------------------------------------------------------------------------------";
echo "Adjusting file/folder permissions."
echo ""
echo ""; sleep 3
chown -R exim:exim /var/spool/MailScanner/
mkdir -p /var/log/baruwa
mkdir -p /var/run/baruwa
mkdir -p /var/lib/baruwa/data/{cache,sessions,uploads,templates}
mkdir -p /var/lock/baruwa
mkdir -p /etc/MailScanner/baruwa/{signatures,dkim,rules}
mkdir -p /etc/MailScanner/baruwa/signatures/domains
mkdir -p /var/lib/baruwa/.spamassassin
chown -R apache:baruwa /var/lib/baruwa
chown -R baruwa:baruwa /var/run/baruwa
chown -R baruwa:baruwa /var/log/baruwa
chown -R baruwa:baruwa /var/lock/baruwa
chmod o+w,g+w /var/lock/baruwa
chmod -R 755 /etc/MailScanner/baruwa
chown -R baruwa: /etc/MailScanner/baruwa
f_clear

}
# +---------------------------------------------------+
# Services Function
# +---------------------------------------------------+

f_services (){
	if [ -f $track/services ];
		then
		:
		else
		f_clear
		echo "------------------------------------------------------------------------------";
		echo "S E R V I C E  R E S T A R T";
		echo "------------------------------------------------------------------------------";
		echo "Restarting necessary services for final time."
		echo "We are also adding services to startup."
		echo ""; sleep 3
	
		service clamd start
		#service exim restart
		chkconfig --level 345 clamd on
		service httpd start
		chkconfig --level 345 httpd on
		service memcached start
		chkconfig --level 345 memcached on
		service postgresql restart
		chkconfig --level 345 postgresql on
		service rabbitmq-server restart
		chkconfig --level 345 rabbitmq-server on
		service searchd start
		chkconfig --level 345 searchd on
		service baruwa start
		chkconfig --level 345 baruwa on
		service crond start
		chkconfig --level 345 crond on
		service MailScanner start
		chkconfig --level 345 MailScanner on
		service spamassassin start
		chkconfig --level 345 spamassassin on
		yum remove bind-chroot -y
		yum install bind -y
		chkconfig --level 345 named on
		sed -i '1i nameserver 127.0.0.1' /etc/resolv.conf
		service named start
		touch $track/services
		f_clear
	fi
}
# +---------------------------------------------------+
# Finish Up
# +---------------------------------------------------+

f_finish (){
sed -i 's:error_email_from = baruwa@localhost:error_email_from = '$erremail':' $etcdir/production.ini
sed -i 's:baruwa.reports.sender = baruwa@ms.home.topdog-software.com:baruwa.reports.sender = '$repemail':' $etcdir/production.ini
sed -i 's:ServerName ms.home.topdog-software.com:ServerName '$baruwadomain':' /etc/httpd/conf.d/baruwa.conf
sed -i 's:email_to = baruwa@localhost:email_to = '$admemail':' $etcdir/production.ini
sed -i 's:Africa/Johannesburg:'$timezone':' $etcdir/production.ini
sed -i 's|baruwa.default.url = http://localhost|baruwa.default.url = http://'$baruwadomain'|' $etcdir/production.ini


f_clear
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
echo "Let's send an email to $admemail with more instructions"
echo "on your next steps to get Baruwa up and running."
f_confirm

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

Lets start by adding this scanning node at http://$eth0ip/settings/node/add
use $baruwadomain as your Hostname.

Once you have added this node, you can check its status at http://$eth0ip/status/node/2

Please visit http://baruwa.org/docs/2.0/guide/admin/index.html
and follow the guide on how to start adding Organizations and Domains.

--
Baruwa $baruwaver Installer by Jeremy McSpadden (jeremy at fluxlabs dot net)

Please support the Baruwa project by donating at
http://pledgie.com/campaigns/12056

EOF

/bin/mail -s "Baruwa $baruwaver Install for ${HOSTNAME}" < /tmp/message $admemail

cat >> /tmp/success << EOF
Successful install by $admemail on ${HOSTNAME}
EOF

/bin/mail -s "[Baruwa Installer] - ${HOSTNAME}" < /tmp/success jeremy@fluxlabs.net
rm -f /tmp/success

mv /tmp/message ~/baruwa2_install.log
f_clear
	echo ""
	echo "An email has been sent to "$admemail"."
	echo ""
	echo "Please visit http://baruwa.org/docs/2.0/guide/admin/index.html"
	echo "and follow the guide on how to configure your install."
	echo ""
	echo "I have also sent a small email to Flux Labs"
	echo "letting them know that you've succesfully installed Baruwa using"
	echo "this script. It contains zero information regarding your system."
	echo ""
	echo "Please support the Baruwa project by donating at"
	echo "http://pledgie.com/campaigns/12056"
	echo ""
f_confirm
}
# +---------------------------------------------------+
# Additional SA Rules
# +---------------------------------------------------+
f_additional_sa (){
	if [ -f $track/additional_sa ];
		then
			echo "The Additional Spam Assassin Rules are already installed."
		else
		f_clear
		echo "------------------------------------------------------------------------------";
		echo "A D D I T I O N A L  S A  R U L E S";
		echo "------------------------------------------------------------------------------";
		echo "I will now setup ScamNailer, KAM, DecodeShortURLS and iXhash2"
		echo ""
		echo ""; sleep 3
	cd /var/lib/clamav; wget http://www.mailscanner.eu/scamnailer.ndb
	cd /etc/mail/spamassassin
	wget http://www.peregrinehw.com/downloads/SpamAssassin/contrib/KAM.cf
	wget https://raw.github.com/smfreegard/DecodeShortURLs/master/DecodeShortURLs.cf
	wget https://raw.github.com/smfreegard/DecodeShortURLs/master/DecodeShortURLs.pm
	if [ -f /etc/cron.daily/kam ];
		then
		echo "Hourly Cronjob exists. Skipping."; sleep 3
	else
		cd /etc/cron.daily/; wget $fluxlabsgit/extras/centos/cron/kam; chmod +x *
	fi
	yum install spamassassin-iXhash2 -y
	service spamd reload
	service MailScanner reload
	touch $track/additional_sa
fi
}
# +---------------------------------------------------+
# Additional Clam AV
# +---------------------------------------------------+
f_additional_clam (){
	if [ -f $track/additional_clam ];
		then
			echo "The Additional Clam AV Rules are already installed."
		else
		f_clear
		echo "------------------------------------------------------------------------------";
		echo "A D D I T I O N A L  C L A M  R U L E S";
		echo "------------------------------------------------------------------------------";
		echo "I will now install the unofficial clamav signatures."
		echo "Please not this will put a heavier load on your server."
		echo "Make sure you have sufficient system resources."
		echo "Not recommended for a small VPS!"
		echo ""; sleep 3
		yum install clamav-unofficial-sigs  -y
		/usr/bin/clamav-unofficial-sigs.sh
		touch $track/additional_clam
	fi
}

# +---------------------------------------------------+
# Baruwa Admin
# +---------------------------------------------------+
f_baruwa_admin (){
	if [ -f /usr/sbin/baruwa-admin ] ;
		then
		echo "It looks as though baruwa-admin is already installed."
	else
		f_clear
	cd /usr/sbin
	curl -O $fluxlabsgit/extras/centos/baruwa-admin
	chmod +x baruwa-admin
	f_clear
	echo "You may now use 'baruwa-admin' as a command."
	sleep 5
fi
}

# +---------------------------------------------------+
# Display menus
# +---------------------------------------------------+

menu_main (){
	clear
	echo "------------------------------"
	echo "Welcome to the Baruwa 2.0 Installer for $osver!"
	echo ""
	echo "Please make a choice:"
	echo ""
	echo "a) Install Baruwa 2.0 (Complete Install)"
	echo "b) Install Additional SpamAssassin Rules"
	echo "c) Install Unofficial ClamAV Signatures"
	echo "d) Install Baruwa-Admin"
	echo "e) Cleanup Installer"
	echo " "
	echo "x) Exit"
}

# +---------------------------------------------------+
# Choices
# +---------------------------------------------------+

read_main (){
	local choice
	read -p "Enter Choice: " choice
	case $choice in
		a)  f_directories
			f_requirements
			f_dependencies
			f_python
			f_postgresql
			f_rabbitmq
			f_mailscanner
			f_exim
			f_perl
			f_libmem
			f_configuration
			f_administrator
			f_http
			f_pyzor_razor_dcc
			f_clam
			f_generate_key
			f_cronjobs
			f_permissions
			f_services
			f_finish ;;
		b)  f_additional_sa ;;
		c)  f_additional_clam ;;
		d)  f_baruwa_admin ;;
		e)  f_cleanup ;;
		x) exit 0;;
		*) echo -e "Error \"$choice\" is not an option..." && sleep 2
	esac
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