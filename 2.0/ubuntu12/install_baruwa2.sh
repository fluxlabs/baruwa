#!/bin/sh

############
#
# Baruwa 2.0 Installer for Ubuntu 12.10
#
# Author - Jeremy McSpadden
# Contact - jeremy@fluxlabs.net
#
############

# VERSION TRACKING - Internal
Date="1-21-2013"						# Date
VERSION="1.0"                        	# Script Version
ID="Ubuntu"								# Script ID
UBVER="12.10"							# Ubuntu Version
BRVER="2.0"								# Baruwa Version
MSVER="4.84.5"							# MS Config Version
TRACK="/usr/src/baruwa2_tracking"		# Dir for tracking
LOGS="/root/baruwa2_logs"				# Logs Directory

# Be sure we're root
USER=`whoami`
if [ "$USER" = "root" ]; then
    :
else
    echo "You must run this installer as root."
    exit 1
fi

# Check system type
OS=`uname -s`
if [ ${OS} = "Linux" ]; then
    :
else
    echo "Sorry, but this installer does not support the ${OS} platform."
    exit 1
fi

DISTRO=`grep NAME /etc/os-release | head -n 1 | awk -F'=' {'print $2'} | awk -F'\"' {'print $2'}`
if [ ${DISTRO} = "Ubuntu" ]; then
    :
else
    echo "Sorry, but this installer does not support the ${DISTRO} distribution."
    exit 1
fi

RLS=`grep VERSION_ID /etc/os-release | awk -F'=' {'print $2'} | awk -F'\"' {'print $2'}`
if [ ${RLS} = "${UBVER}" ]; then
    :
else
    echo "Sorry, but this installer does not support the ${RLS} release."
    exit 1
fi

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	___                                      ______    ______"
echo "	|  |--.---.-.----.--.--.--.--.--.---.-. |__    |  |      |"
echo "	|  _  |  _  |   _|  |  |  |  |  |  _  | |    __|__|  --  |"
echo "	|_____|___._|__| |_____|________|___._| |______|__|______|"                                      
echo ""
echo "	${ID} ${UBVER} Installer v${VERSION}"
echo ""
echo "------------------------------------------------------------------------------";
echo ""
echo "Welcome to the Baruwa's ${BRVER} Installer. (Unofficial Version)"
echo ""
echo "Before we begin: This installer was written for a minimal install of ${ID} ${UBVER}"
echo "This installer is meant to assist you in installing Baruwa 2.0. You still need to "
echo "know linux basics and have an understanding of how Baruwa 2.0 operates. It is a "
echo "complete re-write from 1.0 branch. Alot of changes were made to the code and how it"
echo "works."
echo ""
echo "Please take the time to review the code that I am using below so you understand what"
echo "it is doing. This script will prompt you for the minimal amount of questions needed "
echo "to get Baruwa 2.0 installed and running. You will need to configure baruwa, your firewall,"
echo "spamassassin rules, greylisting, RBL .. etc on your own."
echo ""
echo "If you are un-sure that you can maintain a Baruwa install, I recommend going with the"
echo "commercial product at http://www.baruwa.com; or the PAAS model at http://www.baruwa.net"
echo ""
echo "This script will also fail if you are running SELINUX on enforced policy."
echo "I recommend you disable it during the install. I have not had time to troubleshoot it."
echo "This script will stop your IPTABLES during install"
echo ""
echo "Please make sure you have added a hosts entry for your hostname of this server"
echo "into /etc/hosts or this script will fail. Please cancel if you have not."
echo ""
echo "Also, any bugs found in Baruwa itself should be reported to"
echo "the mailing list @ http://www.baruwa.org. You can contact me at jeremy@fluxlabs.net"
echo "with any concerns or additions you would like to see/add to this script."
echo ""
echo "------------------------------------------------------------------------------";
echo "DO NOT PRESS ANY KEYS UNTIL ASKED, YOU WILL SKIP PASSWORD REQUESTS."
echo ""
echo -n "Press <enter> to continue"
echo ""
read randomkey

if [ -d ${TRACK} ];
	then
	echo "Tracking Directory Exist. Skipping."
else
	mkdir ${TRACK}
fi

if [ -d ${LOGS} ];
	then
	echo "Loging Directory Exists. Skipping."
else 	
	mkdir ${LOGS}
fi

clear 2>/dev/null

# Start Script

echo "------------------------------------------------------------------------------";
echo "          R E Q U I R E D  P A C K A G E S";
echo "------------------------------------------------------------------------------";
echo "I am now going to pull down some necessary sources."
echo "I will also install necessary Packages."; sleep 3

if [ -f ${TRACK}/deps ];
	then
	echo "Dependencies have already been installed. Skipping."; sleep 3
else
	echo ""
	echo "This process could take a few minutes."; sleep 3
	echo ""
	wget -cq -O - http://apt.baruwa.org/baruwa-apt-keys.gpg | apt-key add - &> /dev/null
	echo "deb http://apt.baruwa.org/ubuntu precise main" >> /etc/apt/sources.list.d/baruwa.list
	apt-get update
	export DEBIAN_FRONTEND='noninteractive'
	apt-get -y remove resolvconf popularity-contest
	apt-get install ntp rabbitmq-server pyzor razor expect unrar-free htop arj zoo nomarch lzop \
	cabextract p7zip rpm unrar-free ripole apparmor-profiles apparmor-utils gcc g++ git subversion \
	libjpeg62-dev libxml2-dev libxslt1-dev cython libpq-dev libfreetype6-dev libldap2-dev \
	libssl-dev swig libcrack2-dev libmemcached-dev libgeoip-dev python-dev libsasl2-dev \
	libmysqlclient-dev python-setuptools postgresql postgresql-plpython sphinxsearch \
	memcached mailscanner apache2 apache2-mpm-worker apache2-utils apache2.2-bin apache2.2-common \
	javascript-common libapache2-mod-wsgi libaprutil1-dbd-sqlite3 libaprutil1-ldap libart-2.0-2 \
	libdbd-mysql-perl libjpeg-turbo8 libjpeg8 libjs-dojo-core libjs-dojo-dijit libjs-dojo-dojox \
	liblcms1 libyaml-0-2 wwwconfig-common libstring-crc32-perl libev-perl libdbd-pg-perl \
	libanyevent-perl python-virtualenv exim4-daemon-heavy libauthen-passphrase-perl \
	libcrypt-blowfish-perl libcommon-sense-perl -y

	touch ${TRACK}/deps

fi
clear 2>/dev/null
# Logging Python
(
echo "------------------------------------------------------------------------------";
echo "          V I R T U A L  P Y T H O N  E N V I R O N M E N T";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3
if [ -f ${TRACK}/virt_python1 ];
	then
echo "This section has already been completed. Skipping."; sleep 3
	else
echo "This process could take a while."; sleep 3
mkdir -p /home/baruwa
cd /home/baruwa
virtualenv --distribute px
source px/bin/activate
export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/requirements.txt
pip install distribute
pip install -U distribute
pip install -r requirements.txt
touch ${TRACK}/virt_python1	
fi 
	
if [ -f ${TRACK}/virt_python2 ];
	then
echo "This section has already been completed. Skipping."; sleep 3
	else
clear 2>/dev/null
echo ""
echo "Now let's patch it up."; sleep 3
echo ""
cd /home/baruwa
curl https://sphinxsearch.googlecode.com/svn/trunk/api/sphinxapi.py -o px/lib/python2.7/site-packages/sphinxapi.py
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/patches/repoze.who-friendly-form.patch
curl -O https://raw.github.com/akissa/baruwa2/master/extras/patches/repoze-who-fix-auth_tkt-tokens.patch
cd px/lib/python2.7/site-packages/repoze/who/plugins/
patch -p3 -i /home/baruwa/repoze.who-friendly-form.patch
patch -p4 -i /home/baruwa/repoze-who-fix-auth_tkt-tokens.patch
pip install python-memcached

cd /home/baruwa
curl -O https://raw.github.com/akissa/baruwa2/master/extras/patches/0002-Disable-SSLv2_method.patch
curl -O http://pypi.python.org/packages/source/M/M2Crypto/M2Crypto-0.21.1.tar.gz
tar xzf M2Crypto-0.21.1.tar.gz
cd M2Crypto-0.21.1/
patch -p1 -i ../0002-Disable-SSLv2_method.patch
python setup.py install

touch ${TRACK}/virt_python2
fi
) 2>&1 | tee ${LOGS}/python_env.log

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          P O S T G R E S Q L  C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";

if [ -f ${TRACK}/postgresql ];
	then
echo "This section has already been completed. Skipping." ; sleep 3
	else
echo "Lets set a password for Postgres."
echo "What would you like this super secret"
echo "password to be?"
echo "Please do not use @ : \ | ' as characters."
echo ""
read -p "Password: " PSQLPASS
echo ""
mv /etc/postgresql/9.1/main/pg_hba.conf /etc/postgresql/9.1/main/pg_hba.conf.orig

cat > /etc/postgresql/9.1/main/pg_hba.conf << 'EOF'
# TYPE  DATABASE    USER        CIDR-ADDRESS          METHOD
local   all         postgres                          trust
host    all         all         127.0.0.1/32          md5
host    all         all         ::1/128               md5
EOF

sed -e "s/^#timezone = \(.*\)$/timezone = 'UTC'/" -i /etc/postgresql/9.1/main/postgresql.conf
# restart the service
service postgresql restart
cd /home/baruwa
su - postgres -c "psql postgres -c \"CREATE ROLE baruwa WITH LOGIN PASSWORD '${PSQLPASS}';\""
su - postgres -c 'createdb -E UTF8 -O baruwa -T template1 baruwa'
su - postgres -c "psql baruwa -c \"CREATE LANGUAGE plpythonu;\""
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/baruwa/config/sql/admin-functions.sql
su - postgres -c 'psql baruwa -f /home/baruwa/admin-functions.sql'
service postgresql restart

touch ${TRACK}/postgresql
fi

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          R A B B I T M Q  C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3

if [ -f ${TRACK}/rabbit ];
	then
echo "This section has already been completed. Skipping."; sleep 3
	else
echo "Lets set a password for RabbitMQ."
echo "What would you like this super secret"
echo "password to be?"
echo "Please do not use @ : \ | ' as characters."
echo ""
read -p "Password: " RABPASS
echo ""
	service rabbitmq-server start
	rabbitmqctl add_user baruwa ${RABPASS}
	rabbitmqctl add_vhost baruwa
	rabbitmqctl set_permissions -p baruwa baruwa ".*" ".*" ".*"
	rabbitmqctl delete_user guest
	touch ${TRACK}/rabbit
fi

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          S P H I N X  C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";
echo ""; sleep 5

if [ -f ${TRACK}/sphinx ];
	then
echo "This section has already been completed. Skipping."; sleep 3
	else
cd /etc/sphinxsearch; mv sphinx.conf sphinx.conf.orig
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/sphinx/sphinx.conf
sed -i -e 's:sql_host =:sql_host = 127.0.0.1:' \
-e 's:sql_user =:sql_user = baruwa:' \
-e 's:sql_pass =:sql_pass = '${PSQLPASS}':' \
-e 's:sql_db =:sql_db = baruwa:' sphinx.conf

sed -i -e 's:START=no:START=yes:' /etc/default/sphinxsearch
sed -i -e 's:/var/log/sphinx:/var/log/sphinxsearch:' \
        -e 's:/var/lib/sphinx:/var/lib/sphinxsearch:' sphinx.conf
service sphinxsearch restart
touch ${TRACK}/sphinx
fi

clear 2>/dev/null
#Logging MailScanner
(
echo "------------------------------------------------------------------------------";
echo "          M A I L S C A N N E R  C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";

if [ -f ${TRACK}/mailscanner ];
	then
echo "This section has already been completed. Skipping."; sleep 3
	else
cd /home/baruwa
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/patches/mailscanner-baruwa-iwantlint.patch
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/patches/mailscanner-baruwa-sql-config.patch
cd /usr/sbin
patch -i /home/baruwa/mailscanner-baruwa-iwantlint.patch
cd /usr/share/MailScanner/MailScanner
patch -p3 -i /home/baruwa/mailscanner-baruwa-sql-config.patch
cd /home/baruwa
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/perl/BS.pm
mv BS.pm /etc/MailScanner/CustomFunctions
cd /etc/MailScanner 
mv MailScanner.conf MailScanner.conf.orig
cd /home/baruwa
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mailscanner/MailScanner.conf
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mailscanner/scan.messages.rules
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mailscanner/nonspam.actions.rules
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mailscanner/filename.rules
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mailscanner/filetype.rules
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mailscanner/filename.rules.allowall.conf
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mailscanner/filetype.rules.allowall.conf
mv *.rules /etc/MailScanner/rules/
mv *.conf /etc/MailScanner/
chmod -R 777 /var/spool/MailScanner/

sed -i 's:use_auto_whitelist 0:#use_auto_whitelist 0:' /etc/mail/spamassassin/mailscanner.cf
sed -i s/"\/etc\/exim"/"\/etc\/exim4"/ /etc/MailScanner/MailScanner.conf
sed -i s/"Run As User = exim"/"Run As User = Debian-exim"/ /etc/MailScanner/MailScanner.conf
sed -i s/"Run As Group = exim"/"Run As Group = Debian-exim"/ /etc/MailScanner/MailScanner.conf
sed -i s/"Quarantine User = exim"/"Quarantine User = Debian-exim"/ /etc/MailScanner/MailScanner.conf
sed -i s/"Incoming Work User = exim"/"Incoming Work User = Debian-exim"/ /etc/MailScanner/MailScanner.conf
sed -i s/"Incoming Work Group = clam"/"Incoming Work Group = clamav"/ /etc/MailScanner/MailScanner.conf
sed -i 's:4.84.3:'${MSVER}':' /etc/MailScanner/MailScanner.conf
sed -i 's:Virus Scanners = none:Virus Scanners = clamd:' /etc/MailScanner/MailScanner.conf
sed -i 's:Custom Functions Dir = /usr/share/MailScanner/MailScanner/CustomFunctions:Custom Functions Dir = /etc/MailScanner/CustomFunctions:' /etc/MailScanner/MailScanner.conf
sed -i 's:/usr/local:/usr/:' /usr/lib/MailScanner/clamav-autoupdate
sed -i 's:DB Password = verysecretpw:DB Password = '${PSQLPASS}':' /etc/MailScanner/MailScanner.conf
sed -i 's:/usr/local:/usr/:' /etc/MailScanner/autoupdate/clamav-autoupdate
sed -i s/"#run_mailscanner"/"run_mailscanner"/ /etc/default/mailscanner
sed -i s/"\/var\/lock\/MailScanner.off"/"\/var\/lock\/MailScanner\/MailScanner.off"/ /etc/init.d/mailscanner
sed -i s/"\/var\/lock\/subsys\/mailscanner"/"\/var\/lock\/MailScanner\/mailscanner"/ /etc/init.d/mailscanner

touch ${TRACK}/mailscanner
fi	
) 2>&1 | tee ${LOGS}/mailscanner.log

clear 2>/dev/null
#Logging Baruwa
(
echo "------------------------------------------------------------------------------";
echo "          B A R U W A  I N S T A L L  P A R T  1";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3

if [ -f ${TRACK}/b1 ];
	then
echo "This section has already been completed. Skipping." ; sleep 3
	else
echo "I am now going to install Baruwa 2.0"
echo ""; sleep 3
cd /home/baruwa
virtualenv --distribute px
source px/bin/activate
export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
easy_install -U distribute
pip install baruwa
touch ${TRACK}/b1
fi

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          B A R U W A  I N S T A L L  P A R T  2";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3

if [ -f ${TRACK}/paster ];
	then
	echo "This section has already been completed. Skipping." ; sleep 3
else
	cd /home/baruwa
	/home/baruwa/px/bin/paster make-config baruwa production.ini
	touch ${TRACK}/paster
fi

if  [ -d /etc/baruwa ];
	then
	echo "Hmm, it looks as though I already have an /etc/baruwa directory. Skipping" ; sleep 3
else      
	mkdir /etc/baruwa
fi
) 2>&1 | tee ${LOGS}/baruwa.log

clear 2>/dev/null

echo "------------------------------------------------------------------------------";
echo "          C E L E R Y D  C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3

if [ -f ${TRACK}/prod ];
	then
echo "This section has already been completed. Skipping." ; sleep 3
	else
mv /home/baruwa/production.ini /etc/baruwa
sed -i -e 's|baruwa:@127.0.0.1:5432/baruwa|baruwa:'${PSQLPASS}'@127.0.0.1:5432/baruwa|' /etc/baruwa/production.ini
sed -i -e 's:broker.password =:broker.password = '${RABPASS}':' \
       -e "s:snowy.local:$(hostname):g" \
       -e 's:^#celery.queues:celery.queues:' /etc/baruwa/production.ini
touch ${TRACK}/prod

fi

if [ -f /etc/sysconfig/baruwa ];
	then
	echo "I see you already have an /etc/default/baruwa file. Skipping." ; sleep 3
else
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

clear 2>/dev/null
#Logging Exim
(
echo "------------------------------------------------------------------------------";
echo "          E X I M  I N S T A L L";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3

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

if [[ -f /etc/exim4/exim.conf && -f ${TRACK}/exim ]]; 
	then
	echo "Exim is already configured. Skipping"; sleep 3
else
cd /etc/exim4; mv /etc/exim4/exim.conf /etc/exim4/exim.conf.orig
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/exim/exim.conf
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/exim/exim_out.conf
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/exim/macros.conf
curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/exim/trusted-configs
mkdir baruwa; cd baruwa
curl -0 https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/exim/baruwa/exim-bcrypt.pl
sed -i s/"\/etc\/exim"/"\/etc\/exim4"/ /etc/exim4/exim_out.conf
sed -i s/"\/etc\/exim"/"\/etc\/exim4"/ /etc/exim4/trusted-configs
sed -i -e 's/spf/#spf = /' /etc/exim4/exim.conf
sed -i -e 's/dbl_/#dbl_/' /etc/exim4/exim_out.conf
sed -i -e 's/verysecretpw/'${PSQLPASS}'/' /etc/exim4/macros.conf
touch ${TRACK}/exim
fi
) 2>&1 | tee ${LOGS}/exim.log

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          P E R L  M O D S  C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3

if [ -f ${TRACK}/perl ];
	then
	echo "Perl modules were previously installed. Skipping."; sleep 3
else
	echo "We are now going to install a few Perl Modules"
	echo "Please press Yes/Enter throughout the questions."
	echo -n "Press <enter> to continue"
	read randomkey

	perl -MCPAN -e  'install Encoding::FixLatin'

	touch ${TRACK}/perl
fi	

clear 2>/dev/null
if [ -a ${TRACK}/b2 ];
	then
	echo "This section has already been completed. Skipping."; sleep 3
else
mv /home/baruwa/px/lib/python2.7/site-packages/baruwa/websetup.py /home/baruwa/px/lib/python2.7/site-packages/baruwa/websetup.py.orig
cd /home/baruwa/px/lib/python2.7/site-packages/baruwa/ 
curl -O https://raw.github.com/fluxlabs/scripting/master/baruwa/cent6/websetup.py
cd /home/baruwa
virtualenv --distribute px
source px/bin/activate
pip install -U distribute
export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
/home/baruwa/px/bin/paster setup-app /etc/baruwa/production.ini

	clear 2>/dev/null
	echo "------------------------------------------------------------------------------";
	echo "          B A R U W A  C O N F I G U R A T I O N";
	echo "------------------------------------------------------------------------------";
	echo "We are now going to add an admin user to Baruwa."
	echo ""
	echo "What would you like your username to be?"
	read -p "Username: " ADMINUSER
	echo ""
	echo "What password would you like to use?"
	echo "This must be a complex password!"
	read -p "Password: " ADMINPASS
	echo ""
	echo "What email would you like to use?"
	read -p "Email: " ADMINEMAIL
	echo ""
/home/baruwa/px/bin/paster create-admin-user -u ${ADMINUSER} -p ${ADMINPASS} -e ${ADMINEMAIL} -t UTC /etc/baruwa/production.ini 
rm -f /home/baruwa/px/lib/python2.7/site-packages/baruwa/websetup.py; mv /home/baruwa/px/lib/python2.7/site-packages/baruwa/websetup.py.orig /home/baruwa/px/lib/python2.7/site-packages/baruwa/websetup.py 
touch ${TRACK}/b2
fi

clear 2>/dev/null
#Logging Apache
(
echo "------------------------------------------------------------------------------";
echo "          A P A C H E  C O N F I G U R A T I O N";
echo "------------------------------------------------------------------------------";
echo ""; sleep 3

if [ -f /etc/apache2/conf.d/baruwa.conf ];
	then
	echo "It looks as though you already have a baruwa.conf file for Apache, Skipping."; sleep 3
else
	curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/config/mod_wsgi/apache.conf
	mv apache.conf /etc/apache2/conf.d/baruwa.conf
fi

) 2>&1 | tee ${LOGS}/apache.log
clear 2>/dev/null


if [ -f ${TRACK}/index ];
	then
	echo "Skipping as I believe you've alreay done this section."; sleep 3
else
indexer --all --rotate
mkdir -p /var/log/baruwa /var/run/baruwa /var/lib/baruwa/data/{cache,sessions,uploads} \
/var/lock/baruwa /etc/MailScanner/baruwa/signatures /etc/MailScanner/baruwa/dkim \
/etc/MailScanner/baruwa/rules /etc/apache2/logs

touch /etc/apache2/logs/baruwa-error_log
touch /etc/apache2/logs/baruwa-access_log
sed -i s/"python2.6"/"python2.7"/g /etc/apache2/conf.d/baruwa.conf
sed -i s/"python2.4"/"python2.7"/ /etc/apache2/conf.d/baruwa.conf

touch ${TRACK}/index
fi

clear 2>/dev/null
##############################################################################
# Setup Cron Jobs                                                            #
##############################################################################

if [ -f /etc/cron.hourly/baruwa-updateindex ];
	then
	echo "This section has already been completed. Skipping."; sleep 3
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
	echo "This section has already been completed. Skipping." ; sleep 3
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
	echo "This section has already been completed. Skipping." ; sleep 3
else
cat > /etc/cron.d/mailscanner << 'EOF'
37 5 * * * /usr/sbin/update_phishing_sites
07 * * * * /usr/sbin/update_bad_phishing_sites
58 23 * * * /usr/sbin/clean.quarantine
42 * * * * /usr/sbin/update_virus_scanners
3,23,43 * * * * /usr/sbin/check_mailscanner
EOF
fi

if [[ -f /etc/cron.d/mailscanner && -f /etc/cron.d/baruwa ]];
	then
clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          A D D I N G  C R O N J O B S";
echo "------------------------------------------------------------------------------";
echo -n "We have created cron entries for you."
echo ""; sleep 3
echo ""
echo "Your Baruwa Cronjobs are setup as:"
echo ""
cat /etc/cron.d/baruwa
echo ""
echo "Your MailScanner Cronjobs are setup as:"
echo ""
cat /etc/cron.d/mailscanner
echo ""
echo "Press <enter> to continue."
read randomkey
else
	echo "It seems I was unable to create your cronjobs. Please look into this"; sleep 10
fi

clear 2>/dev/null
##############################################################################
# Check Services/Permissions                                                 #
##############################################################################
getent group baruwa >/dev/null || groupadd -r baruwa
getent passwd baruwa >/dev/null || \
    useradd -r -g baruwa -d /var/lib/baruwa \
    -s /sbin/nologin -c "Baruwa User" baruwa
chown baruwa.baruwa -R /var/lib/baruwa \
        /var/run/baruwa /var/log/baruwa \
        /var/lock/baruwa /etc/MailScanner/baruwa

if [ -x /etc/init.d/baruwa ];
	then
	echo "Skipping, as I already detect a baruwa init file." ; sleep 3
else
	cd /home/baruwa
	curl -O https://raw.github.com/akissa/baruwa2/2.0.0/extras/scripts/init/debian/baruwa.init
	mv baruwa.init /etc/init.d/baruwa
	chmod +x /etc/init.d/baruwa
fi

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          S E R V I C E  R E S T A R T";
echo "------------------------------------------------------------------------------";
echo "Restarting necessary services for final time."
echo "We are also adding services to startup."
echo ""; sleep 3
chown -R baruwa: /var/log/baruwa
chown -R baruwa: /var/run/baruwa
chown -R www-data: /var/lib/baruwa/data
usermod -G Debian-exim baruwa

service apache2 restart
service memcached restart
service postgresql restart
service rabbitmq-server restart
service baruwa restart
update-rc.d baruwa defaults
service mailscanner restart

clear 2>/dev/null
echo -n "Let's update our Clam Definitions real quick."
echo ""; sleep 3
echo "/var/spool/MailScanner/** rw," >> /etc/apparmor.d/local/usr.sbin.clamd 
echo "/var/spool/MailScanner/incoming/** rw," >> /etc/apparmor.d/local/usr.sbin.clamd 
service apparmor restart &> /dev/null
freshclam
service clamav-daemon restart

##############################################################################
# Finishing Up                                                               #
##############################################################################

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "          F I N I S H I N G  U P";
echo "------------------------------------------------------------------------------";
echo -n ""
echo ""; sleep 3

echo "What email would you like root's email to be sent to?"
echo "ie: you@domain.com"
read ROOTEMAIL
echo -n "root:          ${ROOTEMAIL}" >> /etc/aliases
newaliases
echo ""
echo "What email would you like Administrative Emails sent to?"
echo "ie: you@domain.com"
read ADMEMAIL
sed -i 's:email_to = baruwa@localhost:email_to = '${ADMEMAIL}':' /etc/baruwa/production.ini
echo ""
echo "What email would you like Report Emails sent from?"
echo "ie: reports@domain.com"
read REPEMAIL
sed -i 's:baruwa.reports.sender = baruwa@ms.home.topdog-software.com:baruwa.reports.sender = '${REPEMAIL}':' /etc/baruwa/production.ini
echo ""
echo "What email would you like Error Emails sent from?"
echo "ie: errors@domain.com"
read ERREMAIL
sed -i 's:error_email_from = baruwa@localhost:error_email_from = '${ERREMAIL}':' /etc/baruwa/production.ini
echo ""
echo "What hostname would you like Apache to listen on for Baruwa requests?"
echo "ie: baruwa.domain.com"
read BDOMAIN
sed -i 's:ServerName ms.home.topdog-software.com:ServerName '${BDOMAIN}':' /etc/apache2/conf.d/baruwa.conf

clear 2>/dev/null
##############################################################################
# Display Results                                                            #
##############################################################################

echo "Your Postgres Password is : ${PSQLPASS} "
echo "Your RabbitMQ Password is : ${RABPASS}"
echo ""
echo "Your root emails will be sent to: ${ROOTEMAIL}"
echo "Your Reports will be sent from: ${REPEMAIL}"
echo "Your Errors wil be sent from: ${ERREMAIL}"
echo ""
echo "You can login at http://${BDOMAIN}"
echo "Username: ${ADMINUSER}"
echo "Password: ${ADMINPASS}"
echo ""
echo "Press <enter> to send an email to ${ADMEMAIL} "
read randomkey

##############################################################################
# Email Results                                                              #
##############################################################################

cat >> /tmp/message << EOF
----------------------------------
Thanks for installing Baruwa 2.0

Your Postgres Password is : ${PSQLPASS}
Your Rabbit-MQ Password is : ${RABPASS}

Your root emails will be sent to : ${ROOTEMAIL}
Your Reports will be sent from : ${REPEMAIL}
Your Errors wil be sent from : ${ERREMAIL}

You can now login at http://${BDOMAIN}
Username:  ${ADMINUSER}
Password: ${ADMINPASS}

Please visit http://baruwa.org/docs/2.0/guide/admin/index.html
and follow the guide on how to configure your install.

--
Baruwa 2.0 Installer

Please support the Baruwa project by donating at
http://pledgie.com/campaigns/12056

EOF

/bin/mail -s "Baruwa 2.0 Install for ${HOSTNAME}" < /tmp/message ${ADMEMAIL}
cp /tmp/message ${LOGS}/config.log
rm /tmp/message

clear 2>/dev/null
echo ""
echo "An email has been sent to "${ADMEMAIL}"."
echo ""
echo "Please visit http://baruwa.org/docs/2.0/guide/admin/index.html"
echo "and follow the guide on how to configure your install."
echo ""
echo "Please support the Baruwa project by donating at"
echo "http://pledgie.com/campaigns/12056"
echo ""
echo "Press <enter> to exit"
echo ""
read randomkey
