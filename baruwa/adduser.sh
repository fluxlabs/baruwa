#!/bin/bash

#########################
# Add User to Baruwa 2.0
# Jeremy McSpadden
# jeremy@fluxlabs.net
#
#########################

mv /home/baruwa/px/lib/python2.6/site-packages/baruwa/websetup.py /home/baruwa/px/lib/python2.6/site-packages/baruwa/websetup.py.orig
cd /home/baruwa/px/lib/python2.6/site-packages/baruwa/ 
curl -O https://raw.github.com/fluxlabs/scripting/master/baruwa/cent6/websetup.py
cd /home/baruwa
virtualenv --distribute px
source px/bin/activate
pip install -U distribute
export SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
/home/baruwa/px/bin/paster setup-app /etc/baruwa/production.ini

clear 2>/dev/null
echo "------------------------------------------------------------------------------";
echo "	A D D  B A R U W A  A D M I N  A C C O U N T";
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
rm -f /home/baruwa/px/lib/python2.6/site-packages/baruwa/websetup.py; mv /home/baruwa/px/lib/python2.6/site-packages/baruwa/websetup.py.orig /home/baruwa/px/lib/python2.6/site-packages/baruwa/websetup.py
exit 1