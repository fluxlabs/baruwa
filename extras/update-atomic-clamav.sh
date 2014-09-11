#!/bin/bash
# Atomic Clamav Rules for Centos/Baruwa Installer
# Jeremy McSpadden
# Flux Labs
# jeremy at fluxlabs dot net
# 01/26/14
#
# You must have a paid subscription for this to work.
# You can sign-up for a trial at https://www.atomicorp.com/amember/cart/index/product/id/22/c/
# For a subscription, sign up at https://www.atomicorp.com/amember/cart/index/product/id/29/c/
#
# INSTALL GUIDE
# cd /etc/cron.daily; wget https://raw.github.com/fluxlabs/baruwa/master/2.0/extras/update-atomic-clamav.sh
# Just edit your username and password
#

USER=username
PASS=password

# ==== NO NEED TO EDIT BELOW ===

cd /usr/src
wget --user=${USER} --password=${PASS} https://www.atomicorp.com/channels/rules/subscription/VERSION
CLM=$(grep CLAMAV VERSION | awk -F = '{print $2}')

cd /var/lib/clamav; rm -rf ASL*
cd /tmp; wget --user=${USER} --password=${PASS} http://www.atomicorp.com/channels/rules/subscription/clamav-${CLM}.tar.gz
tar zxvf clamav-*; mv clamav/* /var/lib/clamav/.
cd /var/lib/clamav; chmod og+r ASL*
rm -rf /tmp/clamav*; chown clamav:
/etc/init.d/clamd restart

rm -f /usr/src/VERSION