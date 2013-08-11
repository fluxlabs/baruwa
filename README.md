Installers for Baruwa 2.0.1
=========

-
These installers assume that you have added your hostname to hosts.conf.
Example : 55.57.18.3 mx01.domain.com mx01

You must have FQDN and Shortname in your hosts file.

Your hostname must match the domain you choose in this script.

If you would like an automated install edit the script and fill in the fields to match your setup.

Set 1 to Use the autocomplete.

useauto=0
CENT OS 6.4
=========
curl -O https://raw.github.com/fluxlabs/baruwa/master/2.0/cent6/install.sh

It is highly recommended to disable SELinux during this installer.

sed -i -e 's/SELINUX=enforcing/SELINUX=disabled/' /etc/selinux/config

Ubuntu 12.04 (BETA)
=========
curl -O https://raw.github.com/fluxlabs/baruwa/master/2.0/ubuntu12/install.sh




