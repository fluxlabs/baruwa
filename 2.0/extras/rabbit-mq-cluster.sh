#!/bin/bash
# Jeremy McSpadden
# Flux Labs
# Creates Rabbit Cluster

erlang=$(cat /var/lib/rabbitmq/.erlang.cookie | awk '{ print $1 }';)

# Master
function master () {
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
function slave () {
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
rabbitmqctl add_user baruwa sn1ck3r
rabbitmqctl add_vhost $cluster2a
rabbitmqctl set_permissions -p $cluster2a baruwa ".*" ".*" ".*"
rabbitmqctl list_vhosts
rabbitmqctl stop_app
rabbitmqctl join_cluster --disk rabbit@$cluster2a
rabbitmqctl start_app
}

function status () {
	clear 2>/dev/null
	rabbitmqctl status
}

function cluster_status () {
	clear 2>/dev/null
	rabbitmqctl cluster_status
}

function_erlang () {
	get_key=$(cat /var/lib/rabbitmq/.erlang.cookie | awk '{ print $1 }';)
	echo "Your erlang KEY is : $get_key";
	function_show_confirm
}