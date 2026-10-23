#!/bin/bash
# Laboratorio real: firewall de 3 patas con namespaces, reglas exportadas por el simulador y Nmap de verdad.
# Ejecutar como root en Linux (probado en Kali): sudo bash tests/real-lab/lab.sh
D="$(cd "$(dirname "$0")" && pwd)"; O="$D/out"
set -e
for n in fw wan lan dmz; do ip netns del $n 2>/dev/null || true; ip netns add $n; ip -n $n link set lo up; done
mk(){ ip link add $1 type veth peer name $2; ip link set $1 netns fw; ip link set $2 netns $3; ip -n fw link set $1 name $4; ip -n $3 link set $2 name eth0; ip -n fw link set $4 up; ip -n $3 link set eth0 up; }
mk vfw0 vwan wan eth0; mk vfw1 vlan lan eth1; mk vfw2 vdmz dmz eth2
ip -n fw addr add 203.0.113.1/24 dev eth0; ip -n fw addr add 198.51.100.1/24 dev eth0
ip -n fw addr add 192.168.1.1/24 dev eth1; ip -n fw addr add 172.16.0.1/24 dev eth2
ip -n wan addr add 198.51.100.99/24 dev eth0; ip -n wan route add default via 198.51.100.1
ip -n lan addr add 192.168.1.66/24 dev eth0; ip -n lan addr add 192.168.1.50/24 dev eth0; ip -n lan route add default via 192.168.1.1
ip -n dmz addr add 172.16.0.10/24 dev eth0; ip -n dmz addr add 172.16.0.66/24 dev eth0; ip -n dmz route add default via 172.16.0.1
# servicios como en el simulador
ip netns exec dmz python3 "$D/svc.py" t:22 t:80 t:443 u:53 & 
ip netns exec lan python3 "$D/svc.py" t:135 t:445 t:3389 u:137 &
ip netns exec fw python3 "$D/svc.py" t:22 u:53 &
sleep 1
ip netns exec fw sh "$O/rules.sh" >/dev/null
run(){ ns=$1; src=$2; shift 2; ip netns exec $ns nmap -n -Pn --reason --max-retries 1 -S $src -e eth0 "$@" -oX - 2>/dev/null; }
P_TCP=21,22,23,53,80,135,443,445,3389,8080; P_UDP=53,67,123,137,161
{
echo '<scans>'
run wan 198.51.100.99 -sS -p $P_TCP 203.0.113.1
run wan 198.51.100.99 -sA -p $P_TCP 203.0.113.1
run lan 192.168.1.66 -sS -p $P_TCP 192.168.1.1
run lan 192.168.1.66 -sU -p $P_UDP 192.168.1.1
run lan 192.168.1.66 -sS -p $P_TCP 172.16.0.10
run dmz 172.16.0.66 -sS -p $P_TCP 192.168.1.50
run lan 192.168.1.66 -sU -p $P_UDP 172.16.0.10
echo '</scans>'
} > "$O/real.xml"
kill %1 %2 %3 2>/dev/null || true
for n in fw wan lan dmz; do ip netns pids $n | xargs -r kill 2>/dev/null; ip netns del $n; done
echo LAB_OK
