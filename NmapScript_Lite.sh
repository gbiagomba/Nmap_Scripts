#!/usr/bin/env sh
# Author: Gilles Biagomba
# Program: NmapScrip_lite.sh
# Description: This script designed to perform a port knock scan of a target network.\n
#              It checks the top 200 most commonly used TCP/UDP ports using masscan.\n
#              Then it performs various ICMP scans using nmap followed with a targeted scan\n
#              Using the ports it found during the initial massscan scan we performed earlier.\n
#              Last step is to perform some firewall evation scanning.\n
#              Side-note: You shouldd note this is the heavyweigh version,\n
#              yes there is a heavyweigh (i.e., full) version available!\n

# Grabbing the file name from the user
target=$1
if [ $target != "$(ls $PWD | grep $target)" ]; then
    echo "$target does not exist, please enter a valid filename"
    echo "if a file is not specified, default is 'targets'"
    echo usage 'NmapScrip_Lite.sh targets.txt'
    exit
elif [ -z $target ]; then
    target=$PWD/targets
fi

# Setting up work envrionment
mkdir -p fw_evade pingsweep masscan report

# Variables - Set these
declare -a PORTS=(7 9 13 17 19 37 49 53 80 88 106 111 113 119 120 123 135 139 158 177 179 199 389 427 443 445 465 497 500 518 520 548 554 587 593 623 626 631 646 873 990 993 995 1110 1433 1701 1720 1723 1755 1900 2000 2049 2121 2717 3000 3128 3283 3306 3389 3456 3703 3986 4444 4500 4899 5000 5009 5051 5060 5101 5190 5353 5357 5432 5631 5632 5666 5800 5900 6646 7000 7002 7004 7070 8000 8443 8888 9100 9200 10000 17185 20031 30718 31337 32768 32771 32815 33281 49156 49188 65024 1022-1023 1025-1029 1025-1030 110-111 135-139 143-144 1433-1434 161-162 1645-1646 1718-1719 1812-1813 2000-2001 2048-2049 21-23 2222-2223 25-26 32768-32769 443-445 49152-49154 49152-49157 49181-49182 49185-49186 49190-49194 49200-49201 513-515 514-515 543-544 6000-6001 67-69 79-81 8008-8009 8080-8081 996-999 9999-10000)
pth=$(pwd)

# ---------------------------------
# Ping Sweep with Masscan and Nmap
# ---------------------------------

# Masscan - Pingsweep
masscan --ping -iL $target -oL $pth/masscan/masscan_pingsweep
cat $pth/Masscan/masscan_pingsweep | cut -d " " -f 4 | grep -v masscan |grep -v end | sort | uniq > $pth/live

# Nmap - Pingsweep using ICMP echo, netmask, timestamp
echo
echo "Pingsweep using ICMP echo, netmask, timestamp"
nmap -PE -PM -PP -R -sP -iL $target -oA $pth/Nmap/pingsweep
cat $pth/icmpecho/pingsweep.gnmap | grep Up | cut -d ' ' -f 2 > $pth/live
xsltproc $pth/icmpecho/pingsweep.xml -o report/pingsweep.html

# Systems that respond to ping (finding)
echo
echo "Sorting what systems responded to our previous array of pingsweeps"
cat $pth/live | sort | uniq > $pth/livehosts

# ------------------------------------
# Port knocking using Masscan and Nmap
# ------------------------------------

# Masscan - Checking the top 100 TCP/UDP ports used
echo
echo "Masscan - Checking the top 100 TCP/UDP ports used"
masscan -iL $pth/livehosts -p $(echo ${PORTS[*]} | sed 's/ /,/g') --open-only -oL $pth/masscan/masscan_output
OpenPORT=($(cat $pth/masscan/masscan_output | cut -d " " -f 3 | grep -v masscan | sort | uniq))

# Nmap - Checking the top 100 TCP/UDP Ports used
echo
echo "Stealth network mapping scan"
nmap -A -p $(echo ${OpenPORT[*]} | sed 's/ /,/g') -Pn -R  --reason --resolve-all -sS -sU -sV -T4 -iL $pth/livehosts -oA Final

# Nmap - Firewall evasion
echo
echo "Stealth network mapping scan with Firewall evasion techniques"
# nmap -D RND:10 --badsum --data-length 24 --mtu 24 --spoof-mac Dell --randomize-hosts -A -p $(echo ${OpenPORT[*]} | sed 's/ /,/g') -Pn -R -sS -sU -sV -iL $pth/livehosts --script=vulners -oA $pth/fw_evade/FW_Evade
nmap -f -mtu 24 --randomize-hosts --reason --resolve-all --spoof-mac Dell -T2 -A -p $(echo ${OpenPORT[*]} | sed 's/ /,/g') -Pn -R -sS -sU -sV --script=vulners -iL $pth/livehosts -oA $pth/fw_evade/FW_Evade
nmap --append-output -D RND:10 --badsum --data-length 24 --randomize-hosts -reason --resolve-all -T2 -A -p $(echo ${OpenPORT[*]} | sed 's/ /,/g') -Pn -R -sS -sU -sV --script=vulners -iL $pth/livehosts -oA $pth/fw_evade/FW_Evade
xsltproc $pth/fw_evade/FW_Evade.xml -o $pth/report/FW_Evade.html

# Empty file cleanup
find $pth -size 0c -type f -exec rm -rf {} \;

# De-initializing viarables
unset pth
unset OpenPORT
unset PORTS
unset target
set -u
