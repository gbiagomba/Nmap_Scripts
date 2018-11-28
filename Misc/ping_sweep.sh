#!/usr/bin/env bash
# Author: Gilles Biagomba
# Program: ping_sweep.sh
# Description: This script will perform a pingsweep of the target network

# Grabbing the file name from the user
target=$1
if [ $target != "$(ls $PWD | grep $target)" ]; then
    echo "$target does not exist, please enter a valid filename"
    echo "if a file is not specified, default is target.txt"
    echo usage 'tls_sweep.sh targets.txt'
    exit
elif [ -z $target ]; then
    target=$PWD/target.txt
fi

# declaring variable
declare -a Targets=($(cat $target))
declare -i POffset
declare -i MAX=$(expr $(wc -l $target | cut -d " " -f 1) - 1)
pth=$(pwd)
TodaysDAY=$(date +%m-%d)
TodaysYEAR=$(date +%Y)
wrkpth="$pth/$TodaysYEAR/$TodaysDAY"

# Setting Envrionment
mkdir -p  $wrkpth/Nmap/ $wrkpth/Masscan/

# Masscan
echo "--------------------------------------------------"
echo "Performing the Pingsweep scan using Masscan"
echo "--------------------------------------------------"
masscan --ping -iL $target -oL $wrkpth/Masscan/masscan_pingsweep
cat $wrkpth/Masscan/masscan_pingsweep | cut -d " " -f 4 | grep -v masscan |grep -v end | sort | uniq > $wrkpth/live

# Nmap Scan
function Nmap()
{
    echo "--------------------------------------------------"
    echo "Performing the Pingsweep scan using Nmap"
    echo "--------------------------------------------------"
    for i in $(seq 0 $MAX); do
        nmap --append-output --randomize-hosts -R --reason --resolve-all -sP -PE -oA $wrkpth//Nmap/icmpecho $(echo ${Targets[$i]}) &
        nmap --append-output --randomize-hosts -R --reason --resolve-all sP -PP -oA $wrkpth//Nmap/icmptimestamp $(echo ${Targets[$i]}) &
        nmap --append-output --randomize-hosts -R --reason --resolve-all -sP -PM -oA $wrkpth//Nmap/icmpnetmask $(echo ${Targets[$i]}) &
        nmap --append-output --randomize-hosts -R --reason --resolve-all -sP -PS 21,22,23,25,53,80,88,110,111,135,139,443,445,8080 -oA $wrkpth//Nmap/pingsweepTCP $(echo ${Targets[$i]}) &
        nmap --append-output --randomize-hosts -R --reason --resolve-all -sP -PU 53,111,135,137,161,500 -oA $wrkpth//Nmap/pingsweepUDP $(echo ${Targets[$i]}) & 
        wait
    done
}

# Combining nmap output
function Nmap_combined()
{
    echo "--------------------------------------------------"
    echo "Combining Nmap scans"
    echo "--------------------------------------------------"
    for i in $(seq 0 $MAX); do
        xsltproc $wrkpth/Nmap/icmpecho.xml -o $wrkpth/Nmap/icmpecho.html &
        xsltproc $wrkpth/Nmap/icmptimestamp.xml -o $wrkpth/Nmap/icmptimestamp.html &
        xsltproc $wrkpth/Nmap/icmpnetmask.xml -o $wrkpth/Nmap/icmpnetmask.html &
        xsltproc $wrkpth/Nmap/pingsweepTCP.xml -o $wrkpth/Nmap/pingsweepTCP.html &
        xsltproc $wrkpth/Nmap/pingsweepUDP.xml -o $wrkpth/Nmap/pingsweepUDP.html &
        wait
    done
}

# Calling first two functions
Nmap
Nmap_combined

# Generating livehost list
echo "--------------------------------------------------"
echo "Generating livehost list"
echo "--------------------------------------------------"
cat $wrkpth/Nmap/*.nmap | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq >> $wrkpth/live
cat $wrkpth/live | sort | uniq > livehosts
