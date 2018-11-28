#!/usr/bin/env bash
# Author: Gilles Biagomba
# Program: ping_sweep.sh
# Description: This script will check for the use of LLMNR, NBT and SMB

# Grabbing the file name from the user
target=$1
if [ $target != "$(ls $PWD | grep $target)" ]; then
    echo "$target does not exist, please enter a valid filename"
    echo "if a file is not specified, default is target.txt"
    echo usage 'tls_sweep.sh targets.txt'
    exit
elif [ -z $target ]; then
    target=$PWD/targets
fi

# declaring variable
App="cipherscan"
declare -a PORTS=(137-139 445 5355)
declare -a Scripts=(llmnr-resolve nbstat vulners smb2-capabilities smb-os-discovery smb-protocols smb-security-mode smb2-security-mode smb-system-info)
declare -a Targets=($(cat $target))
declare -i MAX=$(expr $(wc -l $target | cut -d " " -f 1) - 1)
declare -i POffset
pth=$(pwd)
TodaysDAY=$(date +%m-%d)
TodaysYEAR=$(date +%Y)
wrkpth="$pth/$TodaysYEAR/$TodaysDAY"

# Setting Envrionment
mkdir -p  $wrkpth/Nmap/ $wrkpth/Masscan/ $wrkpth/Reports/

# Setting  parallel stack
echo "How many nmap processess do you want to run?"
echo "Default: 5, Max: 10, Min: 1"
read POffset

if [ "$POffset" -gt "10" ] || [ "$POffset" -lt 1 ] || [ -z "$POffset" ]; then
    echo "Incorrect value, setting offset to default"
    declare -i POffset=5
fi

# Masscan scan
masscan -iL $target -p $(echo ${PORTS[*]} | sed 's/ /,/g') --open-only -oL $wrkpth/Masscan/LLMNR-NBT-SMB

# Nmap Scan
echo "--------------------------------------------------"
echo "Performing the LLMNR, NBT, and SMB scan using Nmap"
echo "--------------------------------------------------"
declare -i MIN=$POffset
for i in $(seq 0 $MAX); do
    nmap -A -R --reason --resolve-all -sS -sU -sV -p $(echo ${PORTS[*]} | sed 's/ /,/g') --script=$(echo ${Scripts[*]} | sed 's/ /,/g') -oA $wrkpth/Nmap/LLMNR-NBT-SMB-$i $(echo ${Targets[$i]}) & 
    if (( $i == $MIN )); then 
        let "MIN+=$POffset"
        wait
    fi
done   
wait

# Combining nmap output
echo "--------------------------------------------------"
echo "Combining Nmap scans"
echo "--------------------------------------------------"
# touch $wrkpth/Reports/LLMNR-NBT-SMB.gnmap $wrkpth/Reports/LLMNR-NBT-SMB.nmap $wrkpth/Reports/LLMNR-NBT-SMB.html
for i in $(seq 0 $MAX); do
    echo $i # troubleshooting code
    xsltproc $wrkpth/Nmap/LLMNR-NBT-SMB-$i.xml -o $wrkpth/Nmap/LLMNR-NBT-SMB-$i.html &
    cat $wrkpth/Nmap/LLMNR-NBT-SMB-$i.gnmap >> $wrkpth/Reports/LLMNR-NBT-SMB.gnmap &
    cat $wrkpth/Nmap/LLMNR-NBT-SMB-$i.nmap >> $wrkpth/Reports/LLMNR-NBT-SMB.nmap &
    if (( $i == $MIN )); then 
        let "MIN+=$POffset"
        wait
        cat $wrkpth/Nmap/LLMNR-NBT-SMB-$i.html >> $wrkpth/Reports/LLMNR-NBT-SMB.html &
    fi
done
