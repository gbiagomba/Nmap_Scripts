#!/usr/bin/env bash
# Author: Gilles Biagomba
# Program: tls_sweep.sh
# Description: Test to see if TLS 1.0 and TLS 1.1 are enables.\n
#              This program is a derivative of my TLS_Check script.\n
#              https://github.com/gbiagomba/WeakSSL

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

# Asking the user for the target files
# echo "What is the target file name (e.g., targets.txt)?"
# read target

# if [ $target != "$(ls $PWD/$target)" ]; then
#     echo file does not exist
#     exit
# fi

# declaring variable
App="cipherscan"
declare -a PORTS=(21 22 25 26 80 110 118 143 156 280 443 445 465 563 567 585 587 591 593 636 695 808 832 853 888 898 981 989 990 992 993 994 995 1000 1090 1098 1099 1129 1159 1194 1311 1360 1392 1433 1434 1521 1527 1583 1621 2077 2078 2083 2087 2096 2099 2222 2376 2381 2484 2638 3071 3131 3132 3269 3306 3351 3389 3424 3478 3702 3872 3873 4443 4444 4445 4446 4489 4643 4843 4848 4903 5223 5432 5500 5556 5671 5672 5800 5900 5989 6080 6432 6619 6679 6697 6701 6703 7000 7002 7004 7080 7091 7092 7101 7102 7103 7105 7107 7109 7201 7202 7306 7307 7403 7444 7501 7777 7799 7802 8000 8009 8080 8081 8082 8083 8089 8090 8140 8191 8243 8333 8443 8444 8531 8834 8880 8888 8889 8899 9001 9002 9091 9095 9096 9097 9098 9099 9100 9443 9998 9999 10000 10109 10443 10571 10911 11214 11215 12043 12443 12975 13722 17169 17777 17778 17779 17790 17791 18091 18092 18366 19812 20561 20911 23051 23642 27724 31100 32100 32976 33001 33300 33840 36210 37549 38121 38131 38760 40001 41443 41581 41971 43778 46160 46393 49203 49223 49693 49926 55130 55443 56182 57572 58630 60306 62657 63002 64779 65298)
declare -a Targets=($(cat $target))
declare -i POffset
declare -i MAX=$(expr $(wc -l $target | cut -d " " -f 1) - 1)
pth=$(pwd)
TodaysDAY=$(date +%m-%d)
TodaysYEAR=$(date +%Y)
wrkpth="$pth/$TodaysYEAR/$TodaysDAY"

# Setting Envrionment
mkdir -p  $wrkpth/Nmap/ $wrkpth/SSLScan $wrkpth/Reports/ $wrkpth/SSLyze

# Setting  parallel stack
echo "How many nmap processess do you want to run?"
echo "Default: 5, Max: 10, Min: 1"
read POffset

if [ "$POffset" -gt "10" ] || [ "$POffset" -lt 1 ] || [ -z "$POffset" ]; then
    echo "Incorrect value, setting offset to default"
    declare -i POffset=5
fi

# Nmap Scan
function Nmap()
{
    echo "--------------------------------------------------"
    echo "Performing the SSL scan using Nmap"
    echo "--------------------------------------------------"
    declare -i MIN=$POffset
    for i in $(seq 0 $MAX); do
        nmap -A -R --reason --resolve-all -sS -sV -p T:$(echo ${PORTS[*]} | sed 's/ /,/g') --script=ssl-enum-ciphers,vulners -oA $wrkpth/Nmap/TLS-$i $(echo ${Targets[$i]}) &  
        if (( $i == $MIN )); then 
            let "MIN+=$POffset"
            wait
        fi
    done
    wait
    # Converting XML files to CSV
    # for i in $(seq 0 40); do
	#     python nmapxmltocsv.py $wrkpth/Nmap/TLS-$i.xml $wrkpth/Nmap/TLS-$i.csv
    # done
}

# Combining nmap output
function Nmap_combined()
{
    echo "--------------------------------------------------"
    echo "Combining Nmap scans"
    echo "--------------------------------------------------"
    declare -i MIN=$POffset
    # touch $wrkpth/Reports/TLS.gnmap $wrkpth/Reports/TLS.nmap $wrkpth/Reports/TLS.html
    for i in $(seq 0 $MAX); do
        echo $i # troubleshooting code
        xsltproc $wrkpth/Nmap/TLS-$i.xml -o $wrkpth/Nmap/TLS-$i.html &
        cat $wrkpth/Nmap/TLS-$i.gnmap >> $wrkpth/Reports/TLS.gnmap &
        cat $wrkpth/Nmap/TLS-$i.nmap >> $wrkpth/Reports/TLS.nmap &
        echo >> $wrkpth/Reports/TLS.nmap &        
        # cat $wrkpth/Reports/TLS-$i.csv >> $wrkpth/Reports/TLS.csv &
        if (( $i == $MIN )); then 
            let "MIN+=$POffset"
            wait
            cat $wrkpth/Nmap/TLS-$i.html >> $wrkpth/Reports/TLS.html &
        fi
    done
}

# Running all the other tools
function tls_validation()
{
    echo "--------------------------------------------------"
    echo "Performing Performing TLS cross validation"
    echo "--------------------------------------------------"
    for IP in $(cat $wrkpth/livehosts); do
        for PORTNUM in ${OpenPORT[*]}; do
            STAT1=$(cat $wrkpth/Reports/TLS.gnmap | grep $IP | grep "Status: Up" -m 1 -o | cut -c 9-10)
            STAT2=$(cat $wrkpth/Reports/TLS.gnmap | grep $IP | grep "$PORTNUM/open" -m 1 -o | grep "open" -o)
            STAT3=$(cat $wrkpth/Reports/TLS.gnmap | grep $IP | grep "$PORTNUM/filtered" -m 1 -o | grep "filtered" -o)
            SVRNAME=$(cat $wrkpth/Reports/TLS.nmap | grep "Nmap scan report for" | grep $IP | cut -d " " -f 5) # nslookup $IP | grep name | cut -d " " -f 3
            if [ -z "$SVRNAME" ] || [ "$SVRNAME" == " " ]; then
                SVRNAME=$(nslookup $IP | grep name | cut -d " " -f 3)
                if [ "$SVRNAME" == "" ] || [ "$SVRNAME" == " " ]; then
                    SVRNAME="Unknown"
                fi
            fi
            if [ "$STAT1" == "Up" ] && [ "$STAT2" == "open" ] || [ "$STAT3" == "filtered" ]; then
                echo "--------------------------------------------------" | tee -a $wrkpth/SSLScan/$IP:$PORTNUM-sslscan_output.txt $wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.txt
                echo "Performing a TLS 1.1 scan of $IP:$PORTNUM ($SVRNAME:$PORTNUM)" | tee -a $wrkpth/SSLScan/$IP:$PORTNUM-sslscan_output.txt $wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.txt
                echo "THis scan was performed on $(date)" | tee -a $wrkpth/SSLScan/$IP:$PORTNUM-sslscan_output.txt $wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.txt
                echo "THis scan was performed by $(whoami)@$(hostname)" | tee -a $wrkpth/SSLScan/$IP:$PORTNUM-sslscan_output.txt $wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.txt
                echo "--------------------------------------------------" | tee -a $wrkpth/SSLScan/$IP:$PORTNUM-sslscan_output.txt $wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.txt
                sslscan --xml=$wrkpth/SSLScan/$IP:$PORTNUM-sslscan_output.xml $IP:$PORTNUM | tee -a $wrkpth/SSLScan/$IP:$PORTNUM-sslscan_output.txt
                sslyze --xml_out=$wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.xml --regular $IP:$PORTNUM | tee -a $wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.txt | aha -t "SSLyze Output"  >> $wrkpth/SSLyze/$IP:$PORTNUM-sslyze_output.html
                # testssl -oa "$wrkpth/TestSSL/TLS" --append --fast --parallel --sneaky --ids-friendly $IP:$PORTNUM | tee -a $wrkpth/TestSSL/$IP:$PORTNUM-TestSSL_output.txt            
            fi
        done
    done 
}

function tls_validation_combined()
{
    # Combining sslscan & sslyze scans
    echo "--------------------------------------------------"
    echo "Combining SSLScan and SSLyze scans"
    echo "--------------------------------------------------"
    cat $wrkpth/SSLyze/*-sslyze_output.txt | aha -t "SSLyze Output"  >> $wrkpth/Reports/sslyze_output.html
    cat $wrkpth/SSLScan/*-sslscan_output.txt | aha -t "SSL Scan Output"  >> $wrkpth/Reports/sslyze_output.html
    echo "Done scanning"
    echo
}

# Calling first two functions
Nmap
Nmap_combined

# Generating livehost list
echo "--------------------------------------------------"
echo "Generating livehost list"
echo "--------------------------------------------------"
cat $wrkpth/Reports/TLS.nmap | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort | uniq > $wrkpth/livehosts

# Grabbing all open ports
echo "--------------------------------------------------"
echo "Grabbing all open ports"
echo "--------------------------------------------------"
OpenPORT=($(cat $wrkpth/Reports/TLS.gnmap | grep Ports | cut -d " " -f 4 | cut -d "/" -f 1 | sort | uniq))

# Calling last two functions
tls_validation
tls_validation_combined