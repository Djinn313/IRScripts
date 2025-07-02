#!/bin/bash
#IR collection Script
#By Mike Sayegh
#Run this program from the directory it is in ./mike
clear
echo 'This program collects critical volatile and non-volatile data'
read -p 'Do you wish to continue?' c_answer
case $c_answer in
Y|y|yes|YES|Yes) echo '  ';;
N|n|no|NO|No) exit;;
*) echo 'You must answer yes or no';read -p 'Press any key to Exit:'; clear; exit;;
esac

read -p 'Investigators Name: ' name
read -p 'Case Name: ' case_name
read -p 'Date: ' watch_date
read -p 'Time: ' watch_time
comp_date=`date`
location=`pwd`
read -p 'What is the folder name to store the collected data?' collect

if [ -d ./$collect ]
then
	echo 'Writing to $collect'
else
	mkdir $collect
	echo '$collect created'
fi

read -p 'Press Any key to Continue'

echo 'Begin Data Collection'

echo 'System Date and Time'
$location/Tools/date >> $location/$collect/case.dat

echo 'Recording Hostname'
$location/Tools/hostname >> $location/$collect/case.dat

echo 'Who is logged in?'
$location/Tools/who >> $location/$collect/case.dat

echo 'Recording Netstat -ano'
$location/Tools/netstat >> $location/$collect/case.dat

echo 'Recording SS'
$location/Tools/ss >> $location/$collect/ss.dat

echo 'Recording System Messages'
$location/Tools/dmesg >> $location/$collect/dmesg.dat

echo 'Recording ifconfig -a'
ifconfig -a >> $location/$collect/ifconfig-a.dat

echo 'Recording Directory ls / -alhR'
$location/Tools/ls / -alhR >> $location/$collect/directory1.dat 2> $location/$collect/directory1.err

echo 'Copying the etc/passwd file'
$location/Tools/cp /etc/passwd $location/$collect/

echo 'Copying var/log'
$location/Tools/cp -R /var/log $location/$collect/

echo 'Collecting System Variables'
set >> $location/$collect/sys-var.dat
