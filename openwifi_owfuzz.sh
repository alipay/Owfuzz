#!/bin/bash

#if [ $# -ne 2 ]
#  then
#    echo "Please input NIC_name ch_number as input parameter!"
#    exit
#fi

#nic_name=$1
#ch_number=$2
#echo $nic_name
#echo $ch_number

nic_name=sdr0


killall hostapd
killall webfsd

cd ~/openwifi

service network-manager stop
./wgd.sh
#ifconfig sdr0 192.168.13.1
route add default gw 192.168.10.1
service isc-dhcp-server restart

sleep 5

# sudo service network-manager stop
sudo ip link set $nic_name down
sudo iwconfig $nic_name mode monitor
sudo ip link set $nic_name up
#sudo iwconfig $nic_name channel $ch_number
# sudo iwconfig $nic_name modulation 11g
# sudo iwconfig $nic_name rate 6M
ifconfig
iwconfig $nic_name

sleep 1

#cd ~/owfuzz/src

# ap mode
#./owfuzz -i sdr0 -m ap -c 48 -t 28:E7:77:2D:73:67 -b 08:D9:F5:26:FF:C4 -s 08:D9:F5:26:FF:C4 -T 2 -A WPA3 -I 192.168.50.246

# sta mode
#./owfuzz -i sdr0 -m sta -c 48 -t 08:D9:F5:26:FF:C4 -b 08:D9:F5:26:FF:C4 -s 28:E7:77:2D:73:67 -T 2 -A WPA3 -S ttt
