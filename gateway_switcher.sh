#!/bin/bash

testhost1=1.1.1.1
testhost2=8.8.4.4
pings=10

primary_if="eth0"
secondary_if="eth1"
primary_gw="192.168.2.1"
secondary_gw="192.168.4.1"

sudo ip route add $testhost1/32 via $primary_gw
sudo ip route add $testhost2/32 via $primary_gw
sudo ip route change $testhost1/32 via $primary_gw
sudo ip route change $testhost2/32 via $primary_gw
packet_loss11=$(ping -I $primary_if -c $pings $testhost1 | grep "packets transmitted" | awk '{print $6}' | sed 's/%$//')
packet_loss12=$(ping -I $primary_if -c $pings $testhost2 | grep "packets transmitted" | awk '{print $6}' | sed 's/%$//')
echo "Primary channel packet loss to "$testhost1" = "${packet_loss11}"%"
echo "Primary channel packet loss to "$testhost2" = "${packet_loss12}"%"
if [ $packet_loss11 -ge 10 ] && [ $packet_loss12 -ge 10 ];then
echo "Primary channel packet loss is greater or equal 10%";
sudo ip route change $testhost1/32 via $secondary_gw
sudo ip route change $testhost2/32 via $secondary_gw
packet_loss21=$(ping -I $secondary_if -c $pings $testhost1 | grep "packets transmitted" | awk '{print $6}' | sed 's/%$//')
packet_loss22=$(ping -I $secondary_if -c $pings $testhost2 | grep "packets transmitted" | awk '{print $6}' | sed 's/%$//')
echo "Secondary channel packet loss to "$testhost1" = "${packet_loss21}"%"
echo "Secondary channel packet loss to "$testhost1" = "${packet_loss22}"%"
        if [ $packet_loss21 -le 10 ] && [ $packet_loss22 -le 10 ];then
            echo "Secondary channel packet loss is lower 10%. Switching to Secondary channel"
            sudo ip route del default via $primary_gw
            sudo ip route add default via $secondary_gw dev $secondary_if
        else
            if [ $packet_loss21 -ge $packet_loss11 ] && [ $packet_loss22 -ge $packet_loss12 ];then
            echo "Secondary channel packet loss is greater than on Primary channel. Switching to Primary channel"
            sudo ip route del default via $secondary_gw
            sudo ip route add default via $primary_gw dev $primary_if
            else
            echo "Secondary channel packet loss is lower than on Primary channel./n Switching to Secondary channel"
            sudo ip route del default via $primary_gw
            sudo ip route add default via $secondary_gw dev $secondary_if
            fi;
        fi;

else
echo "Primary channel packet loss is lower than 10%./n Switching to Primary channel"
sudo ip route del default via $secondary_gw
sudo ip route add default via $primary_gw dev $primary_if
fi;

packet_loss1=$(ping -I tun0 -c 4 $testhost1 | grep "packets transmitted" | awk '{print $6}' | sed 's/%$//')
packet_loss2=$(ping -I tun0 -c 4 $testhost2 | grep "packets transmitted" | awk '{print $6}' | sed 's/%$//')
echo "OVPN packet loss to "$testhost1" = "${packet_loss1}"%"
echo "OVPN packet loss to "$testhost2" = "${packet_loss2}"%"
if [ $packet_loss1 -gt 25 ] && [ $packet_loss2 -gt 25 ];then
   echo "Tunnel packet loss is greater 25%. Restarting OVPN"
   sudo systemctl restart openvpn@client
fi;

#echo "Primary channel packet loss to "$testhost1" = "$packet_loss11"%"
#echo "Primary channel packet loss to "$testhost2" = "$packet_loss12"%"
#echo "Secondary channel packet loss to "$testhost1" = "$packet_loss21"%"
#echo "Secondary channel packet loss to "$testhost1" = "$packet_loss22"%"