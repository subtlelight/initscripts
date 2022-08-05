#!/bin/bash

echo
echo "set HOSTNAME"
read -p "HOSTNAME: " HOSTNAME
echo "set USERNAME"
read -p "USERNAME: " USERNAME
echo "$USERNAME"
echo "set PASSWORD"
read -p "PSWD: " PSWD
echo "$PSWD"
echo "SSH Port"
read -p "SSHPort: " SSHPort
echo "Open other TCP Ports?"
read -p "Other open TCP ports, delimit with comma, or set port range with dash [ 8302,1024-65525]: " OpenPorts

## Install packets

apt-get update && apt-get upgrade -y && apt-get install -y iptables nano curl mc htop jq bc cron

## USERADD

useradd -m -U -s /bin/bash -G sudo minadmin
passwd ${USERNAME} << EOD
${PSWD}
${PSWD}
EOD

PSWD=''

cp -r ~/.ssh/ /home/"$USERNAME"/ && chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.ssh/ -R

## SETHOSTNAME

hostnamectl set-hostname "$HOSTNAME" && hostnamectl

ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
echo "$ip"
echo >> /etc/hosts
echo ""$ip"     "$HOSTNAME"" >> /etc/hosts
echo ""$ip6"     "$HOSTNAME"" >> /etc/hosts

## SSH

mv /etc/ssh/sshd_config /etc/ssh/sshd_config.default
touch /etc/ssh/sshd_config

echo " Include /etc/ssh/sshd_config.d/*.conf

Port "$SSHPort"
PermitRootLogin no
ClientAliveInterval 3600
ClientAliveCountMax 1
AllowUsers "$USERNAME"
MaxAuthTries 3
PasswordAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
UsePAM yes
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
AuthorizedKeysFile .ssh/authorized_keys
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server" > /etc/ssh/sshd_config

sshd -t && systemctl restart sshd


## IPTABLES

mkdir /etc/network/if-up.d && touch /etc/network/if-up.d/iptables-rules && chmod +x /etc/network/if-up.d/iptables-rules

echo ' #!/bin/bash
ipt=/sbin/iptables
ip6t=/sbin/ip6tables

sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.all.proxy_arp=0

$ipt --flush -t filter
$ipt --flush -t nat
$ipt --flush -t mangle
$ipt --flush -t raw
$ipt --delete-chain -t filter
$ipt --delete-chain -t nat
$ipt --delete-chain -t mangle
$ipt --delete-chain -t raw
$ip6t --flush -t filter
$ip6t --flush -t nat
$ip6t --flush -t mangle
$ip6t --flush -t raw
$ip6t --delete-chain -t filter
$ip6t --delete-chain -t nat
$ip6t --delete-chain -t mangle
$ip6t --delete-chain -t raw

$ipt -P INPUT DROP
$ipt -P FORWARD DROP
$ipt -P OUTPUT DROP

$ip6t -P INPUT DROP
$ip6t -P FORWARD DROP
$ip6t -P OUTPUT DROP

$ipt -N BAD-PACKETS
$ipt -F BAD-PACKETS
$ipt -A BAD-PACKETS -m state --state INVALID -j DROP
$ipt -A BAD-PACKETS -p tcp -m tcp ! --syn -m conntrack --ctstate NEW -j DROP
$ipt -A BAD-PACKETS -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
$ipt -A BAD-PACKETS -p tcp -m tcp --tcp-option 64 -j DROP
$ipt -A BAD-PACKETS -p tcp -m tcp --tcp-option 128 -j DROP
$ipt -A BAD-PACKETS -m pkttype --pkt-type broadcast -j DROP
$ipt -A BAD-PACKETS -m pkttype --pkt-type multicast -j DROP
$ipt -N IPLOGGING
$ipt -F IPLOGGING
# $ipt -A IPLOGGING -j LOG --log-level info --log-prefix "IPLOGGING: "

$ip6t -N BAD-PACKETS
$ip6t -F BAD-PACKETS
$ip6t -A BAD-PACKETS -m state --state INVALID -j DROP
$ip6t -A BAD-PACKETS -p tcp -m tcp ! --syn -m conntrack --ctstate NEW -j DROP
$ip6t -A BAD-PACKETS -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset
$ip6t -A BAD-PACKETS -p tcp -m tcp --tcp-option 64 -j DROP
$ip6t -A BAD-PACKETS -p tcp -m tcp --tcp-option 128 -j DROP
$ip6t -A BAD-PACKETS -m pkttype --pkt-type broadcast -j DROP
$ip6t -A BAD-PACKETS -m pkttype --pkt-type multicast -j DROP
$ip6t -N IPLOGGING
$ip6t -F IPLOGGING
# $ip6t -A IPLOGGING -j LOG --log-level info --log-prefix "IPLOGGING: "

$ipt -I OUTPUT -d 10.0.0.0/8 -j DROP
$ipt -I OUTPUT -d 172.16.0.0/12 -j DROP
$ipt -I OUTPUT -d 192.168.0.0/16 -j DROP
$ipt -I OUTPUT -d 100.64.0.0/10 -j DROP
$ipt -I OUTPUT -d 198.18.0.0/15 -j DROP
$ipt -I OUTPUT -d 169.254.0.0/16 -j DROP

$ipt -I INPUT 1 -i lo -j ACCEPT
$ipt -I OUTPUT 1 -o lo -j ACCEPT

$ip6t -I INPUT 1 -i lo -j ACCEPT
$ip6t -I OUTPUT 1 -o lo -j ACCEPT

$ipt -A INPUT -p icmp --icmp-type 0 -j ACCEPT
$ipt -A INPUT -p icmp --icmp-type 8 -j ACCEPT
$ipt -A OUTPUT -p icmp -j ACCEPT

$ip6t -A INPUT -p icmpv6 --icmpv6-type 0 -j ACCEPT
$ip6t -A INPUT -p icmpv6 --icmpv6-type 8 -j ACCEPT
$ip6t -A OUTPUT -p icmpv6 -j ACCEPT

$ipt -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$ipt -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

$ip6t -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$ip6t -A OUTPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

# $ipt -A OUTPUT -p tcp -d 62.149.128.4,62.149.132.4,8.8.8.8,8.8.4.4 --dport 53 --sport 1024:65535
# $ipt -A OUTPUT -p udp -d 62.149.128.4,62.149.132.4,8.8.8.8,8.8.4.4 --dport 53 --sport 1024:65535
# $ip6t -A OUTPUT -p tcp -d 2001:4860:4860::8888 --dport 53 --sport 1024:65535
# $ip6t -A OUTPUT -p udp -d 2001:4860:4860::8888 --dport 53 --sport 1024:65535

$ipt -A INPUT -p tcp --dport 8302 -j ACCEPT
$ip6t -A INPUT -p tcp --dport 8302 -j ACCEPT

$ipt -A INPUT -p tcp --dport '"$SSHPort"' -j ACCEPT

$ip6t -A INPUT -p tcp --dport '"$SSHPort"' -j ACCEPT

$ipt -A INPUT -p tcp --dport '"$OpenPorts"' -j ACCEPT

$ip6t -A INPUT -p tcp --dport '"$OpenPorts"' -j ACCEPT ' > /etc/network/if-up.d/iptables-rules


bash /etc/network/if-up.d/iptables-rules

sudo apt-get install -y iptables-persistent netfilter-persistent && iptables-save  > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6


## FAIL2BAN

apt install -y fail2ban && systemctl enable fail2ban && echo '[INCLUDES]

before = paths-debian.conf

[DEFAULT]
ignorecommand =
bantime  = 10m
findtime  = 10m
maxretry = 5
maxmatches = %(maxretry)s
backend = systemd
usedns = warn
logencoding = auto
enabled = false
mode = normal
filter = %(__name__)s[mode=%(mode)s]
destemail = root@localhost
sender = root@<fq-hostname>
mta = sendmail
protocol = tcp
chain = <known/chain>
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
banaction = iptables-multiport
banaction_allports = iptables-allports
action_ = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mw = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
            %(mta)s-whois[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mwl = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             %(mta)s-whois-lines[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]
action_xarf = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             xarf-login-attack[service=%(__name__)s, sender="%(sender)s", logpath="%(logpath)s", port="%(port)s"]
action_cf_mwl = cloudflare[cfuser="%(cfemail)s", cftoken="%(cfapikey)s"]
                %(mta)s-whois-lines[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]
action_blocklist_de  = blocklist_de[email="%(sender)s", service=%(filter)s, apikey="%(blocklist_de_apikey)s", agent="%(fail2ban_agent)s"]
action_badips = badips.py[category="%(__name__)s", banaction="%(banaction)s", agent="%(fail2ban_agent)s"]
action_badips_report = badips[category="%(__name__)s", agent="%(fail2ban_agent)s"]
action_abuseipdb = abuseipdb
action = %(action_)s 

[sshd]

#mode   = normal
enabled = true
port    = '"$SSHPort"'
logpath = %(sshd_log)s
backend = %(sshd_backend)s ' >> /etc/fail2ban/jail.local
systemctl restart fail2ban

echo
echo
echo
echo
## SHOW RESULTS
hostnamectl && echo && lslogins -u && echo && iptables -vnL && systemctl status fail2ban && systemctl status sshd
