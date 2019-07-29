#!/bin/bash
###########################################################################
# modified by George Liu (centminmod.com)
# https://github.com/centminmod/wireguard-install/tree/centminmod
# https://angristan.xyz/how-to-setup-vpn-server-wireguard-nat-ipv6/
###########################################################################
CLIENT_CONFIGDIR='/etc/wireguard/client-configs'

# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir -p "$CLIENT_CONFIGDIR" > /dev/null 2>&1

if [ "$EUID" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit
fi

if [ "$(systemd-detect-virt)" == "lxc" ]; then
    echo "LXC is not supported (yet)."
    echo "WireGuard can technically run in an LXC container,"
    echo "but the kernel module has to be installed on the host,"
    echo "the container has to be run with some specific parameters"
    echo "and only the tools need to be installed in the container."
    exit
fi

# Check OS version
if [[ -e /etc/debian_version ]]; then
    source /etc/os-release
    OS=$ID # debian or ubuntu
elif [[ -e /etc/fedora-release ]]; then
    OS=fedora
elif [[ -e /etc/centos-release ]]; then
    OS=centos
elif [[ -e /etc/arch-release ]]; then
    OS=arch
else
    echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
    exit 1
fi

unbound() {
  reset=$1
  echo
  echo "setup unbound DNS resolver with DNS-over-TLS & DNSSEC"
  echo 
  if [[ "$OS" = 'centos' ]]; then
    if [ ! -d /etc/unbound/conf.d ]; then
        yum -y install unbound
    fi
  fi
cat > /etc/unbound/conf.d/wireguard.conf <<EOF
server:
    access-control:  0.0.0.0/0       refuse
    access-control:  127.0.0.1       allow
    access-control:  10.66.66.0/24   allow
    private-address: 10.66.66.0/24

    interface: ::1                                            
    interface: 127.0.0.1
    interface: 10.66.66.1

    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-referral-path: yes
    unwanted-reply-threshold: 10000000

    #Have the validator print validation failures to the log.
    val-log-level: 1

    cache-min-ttl: 1800
    cache-max-ttl: 14400
EOF
cat > /etc/unbound/conf.d/wireguard-forward.conf <<EOF
server:                                                                                       
  forward-zone:                                                                               
   name: "."                                                                                  
   forward-ssl-upstream: yes                                                                  
   forward-addr: 1.1.1.1@853#one.one.one.one                                                  
   #forward-addr: 8.8.8.8@853#dns.google                                                       
   #forward-addr: 9.9.9.9@853#dns.quad9.net                                                    
   forward-addr: 1.0.0.1@853#one.one.one.one                                                  
   #forward-addr: 8.8.4.4@853#dns.google                                                       
   #forward-addr: 149.112.112.112@853#dns.quad9.net
EOF
  echo "nameserver 127.0.0.1" > /etc/resolv.conf
  echo
  if [[ "$reset" = 'reset' ]]; then
    echo "systemctl restart unbound"
    systemctl restart unbound
  else
    echo "systemctl start unbound"
    systemctl start unbound
  fi
  echo
  echo "systemctl enable unbound"
  systemctl enable unbound
  echo
  echo "systemctl status unbound"
  systemctl status unbound
  echo
  echo "unbound-control stats"
  unbound-control stats
  echo
  echo "nslookup cloudflare.com localhost"
  nslookup cloudflare.com localhost
  echo
  echo "dig @localhost cloudflare.com +dnssec +multi"
  dig @localhost cloudflare.com +dnssec +multi
  echo
  echo "unbound-host -vDr cloudflare.com"
  unbound-host -vDr cloudflare.com
  echo
  echo "dig +dnssec A www.dnssec.cz | grep ad"
  dig +dnssec A www.dnssec.cz | grep ad
  echo 
}

wg_setup() {
  reset=$1

# Detect public IPv4 address and pre-fill for the user
SERVER_PUB_IPV4=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
read -rp "IPv4 or IPv6 public address: " -e -i "$SERVER_PUB_IPV4" SERVER_PUB_IP

# Detect public interface and pre-fill for the user
SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
read -rp "Public interface: " -e -i "$SERVER_PUB_NIC" SERVER_PUB_NIC

SERVER_WG_NIC="wg0"
read -rp "WireGuard interface name: " -e -i "$SERVER_WG_NIC" SERVER_WG_NIC

SERVER_WG_IPV4="10.66.66.1"
read -rp "Server's WireGuard IPv4 " -e -i "$SERVER_WG_IPV4" SERVER_WG_IPV4

SERVER_WG_IPV6="fd42:42:42::1"
read -rp "Server's WireGuard IPv6 " -e -i "$SERVER_WG_IPV6" SERVER_WG_IPV6

SERVER_PORT=51821
read -rp "Server's WireGuard port " -e -i "$SERVER_PORT" SERVER_PORT

# 1st client

CLIENT_WG_IPV4_1="10.66.66.2"
read -rp "Client 1 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_1" CLIENT_WG_IPV4_1

CLIENT_WG_IPV6_1="fd42:42:42::2"
read -rp "Client 1 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_1" CLIENT_WG_IPV6_1

# 2nd client

CLIENT_WG_IPV4_2="10.66.66.3"
read -rp "Client 2 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_2" CLIENT_WG_IPV4_2

CLIENT_WG_IPV6_2="fd42:42:42::3"
read -rp "Client 2 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_2" CLIENT_WG_IPV6_2

# 3rd client

CLIENT_WG_IPV4_3="10.66.66.4"
read -rp "Client 3 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_3" CLIENT_WG_IPV4_3

CLIENT_WG_IPV6_3="fd42:42:42::4"
read -rp "Client 3 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_3" CLIENT_WG_IPV6_3

# 4th client

CLIENT_WG_IPV4_4="10.66.66.5"
read -rp "Client 4 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_4" CLIENT_WG_IPV4_4

CLIENT_WG_IPV6_4="fd42:42:42::5"
read -rp "Client 4 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_4" CLIENT_WG_IPV6_4

# 5th client

CLIENT_WG_IPV4_5="10.66.66.6"
read -rp "Client 5 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_5" CLIENT_WG_IPV4_5

CLIENT_WG_IPV6_5="fd42:42:42::6"
read -rp "Client 5 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_5" CLIENT_WG_IPV6_5

# 6th client

CLIENT_WG_IPV4_6="10.66.66.7"
read -rp "Client 6 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_6" CLIENT_WG_IPV4_6

CLIENT_WG_IPV6_6="fd42:42:42::7"
read -rp "Client 6 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_6" CLIENT_WG_IPV6_6

# 7th client

CLIENT_WG_IPV4_7="10.66.66.8"
read -rp "Client 7 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_7" CLIENT_WG_IPV4_7

CLIENT_WG_IPV6_7="fd42:42:42::8"
read -rp "Client 7 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_7" CLIENT_WG_IPV6_7

# 8th client

CLIENT_WG_IPV4_8="10.66.66.9"
read -rp "Client 8 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_8" CLIENT_WG_IPV4_8

CLIENT_WG_IPV6_8="fd42:42:42::9"
read -rp "Client 8 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_8" CLIENT_WG_IPV6_8

# 9th client

CLIENT_WG_IPV4_9="10.66.66.10"
read -rp "Client 9 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_9" CLIENT_WG_IPV4_9

CLIENT_WG_IPV6_9="fd42:42:42::10"
read -rp "Client 9 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_9" CLIENT_WG_IPV6_9

# 10th client

CLIENT_WG_IPV4_10="10.66.66.11"
read -rp "Client 10 WireGuard IPv4 " -e -i "$CLIENT_WG_IPV4_10" CLIENT_WG_IPV4_10

CLIENT_WG_IPV6_10="fd42:42:42::11"
read -rp "Client 10 WireGuard IPv6 " -e -i "$CLIENT_WG_IPV6_10" CLIENT_WG_IPV6_10

# Adguard DNS by default
# 176.103.130.130
# Cloudflare
# 1.1.1.1
# Unbound
# 10.66.66.1
CLIENT_DNS1="176.103.130.130"
#CLIENT_DNS1="1.1.1.1"
read -rp "First DNS resolver to use for the client: " -e -i "$CLIENT_DNS1" CLIENT_DNS1

# Adguard DNS by default
# 176.103.130.131
# Cloudflare
# 1.0.0.1
CLIENT_DNS2="176.103.130.131"
#CLIENT_DNS2="1.0.0.1"
read -rp "Second DNS resolver to use for the client: " -e -i "$CLIENT_DNS2" CLIENT_DNS2

# Ask for pre-shared symmetric key
IS_PRE_SYMM="n"
read -rp "Want to use pre-shared symmetric key? [Y/n]: " -e -i "$IS_PRE_SYMM" IS_PRE_SYMM

if [[ $SERVER_PUB_IP =~ .*:.* ]]
then
  echo "IPv6 Detected"
  ENDPOINT="[$SERVER_PUB_IP]:$SERVER_PORT"
else
  echo "IPv4 Detected"
  ENDPOINT="$SERVER_PUB_IP:$SERVER_PORT"
fi

# Install WireGuard tools and module
if [[ "$OS" = 'ubuntu' ]]; then
    add-apt-repository ppa:wireguard/wireguard
    apt-get update
    apt-get install wireguard
elif [[ "$OS" = 'debian' ]]; then
    echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
    printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
    apt update
    apt install wireguard
elif [[ "$OS" = 'fedora' ]]; then
    dnf copr enable jdoss/wireguard
    dnf install wireguard-dkms wireguard-tools
elif [[ "$OS" = 'centos' ]]; then
    curl -sLo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
    if [ ! -f /etc/yum.repos.d/epel.repo ]; then
        yum -y install epel-release
    fi
    if [ ! -f /usr/bin/qrencode ]; then
        yum -y install qrencode
    fi
    if [ ! -f /usr/bin/dig ]; then
        yum -y install bind-utils
    fi
    if [ ! -f /usr/sbin/tcpdump ]; then
      yum -y install tcpdump
    fi
    if [ ! -f /usr/bin/wg ]; then
      yum -y install wireguard-dkms wireguard-tools
    fi
elif [[ "$OS" = 'arch' ]]; then
    pacman -S wireguard-tools
fi

# Generate key pair for the server
SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "$SERVER_PRIV_KEY" | wg pubkey)

# Generate key pair for the server
CLIENT_PRIV_KEY1=$(wg genkey)
CLIENT_PUB_KEY1=$(echo "$CLIENT_PRIV_KEY1" | wg pubkey)

CLIENT_PRIV_KEY2=$(wg genkey)
CLIENT_PUB_KEY2=$(echo "$CLIENT_PRIV_KEY2" | wg pubkey)

CLIENT_PRIV_KEY3=$(wg genkey)
CLIENT_PUB_KEY3=$(echo "$CLIENT_PRIV_KEY3" | wg pubkey)

CLIENT_PRIV_KEY4=$(wg genkey)
CLIENT_PUB_KEY4=$(echo "$CLIENT_PRIV_KEY4" | wg pubkey)

CLIENT_PRIV_KEY5=$(wg genkey)
CLIENT_PUB_KEY5=$(echo "$CLIENT_PRIV_KEY5" | wg pubkey)

CLIENT_PRIV_KEY6=$(wg genkey)
CLIENT_PUB_KEY6=$(echo "$CLIENT_PRIV_KEY6" | wg pubkey)

CLIENT_PRIV_KEY6=$(wg genkey)
CLIENT_PUB_KEY6=$(echo "$CLIENT_PRIV_KEY6" | wg pubkey)

CLIENT_PRIV_KEY7=$(wg genkey)
CLIENT_PUB_KEY7=$(echo "$CLIENT_PRIV_KEY7" | wg pubkey)

CLIENT_PRIV_KEY8=$(wg genkey)
CLIENT_PUB_KEY8=$(echo "$CLIENT_PRIV_KEY8" | wg pubkey)

CLIENT_PRIV_KEY9=$(wg genkey)
CLIENT_PUB_KEY9=$(echo "$CLIENT_PRIV_KEY9" | wg pubkey)

CLIENT_PRIV_KEY10=$(wg genkey)
CLIENT_PUB_KEY10=$(echo "$CLIENT_PRIV_KEY10" | wg pubkey)

# Add server interface
echo "[Interface]
Address = $SERVER_WG_IPV4/24,$SERVER_WG_IPV6/64
ListenPort = $SERVER_PORT
PrivateKey = $SERVER_PRIV_KEY
#PostUp = iptables -A FORWARD -o $SERVER_WG_NIC -j ACCEPT; ip6tables -A FORWARD -o $SERVER_WG_NIC -j ACCEPT; iptables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -t nat -A POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE
#PostDown = iptables -D FORWARD -o $SERVER_WG_NIC -j ACCEPT; ip6tables -D FORWARD -o $SERVER_WG_NIC -j ACCEPT; iptables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE; ip6tables -t nat -D POSTROUTING -o $SERVER_PUB_NIC -j MASQUERADE" > "/etc/wireguard/$SERVER_WG_NIC.conf"

# Add client 1 to 10 as a peer to the server
echo "

[Peer]
PublicKey = $CLIENT_PUB_KEY1
AllowedIPs = $CLIENT_WG_IPV4_1/32,$CLIENT_WG_IPV6_1/128

[Peer]
PublicKey = $CLIENT_PUB_KEY2
AllowedIPs = $CLIENT_WG_IPV4_2/32,$CLIENT_WG_IPV6_2/128

[Peer]
PublicKey = $CLIENT_PUB_KEY3
AllowedIPs = $CLIENT_WG_IPV4_3/32,$CLIENT_WG_IPV6_3/128

[Peer]
PublicKey = $CLIENT_PUB_KEY4
AllowedIPs = $CLIENT_WG_IPV4_4/32,$CLIENT_WG_IPV6_4/128

[Peer]
PublicKey = $CLIENT_PUB_KEY5
AllowedIPs = $CLIENT_WG_IPV4_5/32,$CLIENT_WG_IPV6_5/128

[Peer]
PublicKey = $CLIENT_PUB_KEY6
AllowedIPs = $CLIENT_WG_IPV4_6/32,$CLIENT_WG_IPV6_6/128

[Peer]
PublicKey = $CLIENT_PUB_KEY7
AllowedIPs = $CLIENT_WG_IPV4_7/32,$CLIENT_WG_IPV6_7/128

[Peer]
PublicKey = $CLIENT_PUB_KEY8
AllowedIPs = $CLIENT_WG_IPV4_8/32,$CLIENT_WG_IPV6_8/128

[Peer]
PublicKey = $CLIENT_PUB_KEY9
AllowedIPs = $CLIENT_WG_IPV4_9/32,$CLIENT_WG_IPV6_9/128

[Peer]
PublicKey = $CLIENT_PUB_KEY10
AllowedIPs = $CLIENT_WG_IPV4_10/32,$CLIENT_WG_IPV6_10/128" >> "/etc/wireguard/$SERVER_WG_NIC.conf"

#########################################################################
# 1st client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY1
Address = $CLIENT_WG_IPV4_1/24,$CLIENT_WG_IPV6_1/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_1.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_1.conf"

#########################################################################
# 2nd client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY2
Address = $CLIENT_WG_IPV4_2/24,$CLIENT_WG_IPV6_2/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_2.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_2.conf"

#########################################################################
# 3rd client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY3
Address = $CLIENT_WG_IPV4_3/24,$CLIENT_WG_IPV6_3/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_3.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_3.conf"

#########################################################################
# 4th client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY4
Address = $CLIENT_WG_IPV4_4/24,$CLIENT_WG_IPV6_4/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_4.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_4.conf"

#########################################################################
# 5th client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY5
Address = $CLIENT_WG_IPV4_5/24,$CLIENT_WG_IPV6_5/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_5.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_5.conf"

#########################################################################
# 6th client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY6
Address = $CLIENT_WG_IPV4_6/24,$CLIENT_WG_IPV6_6/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_6.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_6.conf"

#########################################################################
# 7th client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY7
Address = $CLIENT_WG_IPV4_7/24,$CLIENT_WG_IPV6_7/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_7.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_7.conf"

#########################################################################
# 8th client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY8
Address = $CLIENT_WG_IPV4_8/24,$CLIENT_WG_IPV6_8/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_8.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_8.conf"

#########################################################################
# 9th client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY9
Address = $CLIENT_WG_IPV4_9/24,$CLIENT_WG_IPV6_9/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_9.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_9.conf"

#########################################################################
# 10th client
# Create client file with interface
echo "[Interface]
PrivateKey = $CLIENT_PRIV_KEY10
Address = $CLIENT_WG_IPV4_10/24,$CLIENT_WG_IPV6_10/64
DNS = $CLIENT_DNS1,$CLIENT_DNS2" > "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_10.conf"

# Add the server as a peer to the client
echo "

[Peer]
PublicKey = $SERVER_PUB_KEY
Endpoint = $ENDPOINT
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 15" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_10.conf"

# Add pre shared symmetric key to respective files
case "$IS_PRE_SYMM" in
    [yY][eE][sS]|[yY]) 
        CLIENT_SYMM_PRE_KEY=$( wg genpsk )
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "/etc/wireguard/$SERVER_WG_NIC.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_1.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_2.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_3.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_4.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_5.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_6.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_7.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_8.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_9.conf"
        echo "PresharedKey = $CLIENT_SYMM_PRE_KEY" >> "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_10.conf"
        ;;
esac

chmod 600 -R /etc/wireguard/

# Enable routing on the server
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" > /etc/sysctl.d/wg.conf

echo
sysctl --system

echo
if [[ "$reset" = 'reset' ]]; then
  systemctl restart "wg-quick@$SERVER_WG_NIC"
else
  systemctl start "wg-quick@$SERVER_WG_NIC"
fi
echo
systemctl enable "wg-quick@$SERVER_WG_NIC"
echo
systemctl status "wg-quick@$SERVER_WG_NIC"
echo
wg show

echo
echo "----------------------------------"
echo "server config"
echo
cat "/etc/wireguard/$SERVER_WG_NIC.conf"
echo
echo
echo "----------------------------------"
echo "client configs"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_1.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_1.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_1.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_2.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_2.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_2.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_3.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_3.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_3.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_4.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_4.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_4.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_5.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_5.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_5.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_6.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_6.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_6.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_7.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_7.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_7.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_8.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_8.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_8.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_9.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_9.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_9.conf"
echo
echo "----------------------------------"
echo "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_10.conf"
echo
cat "$CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_10.conf"
echo
echo "qrencode -t ansiutf8 < $CLIENT_CONFIGDIR/$SERVER_WG_NIC-client_10.conf"
echo
echo "wg showconf $SERVER_WG_NIC"
wg showconf $SERVER_WG_NIC
echo 
echo "firewalld setup"
echo
echo "firewall-cmd --permanent --add-rich-rule=\"rule family=ipv4 source address=$SERVER_WG_IPV4/24 masquerade\""
firewall-cmd --permanent --add-rich-rule="rule family=ipv4 source address=$SERVER_WG_IPV4/24 masquerade"
echo
echo "firewall-cmd --permanent --add-rich-rule=\"rule family=ipv6 source address=$SERVER_WG_IPV6/64 masquerade\""
firewall-cmd --permanent --add-rich-rule="rule family=ipv6 source address=$SERVER_WG_IPV6/64 masquerade"
echo
echo "firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i $SERVER_WG_NIC -o $SERVER_PUB_NIC -j ACCEPT"
firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i $SERVER_WG_NIC -o $SERVER_PUB_NIC -j ACCEPT
echo
echo "firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -i $SERVER_WG_NIC -o $SERVER_PUB_NIC -j ACCEPT"
firewall-cmd --permanent --direct --add-rule ipv6 filter FORWARD 0 -i $SERVER_WG_NIC -o $SERVER_PUB_NIC -j ACCEPT
echo
echo "firewall-cmd --reload"
firewall-cmd --reload
echo
echo "firewall-cmd --permanent --list-rich-rules"
firewall-cmd --permanent --list-rich-rules
}

case "$1" in
  install )
    unbound
    wg_setup
    ;;
  reset )
    unbound reset
    wg_setup reset
    ;;
  check )
    echo
    echo "tcpdump -i $SERVER_WG_NIC"
    echo
    echo "tcpdump -vv -x -X -s 1500 -i eth0 'port 53'"
    ;;
  * )
    echo
    echo "Usage:"
    echo
    echo "$0 {install|reset}"
    ;;
esac