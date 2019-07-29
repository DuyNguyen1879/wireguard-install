#!/bin/bash
####################################
# initial centos 7 firewalld config
####################################
PORTNUM=813

# improve openssh security https://infosec.mozilla.org/guidelines/openssh
cat >> /etc/ssh/sshd_config <<EOF

KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com
EOF

echo "awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv -f /etc/ssh/moduli.tmp /etc/ssh/moduli"
awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.tmp && mv -f /etc/ssh/moduli.tmp /etc/ssh/moduli

if [ "$(grep '#Port' /etc/ssh/sshd_config)" ]; then
  sed -i 's/#Port /Port /g' /etc/ssh/sshd_config
  sed -i 's/Port.*[0-9]$/Port '$PORTNUM'/gI' /etc/ssh/sshd_config   
elif [ "$(grep '^Port' /etc/ssh/sshd_config)" ]; then
  #echo "Port $PORTNUM" >> /etc/ssh/sshd_config
  sed -i 's/Port.*[0-9]$/Port '$PORTNUM'/gI' /etc/ssh/sshd_config   
fi

echo
echo "firewall-cmd --permanent --zone=public --add-port=$PORTNUM/tcp"
firewall-cmd --permanent --zone=public --add-port=$PORTNUM/tcp
echo
echo "firewall-cmd --zone=public --remove-service=ssh --permanent;"
firewall-cmd --zone=public --remove-service=ssh --permanent;
echo
echo "firewall-cmd --reload;"
firewall-cmd --reload;
echo
echo "firewall-cmd --zone=internal --list-ports;"
firewall-cmd --zone=internal --list-ports;
echo
echo "firewall-cmd --zone=internal --list-services;"
firewall-cmd --zone=internal --list-services;
echo
echo "firewall-cmd --zone=public --list-ports;"
firewall-cmd --zone=public --list-ports;
echo
echo "firewall-cmd --zone=public --list-services;"
firewall-cmd --zone=public --list-services;

echo
service sshd restart
echo