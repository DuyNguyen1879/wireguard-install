#!/bin/bash
####################################
# initial centos 7 firewalld config
####################################
PORTNUM=813

sysctl_setup() {
cat > /etc/sysctl.d/101-sysctl.conf <<EOF
# centminmod added
fs.nr_open=12000000
fs.file-max=9000000
net.core.wmem_max=16777216
net.core.rmem_max=16777216
net.ipv4.tcp_rmem=8192 87380 16777216                                          
net.ipv4.tcp_wmem=8192 65536 16777216
net.core.netdev_max_backlog=65536
net.core.somaxconn=65535
net.core.optmem_max=8192
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_keepalive_intvl=30
net.ipv4.tcp_keepalive_probes=3
net.ipv4.tcp_keepalive_time=240
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_sack=1
net.ipv4.tcp_syn_retries=3
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 0
net.ipv4.tcp_max_tw_buckets = 1440000
vm.swappiness=10
vm.min_free_kbytes=65536
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_limit_output_bytes=65536
net.ipv4.tcp_rfc1337=1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.netfilter.nf_conntrack_helper=0
net.nf_conntrack_max = 524288
net.netfilter.nf_conntrack_tcp_timeout_established = 28800
net.netfilter.nf_conntrack_generic_timeout = 60
net.ipv4.tcp_challenge_ack_limit = 999999999
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.unix.max_dgram_qlen = 4096
EOF
sysctl --system
}

resolv_setup() {
  # if detected dhclient-script generated /etc/resolv.conf, then modify it
  if [[ "$(grep -w 'dhclient-script' /etc/resolv.conf)" && -d /etc/dhcp/dhclient.d && ! -f /etc/dhcp/dhclient.d/rotate.sh ]] && [[ ! "$(lsattr /etc/resolv.conf | grep '\-i\-')" ]]; then
cat > "/etc/dhcp/dhclient.d/rotate.sh" <<EOF
rotate_config() {
    echo '# generated by /usr/sbin/dhclient-script' > /etc/resolv.conf
    echo '# generated by centminmod setup' >> /etc/resolv.conf
    echo 'options rotate' >> /etc/resolv.conf
    echo 'options timeout:1' >> /etc/resolv.conf
    echo '#nameserver 208.67.220.220' >> /etc/resolv.conf
    echo '#nameserver 208.67.222.222' >> /etc/resolv.conf
    echo 'nameserver 1.1.1.1' >> /etc/resolv.conf
    echo 'nameserver 1.0.0.1' >> /etc/resolv.conf
    echo '#nameserver 8.8.8.8' >> /etc/resolv.conf
    echo '#nameserver 4.2.2.2' >> /etc/resolv.conf
}

rotate_restore() {
    :
}
EOF
    chmod +x /etc/dhcp/dhclient.d/rotate.sh
cat > "/etc/resolv.conf" <<EFF
# generated by /usr/sbin/dhclient-script
# generated by centminmod setup
options rotate
options timeout:1
#nameserver 208.67.220.220
#nameserver 208.67.222.222
nameserver 1.1.1.1
nameserver 1.0.0.1
#nameserver 8.8.8.8
#nameserver 4.2.2.2
EFF
  elif [[ ! "$(grep -w 'linode' /etc/resolv.conf)" ]] && [[ ! "$(grep -w '1.0.0.1' /etc/resolv.conf)" || ! "$(grep -w '1.1.1.1' /etc/resolv.conf)" || ! "$(grep -w '208.67.222.222' /etc/resolv.conf)" || ! "$(grep -w '8.8.8.8' /etc/resolv.conf)" || ! "$(grep -w '4.2.2.2' /etc/resolv.conf)" || ! "$(grep -w '208.67.220.220' /etc/resolv.conf)" ]] && [[ ! "$(lsattr /etc/resolv.conf | grep '\-i\-')" ]]; then
    # if not linode server based, update /etc/resolv.conf. linode servers don't need updating as they have a more relaible setup
cat > "/etc/resolv.conf" <<EFF
# generated by centminmod setup
options rotate
options timeout:1
#nameserver 208.67.220.220
#nameserver 208.67.222.222
nameserver 1.1.1.1
nameserver 1.0.0.1
#nameserver 8.8.8.8
#nameserver 4.2.2.2
EFF
  elif [[ "$(grep -w 'linode' /etc/resolv.conf)" ]] && [[ ! "$(grep -w '8.8.8.8' /etc/resolv.conf)" ]] && [[ ! "$(grep -w '4.2.2.2' /etc/resolv.conf)" || ! "$(grep -w '208.67.222.222' /etc/resolv.conf)" ]] && [[ ! "$(lsattr /etc/resolv.conf | grep '\-i\-')" ]]; then
    # insert 8.8.8.8 to existing linode /etc/resolv.conf configs
cat > "/etc/resolv-tmp.conf" <<EFF
# generated by centminmod setup
options rotate
options timeout:1
EFF
    cat /etc/resolv.conf >> /etc/resolv-tmp.conf
    sed -i '/search .*/a nameserver 8.8.8.8'  /etc/resolv-tmp.conf
    \cp -a /etc/resolv-tmp.conf /etc/resolv.conf
  fi
  cat /etc/resolv.conf
  rm -rf /etc/resolv-tmp.conf
}

resolv_setup
sysctl_setup

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
echo "firewall-cmd --permanent --zone=public --add-port=1194/udp"
firewall-cmd --permanent --zone=public --add-port=1194/udp
echo
echo "firewall-cmd --permanent --zone=public --add-port=51821/udp"
firewall-cmd --permanent --zone=public --add-port=51821/udp
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