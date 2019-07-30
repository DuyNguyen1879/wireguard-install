#!/bin/bash
###########################################################################
# install Elrepo mainline Linux Kernel For CentOS 7
# written by George Liu (centminmod.com)
###########################################################################
INSTALL_ELREPO='y'

if [[ -d /etc/yum.repos.d && -d /usr/lib/systemd/system && "$INSTALL_ELREPO" = [yY] ]]; then
  uname -r
  rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
  rpm -Uvh https://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
  yum -y remove kernel-tools kernel-tools-libs
  yum -y install yum-utils
  yum-config-manager --enable elrepo-kernel
  yum -y install kernel-ml kernel-ml-devel kernel-ml-tools microcode_ctl --enablerepo=elrepo-kernel
  yum -y versionlock kernel-[0-9]*
  awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg
  grub2-set-default 0
  grub2-mkconfig -o /boot/grub2/grub.cfg
  echo
  echo "cat /etc/default/grub"
  cat /etc/default/grub
  echo
  echo "grub2-editenv list"
  grub2-editenv list
  echo
  echo "sysctl net.ipv4.tcp_available_congestion_control"
  sysctl net.ipv4.tcp_available_congestion_control
  echo
  echo "sysctl -n net.ipv4.tcp_congestion_control"
  sysctl -n net.ipv4.tcp_congestion_control
  echo
  # setup /usr/local/bin/kernel-update script
  echo "wget -q -O /usr/local/bin/kernel-update https://github.com/centminmod/centminmod-digitalocean-marketplace/raw/master/packer/scripts/kernel-update.sh"
  wget -q -O /usr/local/bin/kernel-update https://github.com/centminmod/centminmod-digitalocean-marketplace/raw/master/packer/scripts/kernel-update.sh
  chmod +x /usr/local/bin/kernel-update
  echo
  echo "/usr/local/bin/kernel-update setup"
  echo
  cat /usr/local/bin/kernel-update
fi
if [[ "$INSTALL_BBR" = [yY] ]]; then
  echo 'net.core.default_qdisc=fq' | tee -a /etc/sysctl.conf
  echo 'net.ipv4.tcp_congestion_control=bbr' | tee -a /etc/sysctl.conf
  echo 'net.ipv4.tcp_notsent_lowat=16384' | tee -a /etc/sysctl.conf
  sysctl -p
  echo "sysctl net.ipv4.tcp_available_congestion_control"
  sysctl net.ipv4.tcp_available_congestion_control
  echo
  echo "sysctl -n net.ipv4.tcp_congestion_control"
  sysctl -n net.ipv4.tcp_congestion_control
  echo
  echo "sysctl -n net.core.default_qdisc"
  sysctl -n net.core.default_qdisc
  echo
  echo "sysctl -n net.ipv4.tcp_notsent_lowat"
  sysctl -n net.ipv4.tcp_notsent_lowat
  echo
  echo "lsmod | grep bbr"
  lsmod | grep bbr
fi
echo
echo "Reboot server to complete Kernel Update"
echo "To update Kernel in future run SSH command"
echo
echo "kernel-update"
echo
echo "Then reboot server for update to take effect"