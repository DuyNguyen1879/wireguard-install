# WireGuard installer

This forked branch version is optimised for virgin **CentOS 7 64bit** systems and also adds Unbound DNS resolver with DNS-over-TLS and DNSSEC support for Wireguard and uses CentOS 7 firewalld rich-rules to properlyy configure firewalld usage with Wireguard.

Easily set up a dual-stack WireGuard VPN on a Linux server. See the issues for the WIP.

## Requirements

Supported distributions:

- Ubuntu
- Debian
- Fedora
- Centos
- Arch Linux

## Usage

First on CentOS 7 64bit virgin OS, get the script and make it executable :

```bash
curl -4 -O https://github.com/centminmod/wireguard-install/raw/centminmod/firewalld/centos7-firewalld.sh
chmod +x centos7-firewalld.sh

curl -4 -O https://github.com/centminmod/wireguard-install/raw/centminmod/wireguard-install.sh
chmod +x wireguard-install.sh
```

Then modify `centos7-firewalld.sh` changing `PORTNUM` variable to your desired SSHD port

```
PORTNUM=811
```

Then run `centos7-firewalld.sh` to pre-configure firewalld setup

```sh
./centos7-firewalld.sh
```

Then run `wireguard-install.sh` to install and configure Wireguard:

```sh
./wireguard-install.sh
```

## Unbound

Unbound DNSSEC checks

```
unbound-host -vDr cloudflare.com
cloudflare.com has address 198.41.214.162 (secure)
cloudflare.com has address 198.41.215.162 (secure)
cloudflare.com has IPv6 address 2606:4700::c629:d6a2 (secure)
cloudflare.com has IPv6 address 2606:4700::c629:d7a2 (secure)
cloudflare.com mail is handled by 30 alt2.aspmx.l.google.com. (secure)
cloudflare.com mail is handled by 40 aspmx2.googlemail.com. (secure)
cloudflare.com mail is handled by 50 aspmx3.googlemail.com. (secure)
cloudflare.com mail is handled by 10 aspmx.l.google.com. (secure)
cloudflare.com mail is handled by 20 alt1.aspmx.l.google.com. (secure)
```

```
dig @localhost cloudflare.com +dnssec +multi          

; <<>> DiG 9.9.4-RedHat-9.9.4-74.el7_6.1 <<>> @localhost cloudflare.com +dnssec +multi
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 41828
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 4096
;; QUESTION SECTION:
;cloudflare.com.                IN A

;; ANSWER SECTION:
cloudflare.com.         1800 IN A 198.41.215.162
cloudflare.com.         1800 IN A 198.41.214.162
cloudflare.com.         1800 IN RRSIG A 13 2 300 (
                                20190730170643 20190728150643 34505 cloudflare.com.
                                XJfb78Zh0Ehz7wSul/wpqonzmxZa5WhMldGvn/AaR3f6
                                BLRT1EwBz4S794dkLJFLpT+89++r4t+wW4cokELwiA== )

;; Query time: 137 msec
;; SERVER: ::1#53(::1)
;; WHEN: Mon Jul 29 16:06:50 UTC 2019
;; MSG SIZE  rcvd: 185
```