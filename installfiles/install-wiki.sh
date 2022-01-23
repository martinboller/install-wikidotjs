#! /bin/bash

#############################################################################
#                                                                           #
# Author:       Martin Boller                                               #
#                                                                           #
# Email:        martin@bollers.dk                                           #
# Last Update:  2022-01-11                                                  #
# Version:      1.10                                                        #
#                                                                           #
# Changes:      Initial Version (1.00)                                      #
#                                                                           #
# Info:         Installing Wiki.js on Debian 11                            #
#                                                                           #
# Instruction:  Run this script as root on a fully updated                  #
#               Debian 10 (Buster) or Debian 11 (Bullseye)                  #
#                                                                           #
#############################################################################


install_prerequisites() {
    /usr/bin/logger 'install_prerequisites' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - install_prerequisites"
    echo -e "\e[1;36m ... installing Prerequisite packages\e[0m";
    tzone=$(cat /etc/timezone)
    export DEBIAN_FRONTEND=noninteractive;
    # Install prerequisites
    #echo -e "\e[1;36m ... adding PHP repository.\e[0m"
    #apt-get -qq -y install apt-transport-https lsb-release ca-certificates > /dev/null 2>&1
    #wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg > /dev/null 2>&1
    #echo "deb https://packages.sury.org/php/ $codename main" > /etc/apt/sources.list.d/php.list

    echo -e "\e[1;36m ... updating all packages\e[0m";
    apt-get -qq update > /dev/null 2>&1;
    # Install some basic tools on a Debian net install
    /usr/bin/logger '..Install some basic tools on a Debian net install' -t 'wikidotjs-2022-01-23';

    echo -e "\e[1;36m ... installing packages missing from Debian net-install\e[0m";
    apt-get -qq -y install --fix-policy > /dev/null 2>&1;
    apt-get -qq -y install adduser wget whois unzip curl git gnupg2 software-properties-common dnsutils python3 python3-pip > /dev/null 2>&1;

    echo -e "\e[1;36m ... installing PostgreSQL\e[0m" 
    apt-get -qq -y install postgresql-contrib postgresql postgresql-server-dev-all > /dev/null 2>&1

    echo -e "\e[1;36m ... installing nodejs\e[0m" 
    apt-get -qq -y install nodejs
    apt-get -qq -y install libpng-dev libjpeg-dev libwebp-dev libgd2-xpm-dev* > /dev/null 2>&1
    # Install other preferences and clean up APT

    echo -e "\e[1;36m ... installing some preferences on Debian and cleaning up apt\e[0m";
    /usr/bin/logger '....installing some preferences on Debian and cleaning up apt' -t 'wikidotjs-2022-01-23';
    apt-get -qq -y install bash-completion > /dev/null 2>&1;
    # Install SUDO
    apt-get -qq -y install sudo > /dev/null 2>&1;
    # A little apt 
    apt-get -qq -y install --fix-missing > /dev/null 2>&1;
    apt-get -qq update > /dev/null 2>&1;
    apt-get -qq -y full-upgrade > /dev/null 2>&1;
    apt-get -qq -y autoremove --purge > /dev/null 2>&1;
    apt-get -qq -y autoclean > /dev/null 2>&1;
    apt-get -qq -y clean > /dev/null 2>&1;
    # Python pip packages
    echo -e "\e[1;36m ... installing python3-pip\e[0m";
    apt-get -qq -y python3-pip > /dev/null 2>&1;
    python3 -m pip install --upgrade pip > /dev/null 2>&1;
    echo -e "\e[1;32m - install_prerequisites finished"
    /usr/bin/logger 'install_prerequisites finished' -t 'wikidotjs-2022-01-23';
}

generate_certificates() {
    /usr/bin/logger 'generate_certificates()' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - generate_certificates"
    mkdir -p $NGINX_CERTS_DIR > /dev/null 2>&1;

    echo -e "\e[1;36m ... generating openssl.cnf file\e[0m";
    cat << __EOF__ > ./openssl.cnf
## Request for $fqdn
[ req ]
default_bits = 2048
default_md = sha256
prompt = no
encrypt_key = no
distinguished_name = dn
req_extensions = req_ext

[ dn ]
countryName         = $ISOCOUNTRY
stateOrProvinceName = $PROVINCE
localityName        = $LOCALITY
organizationName    = $ORGNAME
CN = $fqdn

[ req_ext ]
subjectAltName = $ALTNAMES
__EOF__
    sync;
    # generate Certificate Signing Request to send to corp PKI
    echo -e "\e[1;36m ... generating csr and private key\e[0m";
    openssl req -new -config openssl.cnf -keyout $NGINX_CERTS_DIR/$fqdn.key -out $NGINX_CERTS_DIR/$fqdn.csr > /dev/null 2>&1
    # generate self-signed certificate (remove when CSR can be sent to Corp PKI)
    echo -e "\e[1;36m ... generating self signed certificate\e[0m";
    openssl x509 -in $NGINX_CERTS_DIR/$fqdn.csr -out $NGINX_CERTS_DIR/$fqdn.crt -req -signkey $NGINX_CERTS_DIR/$fqdn.key -days 365 > /dev/null 2>&1
    chmod 600 $NGINX_CERTS_DIR/$fqdn.key > /dev/null 2>&1
    echo -e "\e[1;32m - generate_certificates finished"
    /usr/bin/logger 'generate_certificates() finished' -t 'wikidotjs-2022-01-23';
}

letsencrypt_certificates() {
    /usr/bin/logger 'letsencrypt_certificates()' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - letsencrypt_certificates()"

     echo -e "\e[1;36m ... installing certbot\e[0m";
    apt-get -y -qq install certbot python3-certbot-NGINX > /dev/null 2>&1
    sync;

    # Start certbot'ing
    echo -e "\e[1;36m ... running certbot\e[0m";
    certbot run -n --agree-tos --NGINX -m $mailaddress --domains $fqdn

    echo -e "\e[1;36m ... creating cron job for automatic renewal of certificates\e[0m";
        cat << __EOF__ > /etc/cron.weekly/certbot
#!/bin/sh
/usr/bin/certbot renew
__EOF__
    chmod 755 /etc/cron.weekly/certbot > /dev/null 2>&1
    echo -e "\e[1;32m - letsencrypt_certificates() finished"
    /usr/bin/logger 'letsencrypt_certificates() finished' -t 'wikidotjs-2022-01-23';
}

prepare_nix() {
    /usr/bin/logger 'prepare_nix()' -t 'gse-21.4';
    echo -e "\e[1;32m - prepare_nix"

    echo -e "\e[1;36m ... creating some permanent variables for Wiki.js\e[0m";    

    echo -e "\e[1;36m ... generating motd file\e[0m";    
    # Configure MOTD
    BUILDDATE=$(date +%Y-%m-%d)
    cat << __EOF__ >> /etc/motd
           
*********************************************       
*                 _ _    _   _              *
*                (_) |  (_) (_)             *
*       __      ___| | ___   _ ___          *
*       \ \ /\ / / | |/ / | | / __|         *
*        \ V  V /| |   <| |_| \__ \         *
*         \_/\_/ |_|_|\_\_(_) |___/         *
*                          _/ |             *
*                         |__/              *
********************||***********************
             (\__/) ||
             (•ㅅ•) ||
            /  　  づ

        Automated install v  1.10
              2022-01-23

__EOF__

    echo -e "\e[1;36m ... configuring motd display\e[0m";
    # do not show motd twice
    sed -ie 's/session    optional     pam_motd.so  motd=\/etc\/motd/#session    optional     pam_motd.so  motd=\/etc\/motd/' /etc/pam.d/sshd > /dev/null 2>&1
    sync;
    echo -e "\e[1;32m - prepare_nix() finished"
    /usr/bin/logger 'prepare_nix() finished' -t 'wikidotjs-2022-01-23';
}

configure_iptables() {
    /usr/bin/logger 'configure_iptables() started' -t 'bSIEM Step2';
    echo -e "\e[32m - configure_iptables()\e[0m";

    echo -e "\e[36m ... creating iptables rules file for IPv4\e[0m";
    cat << __EOF__  >> /etc/network/iptables.rules
##
## Ruleset for wikidotjs Server
##
## IPTABLES Ruleset Author: Martin Boller 2021-11-11 v1

*filter
## Dropping anything not explicitly allowed
##
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOG_DROPS - [0:0]

## DROP IP fragments
-A INPUT -f -j LOG_DROPS
-A INPUT -m ttl --ttl-lt 4 -j LOG_DROPS

## DROP bad TCP/UDP combinations
-A INPUT -p tcp --dport 0 -j LOG_DROPS
-A INPUT -p udp --dport 0 -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROPS

## Allow everything on loopback
-A INPUT -i lo -j ACCEPT

## SSH, DNS, WHOIS, DHCP ICMP - Add anything else here needed for ntp, monitoring, dhcp, icmp, updates, and ssh
##
## SSH
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
## HTTP(S)
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
## NTP
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
## ICMP
-A INPUT -p icmp -j ACCEPT
## Already established sessions
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

## Logging
-A INPUT -j LOG_DROPS
## get rid of broadcast noise
-A LOG_DROPS -d 255.255.255.255 -j DROP
# Drop Broadcast to internal networks
-A LOG_DROPS -m pkttype --pkt-type broadcast -d 192.168.0.0/16 -j DROP
-A LOG_DROPS -p ip -m limit --limit 60/sec -j --log-prefix "iptables:" --log-level 7
-A LOG_DROPS -j DROP

## Commit everything
COMMIT
__EOF__

    echo -e "\e[36m ... creating iptables rules file for IPv6\e[0m";
# ipv6 rules
    cat << __EOF__  >> /etc/network/ip6tables.rules
##
## Ruleset for spiderfoot Server
##
## IP6TABLES Ruleset Author: Martin Boller 2021-11-11 v1

*filter
## Dropping anything not explicitly allowed
##
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOG_DROPS - [0:0]

## DROP bad TCP/UDP combinations
-A INPUT -p tcp --dport 0 -j LOG_DROPS
-A INPUT -p udp --dport 0 -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL NONE -j LOG_DROPS
-A INPUT -p tcp --tcp-flags ALL ALL -j LOG_DROPS

## Allow everything on loopback
-A INPUT -i lo -j ACCEPT

## Allow access to port 5001
-A OUTPUT -p tcp -m tcp --dport 5001 -j ACCEPT
## SSH, DNS, WHOIS, DHCP ICMP - Add anything else here needed for ntp, monitoring, dhcp, icmp, updates, and ssh
## SSH
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
## HTTP(S)
-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
## NTP
-A INPUT -p udp -m udp --dport 123 -j ACCEPT
## ICMP
-A INPUT -p icmp -j ACCEPT
## Already established sessions
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

## Logging
-A INPUT -j LOG_DROPS
-A LOG_DROPS -p ip -m limit --limit 60/sec -j --log-prefix "iptables:" --log-level 7
-A LOG_DROPS -j DROP

## Commit everything
COMMIT
__EOF__

    # Configure separate file for iptables logging
    echo -e "\e[36m ... configuring separate file for iptables\e[0m";
    cat << __EOF__  >> /etc/rsyslog.d/30-iptables-syslog.conf
:msg,contains,"iptables:" /var/log/iptables.log
& stop
__EOF__
    sync;
    systemctl restart rsyslog.service> /dev/null 2>&1;

    # Configure daily logrotation (forward this to mgmt)
    echo -e "\e[36m ... configuring daily logrotation for iptables log\e[0m";
    cat << __EOF__  >> /etc/logrotate.d/iptables
/var/log/iptables.{
  rotate 5
  daily
  compress
  create 640 root root
  notifempty
  postrotate
    /usr/lib/rsyslog/rsyslog-rotate
  endscript
}
__EOF__

    # Apply iptables at boot
    echo -e "\e[36m ... creating if-up script to apply iptables rules at every startup\e[0m";
    echo -e "\e[36m-Script applying iptables rules\e[0m";
    cat << __EOF__  >> /etc/network/if-up.d/firewallrules
#! /bin/bash
iptables-restore < /etc/network/iptables.rules
ip6tables-restore < /etc/network/ip6tables.rules
exit 0
__EOF__
    sync;
    ## make the script executable
    chmod +x /etc/network/if-up.d/firewallrules > /dev/null 2>&1;
    # Apply firewall rules for the first time
    #/etc/network/if-up.d/firewallrules;
    /usr/bin/logger 'configure_iptables() done' -t 'Firewall setup';
}

check_services() {
    /usr/bin/logger 'check_services' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - check_services()"
    # Check status of critical services
    # NGINX and postgresql after restarting them
    
    echo -e "\e[1;36m ... restarting postgresql\e[0m";
    systemctl restart postgresql.service  > /dev/null 2>&1
    
    echo -e "\e[1;36m ... restarting NGINX Web Server\e[0m";
    systemctl restart nginx.service  > /dev/null 2>&1
    systemctl restart wikidotjs.service  > /dev/null 2>&1
    echo -e "\e[1;32m-----------------------------------------------------------------\e[0m";
    
    echo -e "\e[1;32m - Checking core daemons for Wiki.js......\e[0m";
    if systemctl is-active --quiet nginx.service;
        then
            echo -e "\e[1;32m ... NGINX webserver started successfully";
            /usr/bin/logger 'NGINX webserver started successfully' -t 'wikidotjs-2022-01-23';
        else
            echo -e "\e[1;31m ... NGINX webserver FAILED!\e[0m";
            /usr/bin/logger 'NGINX webserver FAILED' -t 'wikidotjs-2022-01-23';
    fi
    # postgresql.service
    if systemctl is-active --quiet postgresql.service;
        then
            echo -e "\e[1;32m ... postgresql.service started successfully";
            /usr/bin/logger 'postgresql.service started successfully' -t 'wikidotjs-2022-01-23';
        else
            echo -e "\e[1;31m ... postgresql.service FAILED!\e[0m";
            /usr/bin/logger "postgresql.service FAILED!" -t 'wikidotjs-2022-01-23';
    fi
    # wikidotjs.service
    if systemctl is-active --quiet wikidotjs.service;
        then
            echo -e "\e[1;32m ... wikidotjs.service started successfully";
            /usr/bin/logger 'wikidotjs.service started successfully' -t 'wikidotjs-2022-01-23';
        else
            echo -e "\e[1;31m ... wikidotjs.service FAILED!\e[0m";
            /usr/bin/logger "wikidotjs.service FAILED!" -t 'wikidotjs-2022-01-23';
    fi
    echo -e "\e[1;32m - check_services() finished"
    /usr/bin/logger 'check_services finished' -t 'wikidotjs-2022-01-23';
}

create_user () {
    echo -e "\e[1;32m - create_user()"
    
    echo -e "\e[1;36m ... creating Wiki.js user $APP_USER.\e[0m"
    adduser --quiet --disabled-password --gecos 'Wiki.js User' "$APP_USER" > /dev/null 2>&1
    
    echo -e "\e[1;36m ... adding Wiki.js user to group $NGINX_group.\e[0m"
    usermod -a -G "$NGINX_group" "$APP_USER" > /dev/null 2>&1
    echo -e "\e[1;32m - create_user()"
}

install_wikidotjs () {
    /usr/bin/logger 'install_wikidotjs()' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - install_wikidotjs()"
    
    echo -e "\e[1;36m ... getting wiki.js\e[0m"
    mkdir $APP_PATH > /dev/null 2>&1
    cd $APP_PATH > /dev/null 2>&1
    wget https://github.com/Requarks/wiki/releases/download/2.5.268/wiki-js.tar.gz
    
    echo -e "\e[1;36m ... unpacking wiki.js\e[0m"
    tar xzf wiki-js.tar.gz > /dev/null 2>&1
    mv config.sample.yml config.yml > /dev/null 2>&1
    # Modify config.yml

    echo -e "\e[1;36m ... setting postgre password to long secret\e[0m"
    sed -ie s/"pass: wikijsrocks"/"pass: $postgreuserpw"/ $APP_PATH/config.yml

    echo -e "\e[1;36m ... creating and enabling wiki.js services\e[0m"
    cat << __EOF__ > /lib/systemd/system/wikidotjs.service
[Unit]
Description=Wiki.js
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node server
Restart=always
# Consider creating a dedicated user for Wiki.js here:
User=$APP_USER
Group=$APP_USER
Environment=NODE_ENV=production
WorkingDirectory=$APP_PATH

[Install]
WantedBy=multi-user.target
__EOF__
    sync;
    systemctl daemon-reload > /dev/null 2>&1
    systemctl enable wikidotjs.service > /dev/null 2>&1
    echo -e "\e[1;32m - install_wikidotjs() finished"
    /usr/bin/logger 'install_wikidotjs() finished' -t 'wikidotjs-2022-01-23';
}

prepare_postgresql() {
    /usr/bin/logger 'prepare_postgresql' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - prepare_postgresql()\e[0m";
    
    echo -e "\e[1;36m ... create postgres user $APP_USER";
    su postgres -c "createuser -drs $APP_USER;"
    su - postgres -c "psql -U postgres -d postgres -c \"alter user wikijs with password '$postgreuserpw';\""
    su postgres -c "psql -c $APP_NAME ALTER USER $APP_USER WITH PASSWORD '$postgreuserpw';"
    
    echo -e "\e[1;36m ... create postgres user root";
    su postgres -c 'createuser -drs root;'
    
    echo -e "\e[1;36m ... create database";
    su postgres -c "createdb -O $APP_USER $APP_NAME;"
    
    # Setup permissions.
    echo -e "\e[1;36m ... setting postgres permissions";
    su postgres -c "psql $APP_NAME -c 'create role dba with superuser noinherit;'"
    su postgres -c "psql $APP_NAME -c 'grant dba to $APP_USER;'"
    su postgres -c "psql $APP_NAME -c 'grant dba to root;'"

    echo -e "\e[1;32m - prepare_postgresql() finished\e[0m";
    /usr/bin/logger 'prepare_postgresql finished' -t 'wikidotjs-2022-01-23';
}

install_nginx() {
    /usr/bin/logger 'install_nginx()' -t 'GSE-21.4.3';
    echo -e "\e[1;32m - install_nginx()\e[0m";

    echo -e "\e[1;36m ... installing nginx and nginx utils\e[0m";
    apt-get -qq -y install nginx apache2-utils > /dev/null 2>&1;
    echo -e "\e[1;32m - install_nginx() finished\e[0m";
    /usr/bin/logger 'install_nginx() finished' -t 'GSE-21.4.3';
}

configure_nginx() {
    /usr/bin/logger 'configure_nginx()' -t 'GSE-21.4.3';
    echo -e "\e[1;32m - configure_nginx()\e[0m";

    echo -e "\e[1;36m ... configuring diffie hellman parameters file\e[0m";
    openssl dhparam -out /etc/nginx/dhparam.pem 2048 > /dev/null 2>&1

    # TLS
    echo -e "\e[1;36m ... configuring site\e[0m";
    cat << __EOF__ > /etc/nginx/sites-available/000-$APP_NAME.conf;
#############################################
# reverse proxy configuration for Wiki.js   #
# Running GSE on port 443 TLS               #
#############################################

server {
    listen 80;
    return 301 https://\$host\$request_uri;
}

server {
    client_max_body_size 32M;
    listen 443 ssl http2;
    ssl_certificate           $NGINX_CERTS_DIR/$fqdn.crt;
    ssl_certificate_key       $NGINX_CERTS_DIR/$fqdn.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!eNULL:!EXPORT:!CAMELLIA:!DES:!MD5:!PSK:!RC4;
    ssl_prefer_server_ciphers on;
    # Enable HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
    # Optimize session cache
    ssl_session_cache   shared:SSL:40m;
    ssl_session_timeout 4h;  # Enable session tickets
    ssl_session_tickets on;
    # Diffie Hellman Parameters
    ssl_dhparam $NGINX_DIR/dhparam.pem;

### wiki.js is listening on localhost port 3000/TCP
    location / {
      # Authentication handled by wiki.js
      # Access log
      access_log              $NGINX_LOG_DIR/$APP_NAME.access.log;
      error_log               $NGINX_LOG_DIR/$APP_NAME.error.log  warn;
      proxy_set_header        Host \$host;
      proxy_set_header        X-Real-IP \$remote_addr;
      proxy_set_header        X-Forwarded-For \$proxy_add_x_forwarded_for;
      proxy_set_header        X-Forwarded-Proto \$scheme;

      # Fix the “It appears that your reverse proxy set up is broken" error.
      proxy_pass          http://localhost:3000;
      proxy_read_timeout  90;

      proxy_redirect      http://localhost:3000 https://$HOSTNAME;
    }
  }
__EOF__
    echo -e "\e[1;32m - configure_nginx() finished\e[0m";
    /usr/bin/logger 'configure_nginx() finished' -t 'GSE-21.4.3';
}

set_hosts () {
    /usr/bin/logger 'set_hosts()' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - set_hosts()"

    echo -e "\e[1;36m ... setting up hosts file.\e[0m"
    echo >> /etc/hosts "127.0.0.1 $(hostname) $fqdn"
    echo -e "\e[1;32m - set_hosts() finished"
    /usr/bin/logger 'set_hosts() finished' -t 'wikidotjs-2022-01-23';
}

rename_default_vhost() {
    /usr/bin/logger 'rename_default_vhost()' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - rename_default_vhost()"

    echo -e "\e[1;36m ... enabling $APP_NAME site.\e[0m"
    rm -f /etc/nginx/sites-enabled/default.conf > /dev/null 2>&1
    rm -f /etc/nginx/sites-available/default.conf > /dev/null 2>&1
    ln /etc/nginx/sites-available/000-$APP_NAME.conf /etc/nginx/sites-enabled/ > /dev/null 2>&1
    echo -e "\e[1;32m - rename_default_vhost() finished"
    /usr/bin/logger 'rename_default_vhost() finished' -t 'wikidotjs-2022-01-23';
}

configure_permissions() {
    /usr/bin/logger 'configure_permissions()' -t 'wikidotjs-2022-01-23';
    echo -e "\e[1;32m - configure_permissions()"

    echo -e "\e[1;36m ... setting permissions.\e[0m"
    for chmod_dir in "$APP_PATH"; do
        chmod -R 775 "$chmod_dir" > /dev/null 2>&1
    done
    chown -R "$APP_USER":"$APP_USER" "$APP_PATH" > /dev/null 2>&1
    echo -e "\e[1;32m - configure_permissions()"
    /usr/bin/logger 'configure_permissions() finished' -t 'wikidotjs-2022-01-23';
}

install_crowdsec() {
    /usr/bin/logger 'install_crowdsec()' -t 'Debian-FW-20211210';
    # Add repo
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash;
    #install crowdsec core daemon
    apt-get -y install crowdsec;
    # install firewall bouncer
    apt-get -y install crowdsec-firewall-bouncer-iptables;
    /usr/bin/logger 'install_crowdsec() finished' -t 'Debian-FW-20211210';
}

configure_crowdsec() {
    /usr/bin/logger 'configure_crowdsec()' -t 'Debian-FW-20211210';
    # Collection iptables
    cscli parsers install crowdsecurity/iptables-logs;
    cscli parsers install crowdsecurity/geoip-enrich;
    cscli scenarios install crowdsecurity/iptables-scan-multi_ports;
    cscli scenarios install crowdsecurity/ssh-bf;
    cscli collections install crowdsecurity/mysql;
    cscli collections install crowdsecurity/linux;
    cscli collections install crowdsecurity/iptables;
    cscli postoverflows install crowdsecurity/rdns;
    # Running 'sudo systemctl reload crowdsec' for the new configuration to be effective.
    systemctl reload crowdsec.service;
    # Enable auto complete for BASH
    source /etc/profile;
    source <(cscli completion bash);
    /usr/bin/logger 'configure_crowdsec() finished' -t 'Debian-FW-20211210';
}

##################################################################################################################
## Main                                                                                                          #
##################################################################################################################

main() {
    /usr/bin/logger 'Installing wikidotjs.......' -t 'wikidotjs';
    # Setting global vars
    # Change the mailaddress below to reflect your mail-address
    # CERT_TYPE can be Self-Signed or LetsEncrypt (internet connected, thus also installing crowdsec)
    readonly CERT_TYPE="Self-Signed"
    readonly fqdn="$(hostname --fqdn)"
    readonly HOSTNAME_ONLY="$(hostname --short)"
    # OS Version
    # freedesktop.org and systemd
    . /etc/os-release
    readonly OPERATING_SYSTEM=$NAME
    readonly VER=$VERSION_ID
    readonly codename=$VERSION_CODENAME
    # Wiji.js specific variables
    readonly APP_USER="wikijs"
    readonly APP_NAME="wiki"
    readonly APP_PATH="/opt/$APP_NAME"
    readonly postgreuserpw="$(< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c24; echo)"
    readonly installedFILE="$APP_PATH/wikidotjs_installed";
    ## Variables required for certificate
    # organization name
    # (see also https://www.switch.ch/pki/participants/)
    readonly ORGNAME=wikidotjs_server
    # the fully qualified server (or service) name, change if other servicename than hostname
    # Local information
    readonly ISOCOUNTRY=DK;
    readonly PROVINCE=Denmark;
    readonly LOCALITY=Copenhagen
    # subjectAltName entries: to add DNS aliases to the CSR, delete
    # the '#' character in the ALTNAMES line, and change the subsequent
    # 'DNS:' entries accordingly. Please note: all DNS names must
    # resolve to the same IP address as the fqdn.
    readonly ALTNAMES=DNS:$HOSTNAME_ONLY # , DNS:bar.example.org , DNS:www.foo.example.org
    # NGINX settings
    readonly NGINX_LOG_DIR=/var/log/nginx;
    readonly NGINX_DIR=/etc/nginx
    readonly NGINX_CERTS_DIR=$NGINX_DIR/certs
    readonly NGINX_GROUP=www-data

    # Crowdsec to provide some additional awesome security for internet connected systems
    if ! [ -f $installedFILE ];
    then
        /usr/bin/logger "Starting installation. Operating System $OPERATING_SYSTEM $VER $codename" -t 'wikidotjs-2022-01-23';
        echo -e "\e[1;32m - starting Wiki.js installation on $fqdn"
        # Reveal OS, Version, and codename
        
        echo -e "\e[1;36m ... operating System $OPERATING_SYSTEM $VER $codename\e[0m";
        # install all required elements and generate certificates for webserver
        install_prerequisites;
        prepare_nix;
        create_user;
        prepare_postgresql;
        install_wikidotjs;
        configure_permissions;
        install_nginx;
        configure_nginx;
        rename_default_vhost;
        set_hosts;

        # Either generate a CSR and use with internal CA, create a self-signed certificate if you are running an internal test server
        # Or Use Lets Encrypt if this is a public server.
        # Configure CERT_TYPE above
        echo -e "\e[1;36m ... generating $CERT_SERVER certificate\e[0m"
        generate_certificates
        case $CERT_TYPE in
        LetsEncrypt)
            echo -e "\e[1;36m ... generating $CERT_SERVER certificate\e[0m"
            letsencrypt_certificates
            install_crowdsec;
            configure_crowdsec;
            ;;
        esac
        check_services;
        /usr/bin/logger 'wikidotjs Installation complete' -t 'wikidotjs-2022-01-23';
        echo -e;
        touch $installedFILE;
        echo -e "\e[1;32mwikidotjs Installation complete\e[0m";
        echo -e "\e[1;32m  *** Browse to \e[1;33mhttps://$fqdn \e[1;32mto login to Wiki.js. ***\e[0m"
        echo -e "\e[1;32m* Cleaning up...\e[0m"
    else
        echo -e "\e[1;31m-------------------------------------------------------------------------------\e[0m";
        echo -e "\e[1;31m   It appears that wikidotjs Asset Server has already been installed\e[0m"
        echo -e "\e[1;31m   If this is in error, or you just want to install again, then delete the\e[0m"
        echo -e "\e[1;31m   files $installedFILE and $mailconfigfile & run this script again\e[0m"
        echo -e "\e[1;31m-------------------------------------------------------------------------------\e[0m";
    fi
    echo -e "\e[1;32m - Installation complete.\e[0m"
}

main;

exit 0;
