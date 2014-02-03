#!/bin/bash
#
# Copyright 2014 Scalix, Inc. (www.scalix.com)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Street #330, Boston, MA 02111-1307, USA.
#

echo "
----------------------------------------------------------------------
Scalix Debian installer. Please take a look at
http://www.scalix.com/wiki/index.php?title=Manual_Installation
to make sure your system fullfills all necessary requirements.
----------------------------------------------------------------------
"

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

DEPENDENCIES=""
SCALIX_SERVER_PACKAGES_EXISTS=""
SCALIX_TOMCAT_PACKAGES_EXISTS=""
SERVER_ARCH="deb7"
DPKG_ARGS=""
PACKAGES_DIR="$PWD"
EXTERNAL_IP=""
SX_WEB_CLIENT_CONF_PATH="/opt/scalix/global/httpd"
SX_WEB_CLIENT_CONF="scalix-web-client.conf"

KERNEL_VERSION=$(uname -v)
LDOMAIN=$(hostname -d)
HOST=$(hostname)
FQDN=$(hostname -f)
SHORT=${HOST:0:1}${HOST: -1:1}
MNODE=$(uname -n)

FQDN_PATTERN='(?=^.{1,254}$)(^(?:(?!\d+\.)[a-zA-Z0-9_\-]{1,63}\.)+(?:[a-zA-Z]{2,})$)'

APT_CMD=$(type -P aptitude)
if [ -z "$APT_CMD" ]; then
  APT_CMD=$(type -P apt-get)
fi

x86_64=false
if [ "$(uname -m)" == "x86_64" ]; then
    x86_64=true
fi


IS_UBUNTU12=false
if [[ $KERNEL_VERSION = *Ubuntu* ]]; then
  ubuntu_version=$(lsb_release -r | grep '[0-9]' | awk '{ print int($2); }')
  if [ $ubuntu_version -lt 13 ]; then
      IS_UBUNTU12=true
  fi
fi

awk_print='{ print $2; }'
if [[ $x86_64 ]] && [[ $IS_UBUNTU12 == false ]] ; then
    awk_print='{ print $2":"$4; }'
fi
INSTALLED_PACKAGES=$(dpkg --list | grep scalix | awk "$awk_print")

function remove_scalix() {

    if [ -z "$INSTALLED_PACKAGES" ]; then
        echo "There are no installed packages to remove."
    else
        aptitude purge $INSTALLED_PACKAGES || exit $?
        echo "Clean up"
        rm -rf /var/opt/scalix
        rm -rf /etc/opt
        rm -rf /opt/scalix
        rm -f /etc/apache2/**/scalix*.conf
        echo "Reload apache config"
        service apache2 force-reload
    fi
    echo "Done!"
    exit 0
}

function download_packages() {
    if [ -d "$PWD/server" ]; then
        local server_backup_folder="$PWD/server_backup$(date +%Y%m%d)"
        if [ -d "$server_backup_folder" ]; then
            local dircount=1
            while [ -d "$server_backup_folder-$dircount" ]; do
                dircount=$(expr $dircount + 1)
            done
            server_backup_folder="$server_backup_folder-$dircount"
        fi
        mv "$PWD/server" "$server_backup_folder"
    fi
    mkdir -p "$PWD/server"
    cd "$PWD/server"
    wget -i http://downloads.scalix.com/debian/?type=deb
    cd "$PACKAGES_DIR"
}

if [ -n "$1" ]; then
    case "$1" in
        "--purge" ) remove_scalix; break;;
        "--update" ) download_packages;;
        * ) echo "Unknown argument."; exit 123;;
    esac
fi

if [ -d "$PWD/server" ]; then
  PACKAGES_DIR="$PWD/server"
fi

if [ -z "$(echo $FQDN | grep -P $FQDN_PATTERN)" ]; then
    echo "Invalid fully-qualified hostname - '$FQDN' (your current FQDN hostname)"
    echo "The \"hostname\" command should return the short hostname, while the
\"hostname --fqdn\" command should return the fully-qualified hostname"
    echo
    exit 2
fi

if $IS_UBUNTU12; then
    SERVER_ARCH="ubuntu12"
    if $x86_64; then
        echo
        echo " At this moment Ubuntu 12.04 x64(amd64) has issues with unresolved
 dependencies in scalix-server package. To install scalix-server package we will
 automatically add option \"--force-all\" for dpkg command and all errors will
 be ignored during instaltion. All necessary dependencies will be suggested to
 you to install before installing packages."
        echo
        echo
        while true; do
            read -p "Do you wish to install scalix despite this issue ( yes / no ) ?" yn
            case $yn in
                [Yy]* ) DPKG_ARGS=" --force-all "; break;;
                [Nn]* ) exit;;
                * ) echo "Please answer yes or no.";;
            esac
        done
    fi
fi


# get real path
function realpath() {
  if [ ! -z "$1" ]; then
    echo $(readlink -f $1)
  fi
}

# execute command and if returned status not 0 than exit
function safety_exec() {
    echo "executing command $1"
    eval $1
    local error=$?
    if test $error -gt 0
    then
        echo "Error while executing \"$1\""
        exit $error
    fi
}


# Debian 7 and Ubunut 13.04
function dpkg_cmd_add_i386_arch() {
  local arch_file="/var/lib/dpkg/arch"
  if [ -f "$arch_file" ]; then
    local arch=$(grep i386 $arch_file)
    if [ -z "$arch" ]; then
      dpkg --add-architecture i386
    fi
  else
    dpkg --add-architecture i386
  fi
}

# Ubuntu 12.04
function manual_add_i386_arch() {
  local arch_file='/etc/dpkg/dpkg.cfg.d/multiarch' #architectures
  if [ -f "$arch_file" ]; then
    local arch=$(grep i386 $arch_file)
    if [ -z "$arch" ]; then
      echo "foreign-architecture i386" > $arch_file
    fi
  else
    echo "foreign-architecture i386" > $arch_file
  fi
}

# add i386 architecture to system to be able to install i386 packages
function add_i386_arch() {
  if [[ $KERNEL_VERSION = *Debian* ]]; then
    dpkg_cmd_add_i386_arch
  elif [[ $KERNEL_VERSION = *Ubuntu* ]]; then
    if $IS_UBUNTU12; then
      if $x86_64; then
          manual_add_i386_arch
      fi
    else
      dpkg_cmd_add_i386_arch
    fi
  fi
  $APT_CMD update
}

# check if package exists in folder
function package_exists () {
    local count=$(find "$PACKAGES_DIR" -name "scalix-$1*[$SERVER_ARCH|all].deb"  | grep -v ^l | wc -l)
    echo $count
}

# Check if IP is valid
# source http://www.linuxjournal.com/content/validating-ip-address-bash-script
# test's
# 4.2.2.2             : good
# a.b.c.d             : bad
# 192.168.1.1         : good
# 0.0.0.0             : good
# 255.255.255.255     : good
# 255.255.255.256     : bad
# 192.168.0.1         : good
# 192.168.0           : bad
# 1234.123.123.123    : bad
function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

# ask user for external ip for scalix postgres.
function get_external_ip() {
  read -p "Please enter the external ip address of your Scalix box? " ip
  if valid_ip $ip; then EXTERNAL_IP=$ip; else get_external_ip; fi
}

# check directory if it contains scalix packages
function check_package_dir() {
  if [ -z "$1" -o ! -d "$(realpath $1)" ]; then
    echo "Folder $1 does not exists or not readable. "
    read -p "Please specify another folder with deb packages: " dir
    check_package_dir $dir
  fi
  local dir=$(realpath $1)
  local pkgs_count=$(find $1 -maxdepth 1 -type f -name 'scalix*\.deb'  | grep -v ^l | wc -l)
  if [ "$pkgs_count" = "0" ]; then
    echo "Folder $1 does not contain deb packages"
    read -p "Please specify another folder with deb packages: " dir
    check_package_dir $dir
  fi
  PACKAGES_DIR=$dir
}

# gether dependencies which need to install
function collect_dependencies() {
    SCALIX_SERVER_PACKAGES_EXISTS=$(package_exists "server")
    if [ -n "$SCALIX_SERVER_PACKAGES_EXISTS" ]; then
      DEPENDENCIES="libc6:i386 libgssapi3-heimdal:i386 libgcc1:i386 gawk sed util-linux util-linux-locales openssl
      procps w3m libkrb5-3:i386 libfreetype6:i386 libsasl2-2:i386 libsasl2-modules:i386 libglib2.0-0:i386
      libxml2:i386 sendmail sendmail-cf libstdc++6:i386 libmilter1.0.1:i386 ed
       zlib1g:i386 mailutils libldap-2.4-2:i386 "
    fi

    SCALIX_TOMCAT_PACKAGES_EXISTS=$(package_exists "tomcat")
    if [ -n "$SCALIX_TOMCAT_PACKAGES_EXISTS" ]; then
      if [ -z "$(type -P java)" ]; then
        DEPENDENCIES="$DEPENDENCIES default-jdk"
      fi

      if [ "$(dpkg --list | grep apache2 | wc -l)" = "0" ]; then
        DEPENDENCIES="$DEPENDENCIES apache2"
      fi

    fi

    local result=$(package_exists "postgres")
    if [ "$result" != "0" -a -z "$(type -P psql)" ]; then
      DEPENDENCIES="$DEPENDENCIES postgresql"
    fi
}

# install scalix packages
function install() {
  echo "Installing $1"
  for entry in $(ls $PACKAGES_DIR | grep -E "$2" | grep -E ".*$3\.deb")
  do
    safety_exec "dpkg -i $4 \"$PACKAGES_DIR/$entry\""
  done
}

check_package_dir $PACKAGES_DIR

collect_dependencies $PACKAGES_DIR

echo "Force add i386 architecture if needed"
add_i386_arch

if [ -n "$DEPENDENCIES" ]; then
  echo "Before installing Scalix you must install following dependencies"
  echo
  echo $DEPENDENCIES
  echo
  $APT_CMD install $DEPENDENCIES

  error=$?
  if test $error -gt 0
  then
      echo "Error while installing dependencies $1"
      exit $error
  fi
  echo "We need to insure that all dependencies are installed"
  echo
  $APT_CMD install "$DEPENDENCIES openssh-server"
fi

if [ -n "$SCALIX_SERVER_PACKAGES_EXISTS" ]; then
  install "installing libical" "libical" "i386"
  install "libical, chardet and iconv" "chardet|iconv" $SERVER_ARCH
  install "Scalix server core" "server" $SERVER_ARCH $DPKG_ARGS

  export PATH=/opt/scalix/bin:$PATH

  read -s -p "Please enter the admin password for the Scalix admin user (sxadmin)? " admpwd
  echo
  read -s -p "Please enter a password for the ldap query user? " ldappwd
  echo

  #configure scalix server core
  echo "Configuring scalix server"
  ommakeom
  sxconfig --set -t general.usrl_cn_rule='G S'
  sxconfig --set -t general.usrl_authid_rule='l@'
  sxconfig --set -t orniasys.name_part_1='"C" <S>' -t orniasys.domain_part_1="$LDOMAIN" # com
  omaddmn -m $MNODE
  omrc -n
  omadmidp -a -s 66000 -n 100
  omaddu -n sxadmin/$MNODE --class limited -c admin -p "$admpwd" sxadmin
  omconfenu -n "sxadmin/$MNODE"
  omlimit -u "sxadmin/$MNODE" -o -i 0 -m 0
  omaddu -n sxqueryadmin/$MNODE --class limited -c admin -p $ldappwd sxqueryadmin@$FQDN
  omaddpdl -l ScalixUserAdmins/$MNODE
  omaddpdl -l ScalixUserAttributesAdmins/$MNODE
  omaddpdl -l ScalixGroupAdmins/$MNODE
  omaddpdl -l ScalixAdmins/$MNODE
  omon -s all

fi

if [ -n "$SCALIX_TOMCAT_PACKAGES_EXISTS" ]; then
  install "Tomcat Connector" "tomcat-connector" "all"
  install "Scalix Tomcat " "tomcat_" "all"
  install "All available web applications" 'mobile|res|swa|wireless|platform|sac|postgres|sis' "all"
  if [ -d "/opt/scalix-postgres/bin" ]; then
    export PATH=/opt/scalix-postgres/bin:$PATH
  fi
  export PATH=/opt/scalix-tomcat/bin:$PATH
fi

base="/var/opt/scalix/$SHORT"
dbpwd=""
echo "Configuring scalix-postgres"
if [ -d "/opt/scalix-postgres/bin" ]; then
    read -s -p "Please enter a password for the db user? " dbpwd
    echo
    sxpsql-setpwd $dbpwd
    echo $dbpwd > "$base/caa/scalix.res/config/psdata"
    get_external_ip
    sxpsql-whitelist $EXTERNAL_IP
fi

echo "Setting up settings for web applications"
base="/var/opt/scalix/$SHORT"
files="$base/webmail/swa.properties \
       $base/caa/scalix.res/config/ubermanager.properties \
       $base/res/config/res.properties \
       $base/platform/platform.properties \
       $base/mobile/mobile.properties \
       $base/sis/sis.properties \
       $base/caa/config/krblogin.conf \
       $base/res/config/krblogin.conf"

for file in $files; do
  sed -e "s;%LOCALDOMAIN%;$LDOMAIN;g" \
      -e "s;%LOCALHOST%;$FQDN;g" \
      -e "s;swa.platform.url=http://%PLATFORMURL%:8080/api;swa.platform.url=http://$FQDN/api;g" \
      -e "s;swa.platform.enabled=false;swa.platform.enabled=true;g" \
      -e "s;%PLATFORMURL%;HTTP://$FQDN/API;g" \
      -e "s;ubermanager.notification.listener.address=\*;ubermanager.notification.listener.address=$EXTERNAL_IP;g" \
      -e "s;__SECURED_MODE__;false;g" \
      -e "s;ubermanager/__FQHN_HOST__@__KERBEROS_REALM__;;g" \
      -e "s;__KERBEROS_REALM__;;g" \
      -e "s;__KEY_TAB_FILE_PATH__;;g" \
      -e "s;__FQHN_FOR_KDC_HOST__;;g" \
      -e "s;__FQHN_QUERY_SERVER_NAME__;$FQDN;g" \
      -e "s;__UBERMGR_USE_EXTERNAL_AUTH__;false;g" \
      -e "s;__UBERMGR_ALLOW_EXTERNAL_AUTH__;false;g" \
      -e "s;__UBERMGR_MAXLIST_SIZE__;100;g" \
      -e "s;__UBERMGR_MAIL_DOMAINS_LIST__;$LDOMAIN;g" \
      -e "s;res/__FQHN_HOST__@;;g" \
      -e "s;__UBERMGR_EXTERNAL_DOMAIN_AUTH_LIST__;;g" \
      -e "s;__CONFIGURED__;true;g" \
      -e "s;__FQHN_FOR_UBERMANAGER__;$FQDN;g" \
      -e "s;__TOMCAT_PORT__;;g" \
      -e "s;res.tomcat.tcp.port=80;res.tomcat.tcp.port=;g" \
      -e "s;localhost;$FQDN;g" \
      -e "s;%SIS-LANGUAGE%;English;g" \
      -e "s;%IMAPHOST%;$FQDN;g" \
      -e "s;%SMTPHOST%;$FQDN;g" \
      -e "s;%LDAPPORT%;389;g" \
      -e "s;%DBHOST%;$FQDN:5733;g" \
      -e "s;%DBPASSWD%;$dbpwd;g" \
      -e "s;%INDEX-WHITELIST%;$EXTERNAL_IP,127.0.0.1;g" \
      -e "s;%SEARCH-WHITELIST%;$EXTERNAL_IP,127.0.0.1;g" \
      -e "s;%INDEXADMIN-WHITELIST%;$EXTERNAL_IP,127.0.0.1;g" \
      $file > $file.neu
  mv $file.neu $file
  email_domain=$(grep swa.email.domain "$base/webmail/swa.properties")
  if [ -z "$email_domain" ]; then
    echo "swa.email.domain=$FQDN" >> "$base/webmail/swa.properties"
  fi

done


echo "Running sxmkindex: redirecting output to /var/log/sxmkindex.log"
nohup nice -n 10 sxmkindex -r 0 > /var/log/sxmkindex.log 2>&1 &

#HACKS
#remove dot in <VirtualHost debian.:80> should be <VirtualHost debian:80> or debian.com
sed -ri 's/(\w+)\.:([0-9]*)/\1:\2/' /etc/opt/scalix-tomcat/connector/*/instance-*.conf


if [ -f "$SX_WEB_CLIENT_CONF_PATH/$SX_WEB_CLIENT_CONF" ]; then
    apache2_base="/etc/apache2/"
    apache_conf_dir="$apache2_base/conf.d"
    if [ -d "$apache2_base/conf-enabled" ]; then
        apache_conf_dir="$apache2_base/conf-enabled"
    fi
    if [ ! -f "$apache_conf_dir/$SX_WEB_CLIENT_CONF" ]; then
        ln -s "$SX_WEB_CLIENT_CONF_PATH/$SX_WEB_CLIENT_CONF" "$apache_conf_dir/$SX_WEB_CLIENT_CONF"
    fi
fi

service scalix-tomcat restart
echo "Stoping apache server (belive me it's better to stop)"
service apache2 stop
sleep 1
echo "Starting apache server"
service apache2 start

cat << EOF

############################################################
#
# FINISHED !!
#
# You should now be able to access your scalix installation at:
#
# Admin Console: http://$FQDN/sac
# Webmail:       http://$FQDN/webmail
# Mobile Client: http://$FQDN/m
# API:           http://$FQDN/api/dav
#
############################################################

EOF
sleep 2
