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
SCALIX_SERVER_PACKAGE=""
SCALIX_TOMCAT_PACKAGE=""
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
RELEASE_NAME=$(lsb_release -d | awk -F":" '{gsub(/^[ \t]+/, "", $2); gsub(/[ \t]+$/, "", $2); print $2 }')
FQDN_PATTERN='(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{2,63}(?<!-)\.?){2,3}(?:[a-zA-Z]{2,})$)'

APT_CMD=$(type -P aptitude)
if [ -z "$APT_CMD" ]; then
  APT_CMD=$(type -P apt-get)
fi

x86_64=false
if [ "$(uname -m)" == "x86_64" ]; then
    x86_64=true
fi

echo "System platform: $RELEASE_NAME"

INSTALLED_PACKAGES=$(dpkg --list | grep scalix | awk '{ printf $2 " " }')

if [[ $KERNEL_VERSION = *Ubuntu* ]]; then
    ubuntu_version=$(lsb_release -r | grep '[0-9]' | awk '{ print int($2); }')
    if [ "$ubuntu_version" -lt 13 ]; then
        echo "Unfortunately this release of Ubuntu ($RELEASE_NAME) is not supported"
        exit 1
    fi
    SERVER_ARCH="ubuntu$ubuntu_version"
fi

function remove_scalix() {

    if [ -z "$INSTALLED_PACKAGES" ]; then
        echo "There are no installed packages to remove."
    else
        $APT_CMD purge $INSTALLED_PACKAGES || exit $?
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


# add i386 architecture to system to be able to install i386 packages
# Debian 7 and Ubunut 13.04
function dpkg_add_i386_arch() {
  local arch_file="/var/lib/dpkg/arch"
  if [ -f "$arch_file" ]; then
    local arch=$(grep i386 $arch_file)
    if [ -z "$arch" ]; then
      dpkg --add-architecture i386
    fi
  else
    dpkg --add-architecture i386
  fi
  $APT_CMD update
}

# check if package exists in folder
function find_sx_package () {
    local skip=''
    if ! $x86_64; then
        skip="*x86_64*"
    fi
    local count=$(find $path ! -name "$skip" -name "scalix-$1*[$SERVER_ARCH|all|$2].deb" | sort -Vru)
    echo $count | awk '{ print $1 }'
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

function use_https_for_webapp() {
    while true; do
        read -p "Do you whant to use secure connection HTTPS instead HTTP for $1 ( yes / no ) ?" yn
        case $yn in
            [Yy]* )
                for i in $(sxtomcat-get-mounted-instances) ; do
                    sxtomcat-webapps --forcehttps $i $2
                done
                break
            ;;
            [Nn]* ) break;;
            * ) echo "Please answer yes or no.";;
        esac
    done
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

function collect_dependencies_from_package() {
    local PKG=$1
    local OIFS=$IFS # store old IFS in buffer
    IFS=','
    for section in 'Depends' 'Pre-Depends' ; do
        pkgs_list="$(dpkg -f $PKG $section)"
        for item in  ${pkgs_list[@]} ; do
            dependency=$(echo "$item" | awk '{ printf $1 }')
            if [[ $dependency != *scalix* ]]; then
                if [[ $dependency == *\|* ]]; then
                    if $x86_64; then
                        dependency=$(echo "$dependency" | awk -F'|' '{ printf $2 }')
                    else
                        dependency=$(echo "$dependency" | awk -F'|' '{ printf $1 }')
                    fi
                fi
                if [[ $DEPENDENCIES != *$dependency* ]]; then
                    DEPENDENCIES="$DEPENDENCIES $dependency"
                fi
            fi
        done
    done
    IFS=$OIFS
}

# gether dependencies which need to install
function collect_dependencies() {
    SCALIX_SERVER_PACKAGE=$(find_sx_package "server")
    if [ -n "$SCALIX_SERVER_PACKAGE" ]; then
        collect_dependencies_from_package "$SCALIX_SERVER_PACKAGE"
    fi

    SCALIX_TOMCAT_PACKAGE=$(find_sx_package "tomcat")
    if [ -n "$SCALIX_TOMCAT_PACKAGE" ]; then
      if [ -z "$(type -P java)" ]; then
        DEPENDENCIES="$DEPENDENCIES default-jdk"
      fi

      if [ -z "$(dpkg-query -l apache2 | grep ii )" ]; then
        DEPENDENCIES="$DEPENDENCIES apache2"
      fi

    fi

    local sx_postgres=$(find_sx_package "postgres")
    if [ -n "$sx_postgres" ]; then
      collect_dependencies_from_package "$sx_postgres"
    fi
}

# install scalix packages
function install_sx_package() {
  echo "Installing $1"
  for entry in $2
  do
    sx_package=$(find_sx_package $entry $3)
    if [ -f "$sx_package" ]; then
        safety_exec "dpkg -i $4 \"$sx_package\""
    else
        echo "Could not find package $entry. Installation failed."
        exit 2
    fi
  done
}

check_package_dir $PACKAGES_DIR

collect_dependencies $PACKAGES_DIR

echo "Force add i386 architecture if needed"
dpkg_add_i386_arch

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
  $APT_CMD install $DEPENDENCIES
fi

if [ -n "$SCALIX_SERVER_PACKAGE" ]; then
  install_sx_package "installing libical" "libical" "i386"
  install_sx_package "libical, chardet and iconv" "chardet iconv" $SERVER_ARCH
  install_sx_package "Scalix server core" "server" $SERVER_ARCH $DPKG_ARGS

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

if [ -n "$SCALIX_TOMCAT_PACKAGE" ]; then
  install_sx_package "Tomcat Connector" "tomcat-connector" "all"
  install_sx_package "Scalix Tomcat " "tomcat_" "all"
  install_sx_package "All available web applications" 'mobile res swa wireless platform sac postgres sis' "all"
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
       $base/res/config/krblogin.conf \
       $base/wireless/wireless.properties"

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

if [ -n "$(dpkg-query -l scalix-sac | grep ii )" ]; then
    use_https_for_webapp "Scalix Administration console", 'sac'
fi

if [ -n "$(dpkg-query -l scalix-swa | grep ii )" ]; then
    use_https_for_webapp "Scalix Web Access", 'webmail'
fi

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
