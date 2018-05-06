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

DPKG_ARGS=""
PACKAGES_DIR="$PWD"
EXTERNAL_IP=""
SX_WEB_CLIENT_CONF_PATH="/opt/scalix/global/httpd"
SX_WEB_CLIENT_CONF="scalix-web-client.conf"

KERNEL_VERSION=$(uname -v)
LDOMAIN=$(hostname -d)
SHORT_HOSTNAME=$(hostname -s)
FQDN=$(hostname -f)
SHORT=${SHORT_HOSTNAME:0:1}${SHORT_HOSTNAME: -1:1}
RELEASE_NAME=$(lsb_release -d | awk -F":" '{gsub(/^[ \t]+/, "", $2); gsub(/[ \t]+$/, "", $2); print $2 }')
FQDN_PATTERN='(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.){2,}+[a-zA-Z]{2,}$)'
DIST_VERSION=$(lsb_release -r | grep '[0-9]' | awk '{ print int($2); }')
SERVER_ARCH="deb$DIST_VERSION"

MNODE=(${SHORT_HOSTNAME//./ })

UAL_SIGNON_TWEAKS=(
    "UAL_SIGNON_ALIAS=YES"
    "UAL_SIGNON_ALIAS_CONFIG=SYS"
    "UAL_USE_SIGNON_ALIAS=FALSE"
)
UAL_SIGNON_TWEAK_HELP_TEXT=$(cat <<-EOF
# These three tweaks allow users to signon using an alias. Only
# system-defined aliases are permitted and it the alias name is ignored
# for the purposes of message creation and so on.
# Note that changing these settings normally requires Scalix to be
# restarted.
EOF
)

CDA_TWEAKS=('CDA_USE_CHANGE_LOG=TRUE')
CDA_TWEAK_HELP_TEXT=$(cat <<-EOF
# The CDA service (used for "type down" in some clients) is more
# efficient if it can check the directory change log before attempting
# to update the access tables that it uses.   One slow machines, it may
# also be worth uncommenting the CDA_CHECKTIME tweak to reduce the check
# interval from five minutes to an hour.
# CDA_CHECKTIME=60
EOF
)

IMAP_CONN_TWEAKS=("IMAP_CONNRATE_LIMIT=10" "IMAP_CONNECTION_LIMIT=500")
IMAP_CONN_TWEAKS_HELP_TEXT=$(cat <<-EOF
# These tweaks limit the number and rate of IMAP connections to the
# server. The IMAP_CONNECTION_LIMIT simply restricts the total number of
# connections to the server -- note that many IMAP clients have several
# connections for each IMAP session. The IMAP_CONNRATE_LIMIT restricts
# the rate at which clients can connect to the server, in this case, at
# most ten connections per second; if clients try to connect faster
# than that, the IMAP server simply slows down the rate at which it will
# accept new connections.
EOF
)

IMAP_IDLE_TWEAKS=("IMAP_IDLE_TIMEOUT=31")
IMAP_IDLE_TWEAKS_HELP_TEXT=$(cat <<-EOF
# The IMAP_IDLE_TIMEOUT tweak is the maximum time an IMAP connection
# will wait for a command before terminating the connection. The default
# setting, and the minimum required setting, is thirty minutes. Some
# clients will "refresh" their connection once every thirty minutes
# exactly -- but if they are a little bit late, the server drops their
# connection. Setting a timeout of 31 minutes avoids this problem.
EOF
)


LD_MSG_STORE_TWEAKS=("LD_CREATE_MESSAGE_STORE=TRUE")
LD_MSG_STORE_TWEAKS_HELP_TEXT=$(cat <<-EOF
# This tweak arranges for Local Delivery to automatically create a
# message store for users who have been created without one.
# Users who have been added using the bulk-add mechanism used by the
# wizard will not have a message store and so setting this tweak allows
# them to receive mail before they have been signed on initially.
EOF
)

MAX_SIGNON_TWEAKS=("MAX_SIGNON_PER_USER=54")
MAX_SIGNON_TWEAKS_HELP_TEXT=$(cat <<-EOF
# The maximum number of session monitor signon's per user e.g.
# the Core server, a satellite plus an Outlook session would count as 3
EOF
)

INDEXER_TWEAKS=(
    "IDX_DEBUG_LOG=false"
    "IDX_MINLOAD=4.0"
    "IDX_MAXLOAD=8.0"
    "INDEX_BROWSE_NICE=5"

)
INDEXER_TWEAKS_HELP_TEXT=$(cat <<-EOF
# indexer tweaks .
# IDX_DEBUG_LOG - enable or disable (by default) logging to file.
# The IDX_MAXLOAD setting will stop the indexer from indexing
# any further messages when the per-CPU load average goes above
# the defined value. The indexer will not resume indexing until the per-CPU
# load average goes below the value defined by IDX_MINLOAD.
# INDEX_BROWSE_NICE - sets it's running priority (nice value) for indexer
# process
EOF
)

APT_CMD=$(type -P apt)
if [ -z "$APT_CMD" ]; then
    APT_CMD=$(type -P apt-get)
fi

APTITUDE_CMD=$(type -P aptitude)
if [ -z "$APTITUDE_CMD" ]; then
  $APT_CMD install aptitude
  APTITUDE_CMD=$(type -P aptitude)
  if [ -z "$APTITUDE_CMD" ]; then
     echo "Could not find aptitude command."
     exit 127
  fi
fi

x86_64=false
if [ "$(uname -m)" == "x86_64" ]; then
    x86_64=true
fi

echo "System platform: $RELEASE_NAME"


CONFIGURE_POSTFIX=false
SMTP_PORT=25


INSTALLED_PACKAGES=$(dpkg --list | grep scalix | awk '{ printf $2 " " }')

if [[ $KERNEL_VERSION = *Ubuntu* ]]; then
    if [ "$DIST_VERSION" -lt 13 ]; then
        echo "Unfortunately this release of Ubuntu ($RELEASE_NAME) is not supported"
        exit 1
    fi
    SERVER_ARCH="ubuntu$DIST_VERSION"
fi

function remove_scalix() {

    if [ -z "$INSTALLED_PACKAGES" ]; then
        echo "There are no installed packages to remove."
    else
        if [ -n "$(type -P apt-get)" ]; then
            APTITUDE_CMD=$(type -P apt-get)
        fi

        $APTITUDE_CMD purge $INSTALLED_PACKAGES || exit $?
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
                dircount=$(eval expr "$dircount" + 1)
            done
            server_backup_folder="$server_backup_folder-$dircount"
        fi
        mv "$PWD/server" "$server_backup_folder"
    fi
    mkdir -p "$PWD/server"
    cd "$PWD/server"
    wget -i http://downloads.scalix.com/debian/?type=deb,gz
    cd "$PACKAGES_DIR"
}

if [ -n "$1" ]; then
    case "$1" in
        "--purge" ) remove_scalix;;
        "--update" ) download_packages;;
        * ) echo "Unknown argument."; exit 123;;
    esac
fi

if [ -d "$PWD/server" ]; then
  PACKAGES_DIR="$PWD/server"
fi

if ! hostname -f | grep -q -P "$FQDN_PATTERN";
then
    echo "Invalid fully-qualified hostname - '$FQDN' (your current FQDN hostname)"
    echo "The \"hostname\" command should return the short hostname, while the
\"hostname --fqdn\" command should return the fully-qualified hostname"
    echo
    exit 2
fi

if ! grep "$FQDN" /etc/hosts
then
    echo "File /etc/hosts does not contain '$FQDN' (fully-qualified hostname)."
    echo "Please add '$FQDN' to the /etc/hosts to proceed next step."
    echo
    exit 3
fi

IF_IPS=$(ip address | sed -En 's/127.0.0.1//;s/.*inet (addr:)?(([0-9]*\.){3}[0-9]*).*/\2/p')
FQDN_IP=$(hostname --ip-address)
if [[ $IF_IPS != *$FQDN_IP* ]]
then
    echo "FQDN ip address $FQDN_IP is not for local machine."
    echo -e "Ip addresses for machine interfaces (except localhost ip):\n$IF_IPS"
    exit 4
fi


function ask_for_mail_node_name() {
    read -p "What should be the name of your primary mail node? " MNODE
    if [ -z $MNODE ]; then
        echo "Mail node name is empty please provide valid mail node name"
        ask_for_mail_node_name
    fi
    if [[ $MNODE = *.* ]]; then
        echo "Mail node name '$MNODE' contains a dot, which is an invalid character"
        ask_for_mail_node_name
    fi
}

function config_mail_node_name() {
    if [[ $MNODE = *.* ]]; then
        echo "Current mail node name '$MNODE' contains a dot, which is an invalid character"
        ask_for_mail_node_name
    fi
    if [ -z $MNODE ]; then
        ask_for_mail_node_name
    else
        while true; do
            read -p "Do you whant to use '$MNODE' as your primary mail node name ( yes / no ) ?" yn
            case $yn in
                [Yy]* )
                    break
                ;;
                [Nn]* ) 
                    ask_for_mail_node_name
                    break
                ;;
                * ) echo "Please answer yes or no.";;
            esac
        done
    fi
}

# get real path
function realpath() {
  if [ ! -z "$1" ]; then
    readlink -f "$1"
  fi
}

# execute command and if returned status not 0 than exit
function safety_exec() {
    echo "executing command $1"
    eval "$1"
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
  $APTITUDE_CMD update
}

# check if package exists in folder
function find_sx_package () {
    local skip=''
    if ! $x86_64; then
        skip="*amd64*"
    elif [ "$1" == "server" ]; then
        skip="*i386*"
    fi
    local count=$(find "$PACKAGES_DIR" ! -name "$skip" -name "scalix-$1*[$SERVER_ARCH|all|$2].deb" | sort -Vru)
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

function add_server_tweaks() {
    local help_added=false
    local filename=$1
    shift
    local help_text=$1
    shift
    local options=("$@")
    for option in "${options[@]}"
    do
        local option_name="$(cut -d'=' -f1 <<<"$option")"
        if ! grep -q "^[[:blank:]]$option_name\|^$option_name" "$filename" ; then
            if [ "$help_added" = false ] ; then
                echo -e "\n$help_text" >> "$filename"
                help_added=true
            fi
            echo -e "$option" >> "$filename"
        fi

    done
}


function confiure_postfix() {
    local sxqueryadmin_pwd=$1
    if [ -z "$sxqueryadmin_pwd" ]; then
        echo "Password for sxaquery admin is empty. Can not continue."
        exit 3
    fi
    sxconfig --set -t smtpd.LISTEN='localhost:24'
    SMTP_PORT=24
    if [ ! -f /etc/postfix/main.cf ]; then
        safety_exec "cp /usr/share/postfix/main.cf.debian /etc/postfix/main.cf"
    fi
    local postconf_edit_cmd="$(type -P postconf) -e"
    local postmap_cmd=$(type -P postmap)
    # listen on all interfaces and ports
    safety_exec "$postconf_edit_cmd 'inet_interfaces = all'"
    safety_exec "$postconf_edit_cmd 'inet_protocols = all'"
    safety_exec "$postconf_edit_cmd 'parent_domain_matches_subdomains=debug_peer_list smtpd_access_maps'"

    safety_exec "$postconf_edit_cmd 'relay_domains=$FQDN'"
    safety_exec "$postconf_edit_cmd 'relay_recipient_maps=ldap:/etc/postfix/scalix_ldap_relay_recipient_maps.cf'"
    if [ ! -f "/etc/postfix/scalix_ldap_relay_recipient_maps.cf" ]; then
        cat > /etc/postfix/scalix_ldap_relay_recipient_maps.cf <<EOT
server_host = ldap://localhost:389/
search_base = o=Scalix
version = 3
bind_dn = cn=sxqueryadmin,o=scalix
bind_pw = $sxqueryadmin_pwd
query_filter = mail=%s
result_attribute = mail

EOT
    fi
    safety_exec "$postconf_edit_cmd 'transport_maps = hash:/etc/postfix/transport'"
    if [ ! -f /etc/postfix/transport ]; then
        echo "$FQDN $FQDN:24" > /etc/postfix/transport
        safety_exec "$postmap_cmd /etc/postfix/transport"
    fi

    safety_exec "$postconf_edit_cmd 'smtpd_sasl_auth_enable = yes'"
    safety_exec "$postconf_edit_cmd 'smtpd_sasl_local_domain = \$mydomain'"
    safety_exec "$postconf_edit_cmd 'smtpd_sasl_security_options = noanonymous'"
    safety_exec "$postconf_edit_cmd 'smtpd_sasl_path = smtpd'"
    safety_exec "$postconf_edit_cmd 'broken_sasl_auth_clients = yes'"
    safety_exec "$postconf_edit_cmd 'smtpd_sasl_authenticated_header = no'"
    safety_exec "$postconf_edit_cmd 'smtpd_client_restrictions = permit_mynetworks        check_client_access hash:/etc/postfix/access       permit_sasl_authenticated        reject_unknown_client permit'"
    if [ ! -f /etc/postfix/access ]; then
        touch /etc/postfix/access
        safety_exec "$postmap_cmd /etc/postfix/access"
    fi
    safety_exec "$postconf_edit_cmd 'smtpd_sender_restrictions = permit_mynetworks    permit_sasl_authenticated    reject_invalid_hostname      reject_non_fqdn_hostname     reject_non_fqdn_recipient  reject_non_fqdn_sender     reject_unknown_sender_domain   reject_unknown_recipient_domain     reject_unauth_destination permit'"
    safety_exec "$postconf_edit_cmd 'smtpd_recipient_restrictions = permit_mynetworks    permit_sasl_authenticated    reject_unauth_destination'"
    safety_exec "$postconf_edit_cmd 'compatibility_level = 2'"
}

function use_https_for_webapp() {
    while true; do
        read -p "Do you whant to use secure connection HTTPS instead HTTP for $1 ( yes / no ) ?" yn
        case $yn in
            [Yy]* )
                for i in $(sxtomcat-get-mounted-instances) ; do
                    sxtomcat-webapps --forcehttps "$i" "$2"
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
  if valid_ip "$ip"; then EXTERNAL_IP=$ip; else get_external_ip; fi
}

# check directory if it contains scalix packages
function check_package_dir() {
  if [ -z "$1" -o ! -d "$(realpath "$1")" ]; then
    echo "Folder $1 does not exists or not readable. "
    read -p "Please specify another folder with deb packages: " dir
    check_package_dir "$dir"
  fi
  local dir=$(realpath "$1")
  local pkgs_count=$(find "$dir" -maxdepth 1 -type f -name 'scalix*\.deb' | grep -v ^l -c)
  if [ "$pkgs_count" = "0" ]; then
    echo "Folder $1 does not contain deb packages"
    read -p "Please specify another folder with deb packages: " dir
    check_package_dir "$dir"
  fi
  PACKAGES_DIR=$dir
}

function collect_dependencies_from_package() {
    local PKG=$1
    local OIFS=$IFS # store old IFS in buffer
    IFS=','
    echo "Collecting dependencies for $PKG"
    for section in 'Depends' 'Pre-Depends' ; do
        for item in $(dpkg -f "$PKG" $section) ; do
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
        if [ -n "$(dpkg -l exim4 | grep ii)" ]; then
            while true; do
                echo "It seems that Exim4 is intalled at your system."
                echo "Scalix does not support this MTA you need to remove it before installing scalix."
                read -p "Do you want to remove Exim4? ( yes / no ) ?" yn
                case $yn in
                    [Yy]* )
                        safety_exec "$APT_CMD purge exim*"
                        # stop all services
                        #service exim4 stop
                        collect_dependencies
                        break
                    ;;
                    [Nn]* )
                        break
                    ;;
                    * ) echo "Please answer yes(y) or no(n).";;
                esac
            done
        fi
        if [ ! -d /opt/scalix/bin -a "$(lsof -i :25 | wc -l)" -le 0 ]; then
            while true; do
                echo "It seems that your system does not have installed and configured Message(Mail) Transfer Agent (MTA)."
                echo "We can install sendmail and configure it for you. But you can skip sendmail installation and "
                echo "set up Postfix manually following this rules LINK_TO_WIKI"
                read -p "Do you want to install Sendmail and automatically configure it to work with scalix? ( yes / no ) ?" yn
                case $yn in
                    [Yy]* )
                        DEPENDENCIES="$DEPENDENCIES libmilter1.0.1:i386 sendmail:all sendmail-cf:all"
                        break
                    ;;
                    [Nn]* )
                        DEPENDENCIES="$DEPENDENCIES postfix libsasl2-modules-ldap sasl2-bin libsasl2-2 postfix-ldap"
                        CONFIGURE_POSTFIX=true
                        break
                    ;;
                    * ) echo "Please answer yes(y) or no(n).";;
                esac
            done
        fi
        collect_dependencies_from_package "$SCALIX_SERVER_PACKAGE"
    fi

    SCALIX_TOMCAT_PACKAGE=$(find_sx_package "tomcat")
    if [ -n "$SCALIX_TOMCAT_PACKAGE" ]; then
      if [ -z "$(type -P java)" ]; then
        DEPENDENCIES="$DEPENDENCIES default-jdk"
      fi

      if ! dpkg-query -l apache2 2>&1 | grep -q ii;
      then
        DEPENDENCIES="$DEPENDENCIES apache2"
      fi
    fi
    local sx_postgres=$(find_sx_package "postgres")
    if [ -n "$sx_postgres" ]; then
      collect_dependencies_from_package "$sx_postgres"
    fi

    if $x86_64; then
        # debian
        DEPENDENCIES=${DEPENDENCIES//mailutils:i386/mailutils}
        DEPENDENCIES=${DEPENDENCIES//openssl:i386/openssl}
    fi

}

# install scalix packages
function install_sx_package() {
  echo "Installing $1"
  for entry in $2
  do
    sx_package=$(find_sx_package "$entry" "$3")
    if [ -f "$sx_package" ]; then
        safety_exec "dpkg -i $4 \"$sx_package\""
    else
        echo "Could not find package $entry. Installation failed."
        exit 2
    fi
  done
}

check_package_dir "$PACKAGES_DIR"

echo "Force add i386 architecture if needed"
dpkg_add_i386_arch

collect_dependencies "$PACKAGES_DIR"


if [ -n "$DEPENDENCIES" ]; then
  echo "Before installing Scalix you must install following dependencies"
  echo
  echo "$DEPENDENCIES"
  echo
  $APTITUDE_CMD install $DEPENDENCIES

  error=$?
  if test $error -gt 0
  then
      echo "Error while installing dependencies $1"
      exit $error
  fi
  echo "We need to insure that all dependencies are installed"
  echo
  echo "$DEPENDENCIES"
  $APTITUDE_CMD install $DEPENDENCIES
fi

# check java version
JAVA_VERSION=`$(type -P java) -version 2>&1 | awk -F '\"' '/version/ {print $2}'`
if [[ ! "$JAVA_VERSION" =~ ^(1\.[8|9|10])|9(.*)|10(.*)$ ]];
then
    echo "It seems that you are using not supported JRE."
    echo "We determined that current JRE version is : '$JAVA_VERSION'"
    echo -e "We tried to install 'default-jdk' but it seems that its \nprovides lower version that we require."
    echo "Please install JRE 1.8 or 10(1.10) manually. "
    exit 124
fi

if [ -n "$SCALIX_SERVER_PACKAGE" ]; then

  SENDMAILCONFIG=$(type -P sendmailconfig)
  if [ -z "$SENDMAILCONFIG" ]; then
      echo "Could not find sendmailconfig utility skiping sendmail configuration check"
  else
      SENDMAILCONFIG_OUTPUT=$($SENDMAILCONFIG --no-reload 2>&1 <<-@@ | grep 'ERROR:'
Y
Y
@@
)
    if [[ $SENDMAILCONFIG_OUTPUT = *ERROR:* ]]; then
        echo "Your currnet sendmail configuration has errors."
        echo "Please resolve following errors in sendmail configuration"
        echo "to proceed  with scalix server installation"
        echo -e "\n$SENDMAILCONFIG_OUTPUT\n"
        exit 5
    fi
  fi

  install_sx_package "installing libical" "libical" "$SERVER_ARCH"
  install_sx_package "libical, chardet and iconv" "chardet iconv" "$SERVER_ARCH"
  install_sx_package "Scalix server core" "server" "$SERVER_ARCH" "$DPKG_ARGS"

  export PATH=/opt/scalix/bin:$PATH

  read -s -p "Please enter the admin password for the Scalix admin user (sxadmin)? " admpwd
  echo
  read -s -p "Please enter a password for the ldap query user? " ldappwd
  echo
  #configure mail node name
  config_mail_node_name

  #configure scalix server core
  echo "Configuring scalix server"
  ommakeom
  sxconfig --set -t general.usrl_cn_rule='G S'
  sxconfig --set -t general.usrl_authid_rule='l@'
  sxconfig --set -t orniasys.name_part_1='"C" <S>' -t orniasys.domain_part_1="$LDOMAIN" # com
  omaddmn -m "$MNODE"
  omrc -n
  omadmidp -a -s 66000 -n 100
  omaddu -n "sxadmin/$MNODE" --class limited -c admin -p "$admpwd" sxadmin
  omconfenu -n "sxadmin/$MNODE"
  omlimit -u "sxadmin/$MNODE" -o -i 0 -m 0
  omaddu -n "sxqueryadmin/$MNODE" --class limited -c admin -p "$ldappwd" "sxqueryadmin@$FQDN"
  omaddpdl -l "ScalixUserAdmins/$MNODE"
  omaddpdl -l "ScalixUserAttributesAdmins/$MNODE"
  omaddpdl -l "ScalixGroupAdmins/$MNODE"
  omaddpdl -l "ScalixAdmins/$MNODE"
  CONFIGURE_POSTFIX=true
  if $CONFIGURE_POSTFIX; then
    confiure_postfix "$ldappwd"
  fi
  exit
  omon -s all
  
  instance_dir="$(omcheckgc -d)"

  add_server_tweaks "$instance_dir/sys/general.cfg" "$UAL_SIGNON_TWEAK_HELP_TEXT" "${UAL_SIGNON_TWEAKS[@]}"
  add_server_tweaks "$instance_dir/sys/general.cfg" "$CDA_TWEAK_HELP_TEXT" "${CDA_TWEAKS[@]}"
  add_server_tweaks "$instance_dir/sys/general.cfg" "$IMAP_CONN_TWEAKS_HELP_TEXT" "${IMAP_CONN_TWEAKS[@]}"
  add_server_tweaks "$instance_dir/sys/general.cfg" "$IMAP_IDLE_TWEAKS_HELP_TEXT" "${IMAP_CONN_TWEAKS[@]}"
  add_server_tweaks "$instance_dir/sys/general.cfg" "$LD_MSG_STORE_TWEAKS_HELP_TEXT" "${LD_MSG_STORE_TWEAKS[@]}"
  add_server_tweaks "$instance_dir/sys/general.cfg" "$MAX_SIGNON_TWEAKS_HELP_TEXT" "${MAX_SIGNON_TWEAKS[@]}"
  add_server_tweaks "$instance_dir/sys/general.cfg" "$INDEXER_TWEAKS_HELP_TEXT" "${INDEXER_TWEAKS[@]}"

fi

if [ -n "$SCALIX_TOMCAT_PACKAGE" ]; then
  install_sx_package "Tomcat Connector" "tomcat-connector" "all"
  install_sx_package "Scalix Tomcat " "tomcat_" "all"
  install_sx_package "All available web applications" 'res swa wireless platform sac postgres sis' "all"
  if [ -d "/opt/scalix-postgres/bin" ]; then
    export PATH=/opt/scalix-postgres/bin:$PATH
  fi
  export PATH=/opt/scalix-tomcat/bin:$PATH
fi


dbpwd=""
echo "Configuring scalix-postgres"
if [ -d "/opt/scalix-postgres/bin" ]; then
    read -s -p "Please enter a password for the db user? " dbpwd
    echo
    sxpsql-setpwd "$dbpwd"

    get_external_ip
    sxpsql-whitelist "$EXTERNAL_IP"
    sxpsql-reconfig
fi

base=$(realpath "$(sxtomcat-get-inst-dir)/../")
if [ -d "$base/caa/scalix.res/config" ]; then
    echo "$dbpwd" > "$base/caa/scalix.res/config/psdata"
fi

echo "Setting up settings for web applications"

files="$base/webmail/swa.properties \
       $base/caa/scalix.res/config/ubermanager.properties \
       $base/res/config/res.properties \
       $base/platform/platform.properties \
       $base/sis/sis.properties \
       $base/caa/config/krblogin.conf \
       $base/res/config/krblogin.conf \
       $base/wireless/wireless.properties"

for file in $files; do
  sed -e "s;%LOCALDOMAIN%;$LDOMAIN;g" \
      -e "s;%LOCALHOST%;$FQDN;g" \
      -e "s;swa.platform.enabled=false;swa.platform.enabled=true;g" \
      -e "s;swa.email.smtpServer=$FQDN;swa.email.smtpServer=$FQDN:$SMTP_PORT;g" \
      -e "s;%PLATFORMURL%;$FQDN;g" \
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
      -e "s;%SMTPHOST%;$FQDN:$SMTP_PORT;g" \
      -e "s;%LDAPPORT%;389;g" \
      -e "s;%DBHOST%;$FQDN:5733;g" \
      -e "s;%DBPASSWD%;$dbpwd;g" \
      -e "s;%INDEX-WHITELIST%;$EXTERNAL_IP,127.0.0.1;g" \
      -e "s;%SEARCH-WHITELIST%;$EXTERNAL_IP,127.0.0.1;g" \
      -e "s;%INDEXADMIN-WHITELIST%;$EXTERNAL_IP,127.0.0.1;g" \
      "$file" > "$file.neu"
  cp -rf "$file"  "$file$(date +%F_%R_%S)"
  mv "$file.neu" "$file"
  email_domain=$(grep swa.email.domain "$base/webmail/swa.properties")
  if [ -z "$email_domain" ]; then
    echo "swa.email.domain=$FQDN" >> "$base/webmail/swa.properties"
  fi

done

if dpkg-query -l scalix-sac | grep -q ii ;
then
    use_https_for_webapp "Scalix Administration console", 'sac'
fi

if dpkg-query -l scalix-swa | grep -q ii ;
then
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

SCALIX_PATH="export PATH=\$PATH:/opt/scalix/bin:/opt/scalix/diag:/opt/scalix-tomcat/bin:/opt/scalix-postgres/bin"
echo $SCALIX_PATH > /etc/profile.d/scalixpathscript.sh
echo $SCALIX_PATH > /root/.profile
eval $SCALIX_PATH
cat << EOF

############################################################
#
# FINISHED !!
#
# You should now be able to access your scalix installation at:
#
# Admin Console: http://$FQDN/sac
# Webmail:       http://$FQDN/webmail
# API:           http://$FQDN/api/dav
#
############################################################

EOF
sleep 2
