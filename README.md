Debian-installer
================

Scalix Installer for Debian 7( Wheezy), Ubuntu 13.04 and 14.04

### Requiments ###
1. Debian 7, Ubuntu 12.04 or 13.04 (i386, x86_64).
2. at least 600Mb of RAM.
3. 300Mb free space on  hard drive.
4. valid FQDN hostname. [Fully qualified domain name(FQDN)][1]
5. Oracle Java runtime environment(minimal version 1.6, maximum version 1.8.X). JRE from IBM is not supported. Scalix does not support openJDK on production servers, however it is possible to use openJDK on low-load non-production installations.

Step be step how to install scalix on debian [How to: Install Scalix on Debian][2].

[Scalix-Web-application-performance-tuning](https://github.com/scalix/Debian-installer/wiki/Scalix-Web-application-performance-tuning#scalix-web-application-performance-tuning)

### Installer arguments ###
1. --purge - removes Scalix from your system and deletes all associated data.

2. --update - downloads latest Scalix deb packages for installs them.


### Usage ###
Clone this repository
```sh
~#git clone git@github.com:scalix/Debian-installer.git
```
Go to the directory
```sh
~#cd ./Debian-installer
```
if you don't have deb packages run script with  '--update' argument (it will download latest deb package) under root user
```sh
~#./deb_installer.sh --update
```
otherwise (under root user)
```sh
~#./deb_installer.sh
```
All necessary dependencies will be automatically checked and you must just confirm to install them.

  [1]: http://en.wikipedia.org/wiki/Fully_qualified_domain_name
  [2]: https://www.flomain.de/2015/07/how-to-install-scalix-on-debian/
