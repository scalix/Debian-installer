Debian-installer
================

Scalix Installer for Debian 7( Wheezy), Ubuntu 12.04 and 13.04

### Requiments ###
1. Debian 7, Ubuntu 12.04 or 13.04 (i386, x86_64).
2. at least 600Mb of RAM.
3. 300Mb free space on  hard drive.
4. valid FQDN hostname. [Fully qualified domain name(FQDN)][1]
5. Oracle Java runtime environment(minimal version 1.5, maximum version 1.7.X). JRE from IBM is not supported. Scalix does not support openJDK on production servers, however it is possible to use openJDK on low-load non-production installations.  Please visit wiki page [Working with JRE][2]  for more details about Java/JDK and Scalix.

### Installer arguments ###
1. --purge  - removes scalix from you system and deletes all data which were created.

2. --update - will download latest deb packages for installation and proceed them  to install


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

### Issues ###
1.  For Ubuntu 12.04 x86_64 scalix-server.deb has incorrect dependencies, so for now script will ignore all dependencies errors (it will show appropriate confirmation)
2. due to some dependencies openssh-server can be removed from you system. So please after installation check if  openssh-server is installed.
```
aptitude install openssh-server
```
or 
```
apt-get install openssh-server
```

### Conatct ###
If you have questions or proposition please contact with abr@scalix.com


  [1]: http://en.wikipedia.org/wiki/Fully_qualified_domain_name%20Fully%20qualified%20domain%20name%28FQDN%29
  [2]: http://scalix.com/wiki/index.php?title=HowTos/Working_with_JRE
