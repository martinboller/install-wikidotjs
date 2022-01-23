# Snipe-IT Open Source Asset Management Installation script

### Bash script automating the installation of Snipe-IT Open Source Asset Management on Debian 11
Most of the Snipe-IT specific details, shamelessly lifted from the installation scripts created by Mike Tucker mtucker6784@gmail.com

<img src="./images/snipe-it-logo-xs.png" alt="https://snipeitapp.com/"/>


For more information about the awesome Snipe Asset Management Solution, go to https://snipeitapp.com/


## Vagrantfile and bootstrap.sh for use with Vagrant and Virtualbox

### Known issues:
  - Currently using self signed cert, but the CSR is there so send that to an Issuing CA instead
  - Not tested with anything else than Debian 11 (Bullseye)

### Latest changes 
#### 2022-01-09 - Initial version
  Version 1.00

### Production Installation
Prerequisite: A Debian 11 server up and running.
- Run git clone https://github.com/martinboller/snipeIT-Install.git
- Change directory into ./snipeIT-Install/
- Execute ./install-snipe.sh
- Connect to https://nameofsnipeserver/ in your favorite browser and follow the guide to do the initial configuration of Snipe-IT.

The above procedure should install everything needed to run Snipe-IT.


## Quick installation - If you just want to get on with it

>**Important: Do NOT use the process below for production, as Vagrant leaves some unfortunate security artifacts behind. The install-snipe.sh alone can be used on a known secure installation of Debian 11, or you could remove Vagrant artifacts (the former is preferred)**

### Packages required
All that is needed to spin up test systems is:
 - VirtualBox https://www.virtualbox.org/
 - Vagrant https://www.vagrantup.com/downloads
 
### Installation
#### VirtualBox
 - Install VirtualBox on your preferred system (MacOS or Linux is preferred) as described on the VirtualBox website
 - Install the VirtualBox Extensions

Both software titles can be downloaded from https://www.virtualbox.org/
They can also be added to your package manager, which help with keeping them up-to-date. This can also easily be changed to run with VMWare.
 
#### Vagrant
 - Install Vagrant on your system as described on the Vagrant website

Vagrant is available at https://www.vagrantup.com/downloads
 
#### Testlab
Prerequisite: A DHCP server on the network, alternatively change the NIC to use a static or NAT within Vagrantfile.
 - Create a directory with ample space for Virtual Machines, e.g. /mnt/data/VMs
 - Configure VirtualBox to use that directory for Virtual Machines by default.
 - Change directory into /mnt/data/Environments/
 - Run git clone https://github.com/martinboller/snipeIT-Install.git
 - Change directory into /mnt/data/Environments/snipeIT-Install/
 - Execute vagrant up simo<sup>1</sup> and wait for the OS to install

<sup>1</sup>https://www.simohayha.com/

You may have to select which NIC to use for this e.g. wl08p01
 
The first install will take longer, as it needs to download the Vagrant box for Debian 11 (which this build is based on) first, however that’ll be reused in subsequent (re)installations.