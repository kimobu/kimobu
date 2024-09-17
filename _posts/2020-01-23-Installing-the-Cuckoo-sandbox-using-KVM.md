---
title: Installing the Cuckoo Sandbox Using KVM
date: 2020-01-23
categories: []
tags: [homelab]
---
The [Cuckoo](https://cuckoosandbox.org) project provides a safe environment in which to execute malware (also called "detonating"). I will be using Cuckoo as part of a malware analysis class. There are [several](https://www.cybrary.it/blog/0p3n/cuckoo-installation-guide-malware-sandboxing/) [guides](https://medium.com/@sainadhjamalpur/build-your-own-cuckoo-sandbox-installation-guide-3fc44b03a622) [that](https://www.sanjaysaha.info/blog/installation-of-cuckoo-sandbox-in-windows-10/) [you](https://tom-churchill.blogspot.com/2017/08/setting-up-cuckoo-sandbox-step-by-step.html) could follow to setup Cuckoo, but almost all of the ones that I found used VirtualBox as a hypervisor. Since I have a homelab running on KVM, I wanted to install Cuckoo to use that as well. There is no groundbreaking information in this post, but it consolidates information that I had to find from several different sources while troubleshooting.

The overall steps that this post covers are:
1. Configuring nested virtualization
2. Installing & configuring a Cuckoo host
3. Creating a sandbox virtual machine
4. Configuring the sandbox

# Configuring nested virtualization
I use oVirt to run my homelab, and there are a few tasks which need to be performed to configure the environment for nested virtualization. First, the hosts need to have the `kvm-intel.nested` kernel option enabled. This can be accomplished by navigating to the host, clicking Edit, going to the Kernel tab, and checking the Nested Virtualization checkbox. Second, the `vdsm-hook-nestedvt` package needs to be installed via Yum. Once those tasks are accomplished, rebooting the host should finish configuration. This can be confirmed by running the below command, which should output "Y".

```cat /sys/module/kvm_intel/parameters/nested```
# Installing & configuring a Cuckoo host
Cuckoo has several software requirements that need to be fulfilled. Most of these can be installed via `apt` or `pip`. I originally attempted to use the [Cuckoo Autoinstall](https://github.com/NVISO-BE/SEC599/blob/master/cuckoo-install.sh) script, but there were just enough differences from when that was created to the current Cuckoo architecture (thinking specifically of virtual environments) and between Virtualbox and KVM, that I ended up doing most of the steps manually and then documenting it as a script. At the bottom of this post is a link to that shell script which will automate package installation and much of the sandbox creation.

Cuckoo recommends a Debian based Linux distribution. I installed Ubuntu 18.04 to a virtual machine. My VM disks are stored on a one terabyte drive. The sandbox VM which Cuckoo will run will have an 80GB disk; keeping this on the data disk would consume a fair amount of space. Instead, I opted to keep the sandbox's disk on a volume exported by FreeNAS. My initial attempt at hosting this over a Samba share did not work. `qemu-img` attempts to obtain a lock on the file, and some bug prevents this lock from being acquired. Using NFS worked, but required some additional [options](https://forum.opennebula.org/t/nfs-v3-datastore-and-failed-to-lock-byte-100/7482):

```bash
freenas.kimobu.space:/mnt/Pool0/Datastore   /mnt/datastore nfs    hard,intr,nolock,nfsvers=3,tcp,timeo=1200,rsize=1048600,wsize=1048600,bg 0 0
```
# Creating a sandbox virtual machine

With networked storage working, the disk for the sandbox could then be created. `qemu-img` is used to create an 80GB qcow2 format disk.
```bash
qemu-img create -f qcow2 /mnt/datastore/vm/Windows7Sandbox/disk1.qcow2 80G
```

With the disk created, I could create a virtual machine in which malware will be executed. While KVM powers oVirt, I did not previously have the need to control KVM manually. This step involved learning how to make, start, stop, and snapshot VMs via the command line. To begin, a virtual machine is created which contains the disk, a CDROM loaded with the Windows 7 installer, and a floppy with the Virt I/O drivers:
```
VMNAME=Windows7Sandbox
DISKPATH=/mnt/datastore/vm/Windows7Sandbox/disk1.qcow2
ISOPATH=/mnt/datastore/iso/
CDROM=Windows7Installer.iso
VIRTIO=virtio-win_amd64.vfd

virt-install --name=$VMNAME --os-type=windows --os-variant win7 --network network=default,model=virtio --disk path=$DISKPATH,format=qcow2,device=disk,bus=virtio --cdrom $ISOPATH$CDROM --disk path=$ISOPATH$VIRTIO,device=floppy --graphics vnc,listen=0.0.0.0 --ram=2048 --vcpus 2
```
Even though the qcow2 format is specified, my version of `virt-install` created a VM which assumed the disk was raw. The actual VM configuration can be checked with `virsh dumpxml $VMNAME`. If needed, `virsh edit $VMNAME` can be used to modify the configuration. My workflow for this ended up being:
```
virsh destroy $VMNAME
virsh edit $VMNAME
# Change disk format
# add <boot dev='cdrom'/> in the <os> tag
# Change <emulator> to use /usr/bin/kvm
virsh start $VMNAME
```
At this point, the VM has the correct hardware settings. In order to save others from having to deal with this step, I exported the VM's configuration to an XML file, and the script that I have provided will use that to create the VM.

# Configuring the sandbox
Once the sandbox VM is up and running, I could VNC into it through port 5900 exposed by the Cuckoo VM. The first step is installing the sandbox operating system which in this case is Windows 7. The only special step here is loading the VirtI/O drivers at the install destination screen to enable the disk and network devices. After the operating system is installed, follow the [Cuckoo docs](https://cuckoo.sh/docs/installation/guest/index.html).

For my purposes, the additional software which I installed included:
* Microsoft Office
* Adobe Reader

Additional configuration was needed to:
* Disable User Account Control
* Enable macros by default for Office documents

I missed the bolded part of the Cuckoo docs, so I will reiterate here that when snapshotting the VM, it needs to be **running**.

# Wrapping up
The last bit was creating startup/shutdown scripts. In the Autoinstall script that I referenced earlier, shell scripts are used to control Cuckoo. Since I have a newer Ubuntu machine, I created Systemd unit files for the Cuckoo engine, its API, and its web service. After those services are started, files can be submitted to the engine for analysis.
![cuckoo](/content/images/2020/02/cuckoo.png)

There is still a lot of learning for me to do on this platform, but as the screenshot above shows, you can get quick wins even with this minimal install. Future things to tune and enable include:
* Get Yara working
* Enable Elasticsearch
* Use Volatility for memory forensics
* Reducing the VM artifacts to reduce the impact of anti-analysis code

The files to enable smoother Cuckoo installation on KVM can be found on [Github](https://github.com/kimobu/cuckoo-kvm)
