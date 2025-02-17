# Linux essentials
```
hostname
uname -a
whoami , who , w
ip addr , ifconfig
ip neigh , arp
ip route , route
ss , netstat
nft list tables , iptables -L 
sudo -l
```

# Variables
  * strings of characters with an assigned value
  * $ to access value
  * a=(100)
  * echo $ to print

# redirection
  * standard input = 0
  * standard ouput = 1
  * standard error = 3 (default for failed commands or a numbered string)
  *  *2>/dev/null*


# linux filesystem
  * / -> root directoryn
  * /bin -> essential binaries
  * /home -> users home directory
  * /etc -> everything configurable
  * /var -> variable data files
  * /tmp -> temporary files, everyone has write permissions

# files and folders
  * drwx------  -> d = directory
  * -rwx------  -> - = file
```
file
strings <file> ##get human readable text
```

# Linux users
  * id  -> identify uid, gid, groups
      * User/owner, groups, others, owner, group owner
      * rwx       , rwx   , rwx   , student, student
      * 421       , 421   , 421
      * 4=read, 2=write, 1=execute
  ```
cat /etc/passwd
#student:    x    :1001:1001::/home/student:/bin/bash
#username
# x = password placeholder
# 1001 = UID
# 1001 = GUID
# comment
# shell
```

# Linux Groups
```
cat /etc/groups
# group: PW placeholder: x : x
```

# Sticky Bit
* User has write access
* they can delete any file
* sticky bit removes the ability to delete files unless the user attempting is the owner of the file

# SUID/ SGID
* -rwsr-xr-x
* executable permissions are passed based on the location of s

# String manipulation

GREP
```
grep
# search strings in a file
# -v to filter out specific string

##Identify heresy by comparing the Inquisition_Targets file to members of the guardsmen group.
grep -Ff <(sort <file of targets>) <cat /etc/group | grep <group> | awk -F ':' '{print $4}' | sed -e $'s/,/\\\n/g')
```

AWK
* re-format or select sections of text based on delimiters
```    
awk
ps -elf | awk -F ' ' '{$3,$4,$11,$15}'
#pull specific columns from process list

cat /etc/passwd | awk -F ':' '{print$1,$3,$4}'
awk 'NR==420,NR==1337' <file> #outputs lines 420-1337
sudo cat /etc/shadow |awk -F[:$] '$1 == "root" {print $5}' | wc
```

SED
* manipulates output does not change the file, instead of filtering or formatting
```
sed
cat /etc/passwd | grep student | sed s/student/Desmond/g
# replaces student with desmond
```

REGEX
```
cat <file> | grep -P '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'  ## regex for ip address
cat <file> | grep -P '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
cat <file> | grep -P '^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$' #for mac addresses
cat numbers | grep -P '(^([0-7]{1}[0-9a-fA-F]{1})[:.-]?([0-9a-fA-F]{2}[:.-]?){4}[0-9a-fA-F]{2}$)|(^([89abcedf]{1}[0-9a-fA-F]{1})[:.-]?([0-9a-fA-F]{2}[:.-]?){4}[0-9a-fA-F]{2}$)'
```

# FIND
  ```
find /media/Bibliotheca -type f -name ".*" ##find hidden files with "."
find /home -type f -exec wc -l {} + | sort -n -r
```
    
# MAN
```
man -k <string>
man --where cat
```

# openssl
```
openssl aes-128-cbc -d -in cipher -out cipher1
-determine salt and password hash in /etc/shadow
```

# hash a file
```
sha512sum -b <file>
md5sum <file>
```

## daemons == services


# BIOS
* MBR -> master boot record
* grub -> boot loader
* linux kernel
* init

# UEFI
* GPT -> GUID Partition Table
* grub.efi -> Grand Unified Boot Loader

# 1st Stage Bootloaders
* MBR and GPT -> locate the 2nd stage bootloader GRUB
  * bootstrap -> 446 bytes
  * partition 1 -> 16
  * partition 2 -> 16
  * partition 3 -> 16
  * partition 4 -> 16
  * boot signature -> 2

# xxd
* examine contents of mbr
```
sudo xxd -1 512 -g 1 /dev/sda
```

# dd
* make copy of MBR
```
dd if=/dev/vda of=MBRcopy bs=<# of bytes> count=<# of times>
#identify specific work in MBR
dd if=mbroken bs=4 skip=98 count=1 | hexdump -C
dd if=mbroken of=mbroken1 bs=4 skip=98 count=1
dd if=<in file> of=<outfile> bs=<bite size used> skip=<# of bytes to skip based on byte size> count=<# of bytes to retrieve>
```        

# GUID partition table (GPT) (UEFI)
* Many boot sectors
* Supports 128 separate physical partitions
* Up to 9 zettabytes

# 2nd stage bootloader (GRUB)
* loads the linux kernel
  * Stage 1
    * boot.img -> first 440 bytes of the MBR loaded
  * stage 1.5
    * core.img -> in MBR between bootstrap and first partition and loads
  * stage 2
      * /boot/grub/i386-pc.mod -> load grub menu
      * /boot/grub/grub.cfg -> linux kernels available to load
  * grub uses the command 'linux' to load the kernel, file after the command is the kernel type
        -search by:
    ```
    cat /boot/grub/grub.cfg | grep linux
    ```

# systems using GPT
* stage 1 grubx64.efi loads /boot
* stage 2 /boot/grub/x86_64-efi/normal.mod

# Linux Kernel - > complete control of system resources
* Monolithic Kernel -> system calls all functionality to the user
```
ltrace -S cat /etc/passwd
```
* modular -> extension to base functionality
```
ltrace -S lsmod
```

# Init -> /sbin/init how do I fix this?
* process of bringing the system to a desired level of functionality
    * main initialization daemons -> Systemd and SysV
    0    ->    Halt
    1    ->    Single User
    2    ->    Multi-user mode
    3    ->    Multi-user mode with networking
    4    ->    not user/user-definable
    5    ->    multi-user mode with net-working and GUI desktop
    6    ->    Reboot

# Sysv init daemon (legacy)
* /etc/init spawns /sbin/init specified run level in /etc/inittab
* run levels in /etc/rc*.d
  * Run levels -> scripts
            K = kill
            S = Start
            the 2 digits that follow dictate the order
    ```
    #list the contest of /etc/rc3.d
    #S01 acpid is symbolic link to ../init.d/acpid
    #list contest of /etc/rc1.d
    #shows K01 for daemons
    ```
    
# Systemd
* PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"
```
        #list symbolic link
            ls -lisa /sbin/init
        /sbin/init -> /lib/systemd/systemd
        ##list units in tree form
            systemctl list -dependenies graphical.target
        ##show wants to units
            systemctl show -p Wants graphical.target
        ##list every individual unit file
            systemctl list-unit-files
        ##cat unit file
            systemctl cat graphical.target
```

# Target units
* Systemd target units are a set of value=data pairs to create processes in a set order on the system.
```
cat /lib/systemd/system/default.target | tail -n 8
```
* service units
  * create processes when called by target units
```
cat /etc/systemd/system/display-manager.service
```

# POST Boot
* /etc/environment file -> sets Global Variables accessible to every user ##$PATH Variable
* /etc/profile file -> load whenever a user loggs on ### location of persistence
    * executes /etc/bash.bashrc -> executes and scripted names *.sh in /etc/profile.d
* .bash_profile and .bashrc
    * located in every users home directory /home/<name>
      * .bash_profile -> interactive login shell
      * bashrc -> non-login shell (not prompted for creds)


# persistence
* /etc/init
* /etc/profile
* .bash_profile
* .bashrc
* /etc/environment
* rc*.d
* daemons == services #all daemons are orphans
* /sbin/init (adoptes ophaned daemons)

# logging
* /usr/sbin/rsyslogd #stardard logging binary across *nix systems

# search for sysv vs. systemd
* One way is to check for the existence of three directories:
        * /usr/lib/systemd tells you you're on a systemd based system.One way is to check for             the existence of three directories:
  * /usr/lib/systemd tells you you're on a systemd based system.
  * /usr/share/upstart is a pretty good indicator that you're on an Upstart-based system.
  * /etc/init.d tells you the box has SysV init in its history.
 

# Process listing
```
ps -elf # view running processes 
        -e #Displays every process on the system
        -l #Lists processes in a long format
        -f #Does a full-format listing

ps --ppid 2 -lf
    #Displays only kthreadd processes (so, only kernel-space processes)
     Processes spawned from kthreadd will always have a PPID of 2

ps --ppid 2 -Nlf
      #Displays anything except kthreadd processes (so, only user-space processes)
      #-N Negates the selection

ps -fp <pid> OR ps aux | grep <name>
      #Find arguments passed to a daemon
        
ps -elf --forest #Displays processes in an ASCII tree
        # --forest ASCII art process tree
        #All kernel processes are fork()ed from [kthreadd] (PID = 2)
        #All user processes are fork()ed from /sbin/init (PID = 1)
```

# TOP
*process list live capture
```
top
#SHIFT + V -> shows tree format
```

# HTOP
*more human-readable version of top
 ```
htop
#F5 -> tree
#Z in the S column = zombie
```

# Kernel Space
* Area of virtual memory where kernel processes run
* Unrestricted access to processor and main memory
  
# User Space
* restricts access to a subset of memory and safe CPU operations

# Privilege Rings
  Ring 0 = kernel
  Ring 1 = drivers
  Ring 2 = drivers
  Ring 3 = Applications

# Process Ownership
* User ID (UID)
    * Overarching ID (RUID will reclect this ID if something is run with different permissions)
* Effective User ID (EUID)
    * user whose file access permissions are used by the process
* Real User ID (RUID)
    * who you actually are
    * who actually spawned the process

# System calls
1. original process ask kernel to create another process (fork())
2. process then fork()
3. identical copy of original process after fork()
4. identical copy performs exec() system call
5. kernel replaces identical copy of original process with that of the new process

   *fork()
        * creates new process-e #Displays every process on the system

    *exec()
        * when a process calls exec, the kernel starts program, replacing the current process

# signals 
* software interrupts sent to a program to indicate that an important event has occured

# Foreground and Background process
* Orphan Processes
    * a running process whose parent process has finished or terminated and is adopted by
* sbin/init and will have a PPID of 1
    * disown -a && exit #close a shell or terminal and force all children to be adopted

* Zombie (Defunct) process
    * Processes completed execution but not been reaped by it's parent process
    * Cannot be killed because it is dead but does not take resources

* Daemons
    * intentionally orphaned process in order to have a background process
    * purpose: manage services: {start,stop,restart}
```
man -cron
#daemons that starts during the boot process
```

# Interacting with linux Services
* sysv
  * service <service name> status/start/stop/restart

* systemd
```
systemctl list-units --all
systemctl status <servicename.service>
systemctl status <PID of service
```

# Cron jobs
* cron daemon checks
  * /var/spool/cron
  * /etc/cron.d
  * /etc/crontab (system cron jobs performed as root)

* System cron jobs
    * run as root
    * perform system wide maintenance tasks
    * /etc/crontab

* user cron jobs
    * use 'crontab' to create user cron job
    * stored in /var/spool/cron/crontabs/
```
crontab -u [user] file This command will load the crontab data from the specified file
crontab -l -u [user] This command will display/list user’s crontab contents
crontab -e -u [user] This command will edit user’s crontab contents
```

# Processes and Proc Dir
* /proc/
* Contains a hierarchy of special files which represent the current state of the kernel

# File Descriptors
* field descriptors have numbers in them (FD coloumn, Ex: 2u)
```
sudo lsof | tail -30
sudo lsof -c sshd (list open files for a specific process)
```

* Interpretting File Descriptors
  * # - The number in front of flag(s) is the file descriptor number used by the process                 associated with the file
    u - File open with Read and Write permission
    r - File open with Read permission
    w - File open with Write permission
    W - File open with Write permission and with Write Lock on entire file
    mem - Memory mapped file, usually for share library

# Navigating Proc Directory
```
ls -l /proc/
ls -l /proc/<PID>
```
# grep -w / -e '/bin/apache3 -lp 443' 2>/dev/null


# Linux Process Find Evil 3
* Scenario: Text files are being exfiltrated from the machine using a network connection. The     connections still occur post-reboot, according to network analysts.
* The junior analysts are having a hard time with attribution because no strange programs or     ports are running, and the connection seems to only occur in 60-second intervals, every 15     minutes.
* Task: Determine the means of persistence used by the program, and the port used. The flag is     the command that allowsexfiltration, and the file its persistence mechanism uses.
* Flag format: command,persistence
```
htop 
#found popup for netcat sending .txt file

cd /var/log
cat syslog
sudo !! 
#found whatischaos.service

systemctl status whatischaos.service
#found directory path to service location

cd <dir>
ls 
#found whatischaos.timer

cat whatischaos.time
```


# Syslog Daemon
```
cat /etc/rsyslog.d/50-default.con
#mail.info matches all messages produced by the kernel with severith of -ge 6/informational (0-6)
#mail.!info less than and not including 6/informational
```

# Filtering syslog log files
```
cat /var/log/syslog | grep timesyncd
cat /var/log/syslog | grep -R "\w*.\w*.\w*"
```

# log rotations
```
cat /etc/logrotate.conf
ls -l /var/log
```

# Essential syslog types locations

Authentication (last)
```
last ./var/log/wtmp
last.*/var/log/wtmp #failed login attempts
# -5 last five loggin sessions
# -R hide a hostname
# -F login and logout times with dates
# -a display hostname in last column
# -s yesterday -t today specific time period
# -d ip addresses into hostnames
# -x system down and run level changes
# -w full user and domain names
```


Journald
```
#filtering logs by boot
jounalctl --list-boots
jounalctl -b b3076f6774b841e08c19236bf327f529

#filtering logs by a specific unit
journal -u ssh.service

#filtering logs since a specific time
journalctl -u ssh.service --since "2 days ago"
```
```
cat log.txt | grep "session opened" | wc -l
#searched in logged file
```

XML
```
xpath -q -e '//element/@attribute' file.xml
```

JSON
```
head <file> | jq .
jq '.' conn.log
jq '."id.orig_h"' conn.log | sort -u #get specific unique values
jq 'select(.resp_ip_bytes > 40) | .resp_ip_bytes' conn.log
#pull data from a group that is greater than 40
```
