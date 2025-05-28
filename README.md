# enum4impacket
Enumerate Active Directory with impacket using RPC.

This tool is meant to automate the initial enumeration and information gathering of an Active Directory domain. It also exports the useful information into ready to use output files automatically.

This is NOT a fully featured replacement for enum4linux but it fits my use case!

# Requirements
Even though there is a requirements.txt it should work out of the box on Kali as the requirements are only impacket and dnspython

# Usage
![image](https://github.com/user-attachments/assets/b1e4bc90-ecc5-499a-ad63-46518b78898a)

```
python enum4impacket.py -h
usage: enum4impacket.py [-h] [--prefix] [-u username] [-p secret] -d domain -t target

enum4impacket by dotpy - enumerate active directory - https://github.com/dotPY-hax

options:
  -h, --help   show this help message and exit
  --prefix     prefix for output files
  -u username
  -p secret    password or ntlm
  -d domain
  -t target    ip or cidr
```

![image](https://github.com/user-attachments/assets/71a1f22d-0a82-44f6-9023-f4544346c1b1)

```
python enum4impacket.py -t 192.168.56.22 -u hodor -p hodor -d north.sevenkingdoms.local
enum4impacket by dotpy - enumerate active directory
https://github.com/dotPY-hax
Trying to find a target for RPC...
NRPC - OK
found 192.168.56.22
=================================enum4impacket==================================
Domain: north.sevenkingdoms.local
Primary DC: winterfell.north.sevenkingdoms.local - 192.168.56.11
=====================================USERS======================================
Administrator  : Built-in account for administering the computer/domain  :   
vagrant        : Vagrant User                                            :   
arya.stark     : Arya Stark                                              :   
eddard.stark   : Eddard Stark                                            :   
catelyn.stark  : Catelyn Stark                                           :   
robb.stark     : Robb Stark                                              :   
sansa.stark    : Sansa Stark                                             :   
brandon.stark  : Brandon Stark                                           :   
rickon.stark   : Rickon Stark                                            :   
hodor          : Brainless Giant                                         :   
jon.snow       : Jon Snow                                                :   
samwell.tarly  : Samwell Tarly (Password : Heartsbane)                   :   
jeor.mormont   : Jeor Mormont                                            :   
sql_svc        : sql service                                             :   
===================================COMPUTERS====================================
WINTERFELL.north.sevenkingdoms.local   : 192.168.56.11  
CASTELBLACK.north.sevenkingdoms.local  : 192.168.56.22  
===============================DOMAIN CONTROLLERS===============================
192.168.56.11
10.0.2.15
=====================================SHARES=====================================
192.168.56.11  : ADMIN$, C$, IPC$, NETLOGON, SYSVOL  
192.168.56.22  : ADMIN$, all, C$, IPC$, public       
====================================SIGNING=====================================
192.168.56.11  : True   
192.168.56.22  : False  
=================================WRITING FILES==================================
23 chars written to /tmp/north.sevenkingdoms.local_domain_controllers.txt
159 chars written to /tmp/north.sevenkingdoms.local_users.txt
27 chars written to /tmp/north.sevenkingdoms.local_computers.txt
74 chars written to /tmp/north.sevenkingdoms.local_hostnames.txt
13 chars written to /tmp/north.sevenkingdoms.local_relay.txt
1091 chars written to /tmp/north.sevenkingdoms.local_user_descriptions.txt
113 chars written to /tmp/north.sevenkingdoms.local_computers_hostnames.txt


```

# Limitations
It only works on a single domain so far.\
It likely requires one user.\
It requires a domain name.\
It will break if the autofind (when using cidr) finds a computer that belongs to a different domain than the domain provided with -d.\
It has not been tested outside of GOAD yet.
