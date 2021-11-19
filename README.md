# ms-exchange-version-nse
 Nmap script to detect a Microsoft Exchange instance version with OWA enabled. 

### Usage
```
$ nmap -p 443 --script ms-exchange-version.nse <target>
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-19 15:58 CET
Nmap scan report for REDACTED (REDACTED)
Host is up (0.0068s latency).
rDNS record for REDACTED: REDACTED

PORT    STATE SERVICE
443/tcp open  https
| ms-exchange-version: 
|   15.1.2375.7: 
|     release: Sep-21
|     version: 2016CU22
|_    package: KB5005333

Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```
