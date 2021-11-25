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
|   15.1.2375.17: 
|     name: Exchange Server 2016 CU22 Nov21SU
|     build: 15.1.2375.17
|     build_long: 15.01.2375.017
|_    release_date: November 9, 2021

Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```

credits to @rommelfs for the crawler to auto update the versions dict.
