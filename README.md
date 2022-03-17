# ms-exchange-version-nse
 Nmap script to detect a Microsoft Exchange instance version with OWA enabled. 

### Usage
```
$ nmap -p 443 --script ms-exchange-version.nse --script-args=http.max-cache-size=10000000 <target>
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

Experimental: 

* `--script-args=showcves`:
```
$ nmap -p 443 --script ms-exchange-version.nse --script-args=showcves,http.max-cache-size=10000000 <target>
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-19 15:58 CET
Nmap scan report for REDACTED (REDACTED)
Host is up (0.0068s latency).
rDNS record for REDACTED: REDACTED

PORT    STATE SERVICE
443/tcp open  https
| ms-exchange-version: 
|   15.1.2044.4: 
|     build_long: 15.01.2044.004
|     product: Exchange Server 2016 CU17
|     release_date: June 16, 2020
|     build: 15.1.2044.4
|     cves: 
|       
|         cvss: 4.6
|         summary: The installation of 1ArcServe Backup and Inoculan AV client modules for Exchange create a log file, exchverify.log, which contains usernames and passwords in plaintext.
|         cvss-time: 2021-04-09T16:57:00
|         last-modified: 2021-04-09T16:57:00
|         id: CVE-1999-1322
|         cwe: NVD-CWE-Other
|         
|         [...]
|_

Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```

* `--script-args=showcpe`:
```
$ nmap -p 443 --script ms-exchange-version.nse --script-args=showcves,http.max-cache-size=10000000 <target>
Starting Nmap 7.80 ( https://nmap.org ) at 2021-12-09 09:53 CET
Nmap scan report for REDACTED (REDACTED)
Host is up (0.025s latency).

PORT    STATE SERVICE
443/tcp open  https
| ms-exchange-version: 
|_  cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_17:*:*:*:*:*:*: 

Nmap done: 1 IP address (1 host up) scanned in 1.19 seconds
```

credits to @rommelfs for the crawler to auto update the versions dict.
