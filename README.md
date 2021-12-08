# ms-exchange-version-nse
 Nmap script to detect a Microsoft Exchange instance version with OWA enabled. 

### Usage
```
$ nmap -p 443 --script ms-exchange-version.nse --script-args=http.max-cache-size=10000000<target>
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

Experimental, show CVEs with a response compatible with `vulners.nse`:
```
$ nmap -p 443 --script ms-exchange-version.nse --script-args=showcves,http.max-cache-size=10000000<target>
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-19 15:58 CET
Nmap scan report for REDACTED (REDACTED)
Host is up (0.0068s latency).
rDNS record for REDACTED: REDACTED

PORT    STATE SERVICE REASON
443/tcp open  https   syn-ack
| ms-exchange-version: 
|   cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_17:*:*:*:*:*:*: 
|       [...]
|       cwe: NVD-CWE-noinfo
|       cvss-time: 2021-05-21T18:15:00
|       id: CVE-2021-26855
|       summary: Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065, CVE-2021-27078.
|       cvss: 7.5
|       last-modified: 2021-05-21T18:15:00
|     
|       cwe: NVD-CWE-noinfo
|       cvss-time: 2021-05-21T18:15:00
|       id: CVE-2021-27065
|       summary: Microsoft Exchange Server Remote Code Execution Vulnerability This CVE ID is unique from CVE-2021-26412, CVE-2021-26854, CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27078.
|       cvss: 6.8
|_      last-modified: 2021-05-21T18:15:00


Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```

credits to @rommelfs for the crawler to auto update the versions dict.
