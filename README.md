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
|_    release_date: November 9, 2021

Nmap done: 1 IP address (1 host up) scanned in 0.61 seconds
```

Experimental: 

* `--script-args=showcves`:
```
$ nmap -p 443 --script ms-exchange-version.nse --script-args=showcves <target>
Starting Nmap 7.80 ( https://nmap.org ) at 2021-11-19 15:58 CET
Nmap scan report for REDACTED (REDACTED)
Host is up (0.0068s latency).
rDNS record for REDACTED: REDACTED

PORT    STATE SERVICE
443/tcp open  https
| ms-exchange-version: 
|   15.1.2044.4: 
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

#### Multiple targets
If you plan to scan multiple targets, add the following argument: `http.max-cache-size=10000000`

```
$ nmap -p 443 --script ms-exchange-version.nse --script-args=http.max-cache-size=10000000 <target>
```

This is because of [a bug](https://github.com/nmap/nmap/pull/2407) in the internal cache mechanism of `nmap`

### Automation
Everyday a Github action is run to check if there are new Microsoft Exchange versions published in this Microsoft docs page: 
* https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates

If so, the files [ms-exchange-versions-dict.json](./ms-exchange-versions-dict.json) and [ms-exchange-versions-cves-dict.json](./ms-exchange-versions-cves-dict.json) are automatically updated so the nmap script can detect these new versions.

**How it works:**

1. [parse_exchange_versions.py](./automation/parse_exchange_versions.py) parses the Microsoft docs page with the MS Exchange build numbers and versions.
   * Some build numbers are missing from Microsoft Docs, so the script uses https://eightwone.com/references/versions-builds-dates/ as complementary source. 
2. [update_main_exchange_versions_cves.py](./automation/update_main_exchange_versions_cves.py) gets the list of CVEs for each main* MS Exchange version by querying [cvepremium.circl.lu](https://cvepremium.circl.lu/api/) API. Unfortunately Microsoft does not provide a sufficiently granular CPE naming scheme, only for main versions, for example:
   
   | Product Name | Release date | Build number |
   | - | - | - |
   |Exchange Server 2019 CU11 Mar22SU|March 8, 2022|15.2.986.22|
   |Exchange Server 2019 CU11 Jan22SU|January 11, 2022|15.2.986.15|
   |Exchange Server 2019 CU11 Nov21SU|November 9, 2021|15.2.986.14|
   |Exchange Server 2019 CU11 Oct21SU|October 12, 2021|15.2.986.9|
   |**Exchange Server 2019 CU11**|**September 28, 2021**|**15.2.986.5**|

    \* All the above versions, share the same CPE: 
    * `cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_11:*:*:*:*:*:*`

    Therefore, theres no way to get the exact list of CVE's that an specific security update is affected by.


3. [update_patches_exchange_versions_cves.py](./automation/update_patches_exchange_versions_cves.py) tries to fix this issue by parsing each security update and removing the fixed CVE's from the immediate previous version.

> credits to @rommelfs for the crawler to auto update the versions dictionary.
