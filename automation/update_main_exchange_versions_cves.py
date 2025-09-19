#!/usr/bin/env python3

import requests
import json
import time
import urllib3
import sys
import re
from looseversion import LooseVersion

urllib3.disable_warnings()

if(len(sys.argv[1:]) < 2):
    exit("versions dict/output file path missing")

versions_file = sys.argv[1]
cves_file = sys.argv[2]

# load versions dict
with open(versions_file, "r") as file:
    main_versions = file.read()
versions_dict = json.loads(main_versions)

# load cves dict
with open(cves_file, "r") as file:
    cves = file.read()
cves_dict = json.loads(cves)


def generate_ms_exchange_cpe(version):
    y = re.search(r'(\d{4})', version["name"])
    if y:
        year = y.group(1)
    else:
        print("unknown exchange year: %s" % version["name"])
        return None

    # grab cumulative update
    cu = re.search(r'CU(\d+)', version["name"])
    if cu:
        cumulative = "cumulative_update_%s" % cu.group(1)
    else:
        print("unknown exchange cumulative update: %s" % version["name"])
        return None

    return "cpe:/a:microsoft:exchange_server:%s:%s:*:*:*:*:*:*" % (year, cumulative)


for version in versions_dict:

    if version not in cves_dict:
        # new version, add it
        cpe = generate_ms_exchange_cpe(versions_dict[version])

        cves_dict[version] = {
            "cpe": cpe,
            "cves": []
        }

    cpe = cves_dict[version]["cpe"]

    if cpe is not None:
        if cpe:
            cves_dict[version]["cves"] = []
            # get cves
            r = requests.get("https://vulnerability.circl.lu/api/vulnerability/cpesearch/%s" % cpe)
            if r.status_code == 200:
                data = json.loads(r.text)

                for vuln in data['cvelistv5']:
                    if vuln["dataType"] == "CVE_RECORD":
                        cve = {
                            "id": vuln["cveMetadata"]["cveId"],
                            "last-modified": vuln["cveMetadata"]["dateUpdated"],
                        }

                        if "cna" in vuln["containers"]:
                            cve["summary"] = vuln["containers"]["cna"].get("title", "")

                            # cvss
                            for item in vuln["containers"]["cna"].get("metrics", []):
                                if item.get("format", "") == "CVSS":
                                    if "cvssV3_1" in item:
                                        cve["cvss"] = item["cvssV3_1"].get("baseScore", "")
                                        break

                            # cwe
                            for item in vuln["containers"]["cna"].get("problemTypes", []):
                                for desc in item.get("descriptions", []):
                                    if desc.get("type", "") == "CWE":
                                        cve["cwe"] = desc.get("cweId", "")
                                        break

                        cves_dict[version]["cves"].append(cve)

            time.sleep(1)

cves_dict = {k: cves_dict[k] for k in sorted(cves_dict, key=LooseVersion)}

with open(cves_file, "w") as output:
    json.dump(cves_dict, output, indent=4, sort_keys=True)
