#!/usr/bin/env python3

import requests
import json
import time
import lxml.html as lh
import re
import urllib3
import sys

urllib3.disable_warnings()

if(len(sys.argv[1:]) < 2):
    exit("versions dict/output file path missing")

versions_file = sys.argv[1]
output_file = sys.argv[2]

# get main versions with cves
with open(output_file, "r") as file:
    main_versions = file.read()
main_versions_dict = json.loads(main_versions)

all_versions_cves_dict = main_versions_dict.copy()
cve_pattern = r'CVE-\d{4}-\d{4,7}'

# get all versions
with open(versions_file, "r") as file:
    all_versions = file.read()
all_versions_dict = json.loads(all_versions)

for version in all_versions_dict:
    if len(all_versions_dict[version]) > 1:
        crono_ordered_versions = list(reversed(all_versions_dict[version]))
        if crono_ordered_versions[0]["build"] in main_versions_dict.keys():
            main_version = main_versions_dict[crono_ordered_versions[0]["build"]]
            if main_version:
                base_cves = main_version["cves"]
            else:
                print("main release has no url: %s" % version)
                continue

            for patch in crono_ordered_versions[1:]:
                if patch["url"]:
                    patch_page = requests.get(patch["url"])
                    
                    patched_cves = []
                    cves = re.findall(cve_pattern, str(patch_page.content))
                    for cve in cves:
                        patched_cves.append(cve)

                    # remove patched cves from base cves
                    base_cves = [cve for cve in base_cves if cve["id"] not in set(patched_cves)]

                    all_versions_cves_dict[patch["build"]] = {
                        "cves": base_cves,
                        # use cpe of the main release
                        "cpe": all_versions_cves_dict[crono_ordered_versions[0]["build"]]["cpe"]
                    }

                    time.sleep(1)

        else:
            print("main release not found: %s" % version)

with open(output_file, "w") as output:
    json.dump(all_versions_cves_dict, output, indent=4, sort_keys=True)
