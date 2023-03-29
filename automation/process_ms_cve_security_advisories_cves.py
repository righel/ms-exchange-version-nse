#!/usr/bin/env python3

import json
import sys
import urllib3
from datetime import datetime
from time import sleep
import requests
import re
urllib3.disable_warnings()

if (len(sys.argv[1:]) < 1):
    exit("output file path missing")

output_file = sys.argv[1]
interactive = (len(sys.argv[1:]) == 2 and sys.argv[2] == "interactive")


def load_json(file):
    # get versions dict
    with open(file, "r") as file:
        raw_file = file.read()
    content = json.loads(raw_file)

    return content


def get_build_release_date(build, ms_versions):
    version = ms_versions[build]
    try:
        return datetime.strptime(version["release_date"], '%B %d, %Y')
    except:
        return datetime.strptime(version["release_date"], '%B, %Y')


def find_build_by_product_name(product_name, versions):
    # why is this so hard? :(
    # microsoft please fix your api and send the correct build number in the affectedProduct endpoint productVersion field
    # does not work for older versions (service packs/rollups for example)

    if product_name == "Microsoft Exchange Server 2019":
        return "15.2.221"

    if product_name == "Microsoft Exchange Server 2016":
        return "15.1.225"

    if product_name == "Microsoft Exchange Server 2013":
        return "15.0.516"

    if product_name == "Microsoft Exchange Server 2010":
        return "14.0.639"

    if product_name == "Microsoft Exchange Server 2013 Service Pack 1":
        return "15.0.847"

    if product_name == "Microsoft Exchange Server 2010 Service Pack 3":
        return "14.3.123"

    y = re.search('(\d{4})', product_name)
    if y:
        year = y.group(1)
    else:
        print("unknown exchange year: %s" % product_name)
        return None

    # grab cumulative update
    cu = re.search('Cumulative Update (\d+)', product_name)
    if cu:
        cumulative = "CU%s" % cu.group(1)
    else:
        print("unknown exchange cumulative update: %s" % product_name)
        return None

    for version in versions:
        if year in versions[version]["name"] and (cumulative in versions[version]["name"]):
            return version[:version.rfind(".")]

    return None


# product id to build map
product_id_build_map = load_json("../product_id_build_map.json")

# affected versions dict
cves_affected_products_dict = load_json("../cves_affected_products_dict.json")

# get ms versions
versions = load_json("../ms-exchange-unique-versions-dict.json")

# get unique cves
versions_cves = load_json("../ms-exchange-versions-cves-dict.json")
unique_cves = set()
for version in versions_cves:
    for cve in versions_cves[version]["cves"]:
        unique_cves.add(cve["id"])

# process cves
for cve in unique_cves:
    if int(cve[4:8]) < 2020:
        # skip old cves
        continue

    # get affected versions via MS API
    url = "https://api.msrc.microsoft.com/sug/v2.0/en-US/affectedProduct?$filter=cveNumber%20eq%20%27{}%27&$top=500".format(
        cve)
    response = requests.get(url, verify=False)
    response = json.loads(response.text)

    affected_versions = {}
    print("getting affected versions for %s ..." % cve)
    for affected_version in response["value"]:
        if "Exchange Server" not in affected_version["product"]:
            print("skipping %s" % affected_version["product"])
            continue

        productId = str(affected_version["productId"])
        build = None

        if productId not in product_id_build_map.keys():
            # find the name via kbArticles[].fixedBuildNumber
            if "kbArticles" in affected_version.keys():
                for kbArticle in affected_version["kbArticles"]:
                    if "fixedBuildNumber" in kbArticle.keys():
                        print("found build %s for %s" % (
                            kbArticle["fixedBuildNumber"], affected_version["product"]))
                        build = kbArticle["fixedBuildNumber"]
                        # remove leading zeros
                        build = ".".join([str(int(v))
                                         for v in build.split(".")])
                        build = build[:build.rfind(".")]  # remove patch number
                        print("short_build: %s" % build)

                        product_id_build_map[productId] = build
                        break

            # find build by string matching of product name
            if build is None:
                build = find_build_by_product_name(
                    affected_version["product"], versions)
                if build is None:
                    if interactive:
                        build = input(
                            "ProductId=%s Not Found. Enter 3 first build numbers for version: %s (press Enter to skip)\n" % (productId, affected_version["product"]))
                        build = build.strip()
                        if build == '':
                            print("skipping %s" % affected_version["product"])
                            continue
                    else:
                        sys.exit(
                            "ERROR: %s could not be mapped, run the script with `interactive` arg and commit the `product_id_build_map.json` file." % affected_version["product"])

            product_id_build_map[productId] = build
        else:
            build = product_id_build_map[productId]

        affected_versions[build] = {
            "productId": productId,
            "product": affected_version["product"],
            "releaseDate": affected_version["releaseDate"],
        }
    cves_affected_products_dict[cve] = affected_versions
    sleep(1)

with open("../cves_affected_products_dict.json", "w") as output:
    json.dump(cves_affected_products_dict, output, indent=4, sort_keys=True)

with open("../product_id_build_map.json", "w") as output:
    json.dump(product_id_build_map, output, indent=4, sort_keys=True)


# remove patched cves
for version in versions_cves.keys():
    version_release_date = get_build_release_date(version, versions)

    if version_release_date is None:
        print("skipping %s" % version)
        continue

    cves = []
    for cve in versions_cves[version]["cves"]:
        if cve["id"] in cves_affected_products_dict.keys():
            product_version = version[:version.rfind(".")]
            if product_version in cves_affected_products_dict[cve["id"]].keys():
                patch_date = datetime.strptime(
                    cves_affected_products_dict[cve["id"]][product_version]["releaseDate"], '%Y-%m-%dT%H:%M:%SZ')

                # if version release date is older than the patch, still vulnerable
                if version_release_date.date() < patch_date.date():
                    cves.append(cve)
    versions_cves[version]["cves"] = cves

with open(output_file, "w") as output:
    json.dump(versions_cves, output, indent=4, sort_keys=True)
