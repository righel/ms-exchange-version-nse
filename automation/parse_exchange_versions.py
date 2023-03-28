#!/usr/bin/env python3

import requests
import lxml.html as lh
import json
import sys
from looseversion import LooseVersion

versions = {}
unique_versions = {}


def convert_short_name_to_long(short_name):
    year = short_name[:4]

    if '+' in short_name:
        cu = short_name[4:short_name.index('+')]
        patch = short_name[short_name.index('+')+1:]
        return "Exchange Version %s %s + %s" % (year, cu, patch)

    cu = short_name[4:]

    return "Exchange Version %s %s" % (year, cu)


def convert_short_date_to_long(short_date):
    months = {
        "Jan": "January",
        "Feb": "February",
        "Mar": "March",
        "Apr": "April",
        "May": "May",
        "Jun": "June",
        "Jul": "July",
        "Aug": "August",
        "Sep": "September",
        "Oct": "October",
        "Nov": "November",
        "Dec": "December",
    }

    m = short_date[:short_date.index('-')]
    y = short_date[short_date.index('-')+1:]

    return "%s, 20%s" % (months.get(m), y)


def nest_sub_versions():
    # add entries without last part of the build
    for version in unique_versions:
        short_key = '.'.join(version.split('.', 3)[:-1])
        if versions.get(short_key):
            versions[short_key].append(unique_versions[version])
        else:
            versions[short_key] = [unique_versions[version]]


def parse_ms_docs_versions():
    URL = "https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates"
    page = requests.get(URL)

    doc = lh.fromstring(page.content)
    tr_elements = doc.xpath('//tr')

    for i in range(1, len(tr_elements)):
        row = tr_elements[i]

        # If row is not of size 4, the //tr data is not from our table
        if len(row) != 4 or row[0].text_content() == "" or row[0].text_content() == "Product name":
            continue

        # grab release details url if exists
        url = None
        if len(row[0]) > 0 and row[0][0].tag == 'a':
            url = row[0][0].attrib['href'].strip()

        # cells in row
        # 0: Product name -> name
        # 1: Release date -> release_date
        # 2: Build number(short format) -> build
        # 3: Build number(long format) -> build_long
        v = {
            'name': row[0].text_content().strip(),
            'release_date': row[1].text_content().strip(),
            'build': row[2].text_content().strip(),
            'urls': [url] if url else [],
        }

        unique_versions[str(v['build'])] = v


def parse_eightwone_versions():
    URL = "https://eightwone.com/references/versions-builds-dates/"
    page = requests.get(URL)

    doc = lh.fromstring(page.content)
    tr_elements = doc.xpath('//tr')

    for i in range(1, len(tr_elements)):
        row = tr_elements[i]

        # skip old versions and headers
        if row[0].text_content() == "2019CU4" or row[0].text_content() == "Version":
            continue

        try:
            name = convert_short_name_to_long(row[0].text_content().strip())
            build = row[1].text_content().strip()

            # fix some build numbers
            if build == "8.0.685.25/24":
                build = "8.0.685.25"

            if build == "v2:15.0.712.24 (v1:15.0.712.22)":
                build = "15.0.712.24"

            release_date = convert_short_date_to_long(
                row[2].text_content().strip())

            urls = []
            if len(row[3]) > 0:
                for a in row[3]:
                    if a.tag == 'a':
                        url = a.attrib['href'].strip()
                        # fix some broken urls
                        if url.lower().startswith('kb'):
                            url = "https://support.microsoft.com/kb/%s" % url[2:]

                        if url.lower().startswith('http://kb'):
                            url = "https://support.microsoft.com/kb/%s" % url[9:]

                        urls.append(url)

            v = {
                'name': name,
                'release_date': release_date,
                'build': build,
                'urls': urls
            }

            # version not listed on Microsoft Docs
            if (build not in unique_versions):
                unique_versions[str(build)] = v
        except Exception as ex:
            print("error parsing version %s" % row[0].text_content().strip())


if __name__ == '__main__':

    if (len(sys.argv[1:]) < 2):
        exit("output files path missing")

    versions_file = sys.argv[1]
    unique_versions_file = sys.argv[2]

    parse_ms_docs_versions()

    parse_eightwone_versions()

    unique_versions = {k: unique_versions[k] for k in sorted(
        unique_versions, key=LooseVersion)}

    nest_sub_versions()

    # save files
    with open(versions_file, "w") as output:
        json.dump(versions, output, indent=4)

    with open(unique_versions_file, "w") as output:
        json.dump(unique_versions, output, indent=4)
