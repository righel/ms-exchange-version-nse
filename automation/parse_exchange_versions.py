#!/usr/bin/env python3

import requests
import lxml.html as lh
import json
import sys

if(len(sys.argv[1:]) < 2):
    exit("output files path missing")

versions_file = sys.argv[1]
unique_versions_file = sys.argv[2]

URL = "https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates"
page = requests.get(URL)

versions = {}
entries = {}

doc = lh.fromstring(page.content)
tr_elements = doc.xpath('//tr')

ignore = ['Product name', 'Release date',
          'Build number(short format)', 'Build number(long format)']


for j in range(1, len(tr_elements)):
    # T is our j'th row
    row = tr_elements[j]

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
        'build_long': row[3].text_content().strip(),
        'url': url
    }

    key = v['build']
    versions[key] = v

    if entries.get(key):
        entries[key].append(v)
    else:
        entries[key] = [v]

    # add entries without last part of the build
    short_key = '.'.join(key.split('.', 3)[:-1])
    if entries.get(short_key):
        entries[short_key].append(v)
    else:
        entries[short_key] = [v]

with open(versions_file, "w") as output:
    json.dump(entries, output, indent=4, sort_keys=True)

with open(unique_versions_file, "w") as output:
    json.dump(versions, output, indent=4, sort_keys=True)
