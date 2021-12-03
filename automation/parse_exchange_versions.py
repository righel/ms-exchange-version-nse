#!/usr/bin/env python3

import requests
import lxml.html as lh
import json
import sys

if(len(sys.argv[1:]) == 0):
    exit("output file path missing")

output_file = sys.argv[1]

URL = "https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates"
page = requests.get(URL)

entries = {}

doc = lh.fromstring(page.content)
tr_elements = doc.xpath('//tr')

ignore = ['Product name', 'Release date',
          'Build number(short format)', 'Build number(long format)']

col = []
i = 0
# For each row, store each first element (header) and an empty list
for t in tr_elements[0]:
    i += 1
    name = t.text_content()
    # print('%d:"%s"'%(i,name))
    col.append((name, []))

for j in range(1, len(tr_elements)):
    # T is our j'th row
    T = tr_elements[j]

    # If row is not of size 4, the //tr data is not from our table
    if len(T) != 4:
        break

    # i is the index of our column
    i = 0

    # Iterate through each element of the row
    for t in T.iterchildren():
        data = t.text_content()
        
        # # save url instead of name
        # if i == 0:
        #     if len(t) > 0 and t[0].tag == 'a':
        #         # data = t[0].text_content()
        #         data = t[0].attrib['href']

        # Check if row is empty
        if i > 0:
            # Convert any numerical value to integers
            try:
                data = int(data)
            except:
                pass
        # Append the data to the empty list of the i'th column
        if data and data not in ignore:
            col[i][1].append(data.lstrip())
        # Increment i for the next column
        i += 1

for i in range(0, len(col[0][1])):

    entry = {
        "name": col[0][1][i],
        "build": col[2][1][i],
        "build_long": col[3][1][i],
        "release_date": col[1][1][i]
    }
    
    key = col[2][1][i]

    if entries.get(key):
        entries[key].append(entry)
    else:
        entries[key] = [entry]

    # add entries without last part of the build
    short_key = '.'.join(key.split('.', 3)[:-1])
    if entries.get(short_key):
        entries[short_key].append(entry)
    else:
        entries[short_key] = [entry]

with open(output_file, "w") as output:
    json.dump(entries, output, indent=4, sort_keys=True)