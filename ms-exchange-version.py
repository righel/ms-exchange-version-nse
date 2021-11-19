#!/usr/bin/env python3

import json
import requests
import sys
import re
import urllib3

urllib3.disable_warnings()


def main(argv):
    if(len(argv) == 0):
        exit("error: target ip missing \nusage:\n\t$ python3.8 ms-exchange-version.py 127.0.0.1")

    ip = argv[0]

    version = get_owa_build(ip)

    if version is None:
        exit("error: could not determine version.")

    print(version)


def get_versions_map():
    # get versions dict
    with open("./ms-exchange-versions-dict.json", "r") as file:
        raw_versions = file.read()
    versions = json.loads(raw_versions)

    return versions


def get_build_via_exporttool(ip, build):
    # get versions dict
    versions = get_versions_map()

    r = requests.get(
        'https://%s/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application' % (ip), verify=False)
    if r.status_code == 200:
        result = re.search(
            "<assemblyIdentity.*version=\"(\d+.\d+.\d+.\d+)\"", r.text)
        if(result):
            return result.group(1)

    # get build via exporttool
    if r.status_code == 200:
        for version in versions:
            r = requests.get(
                'https://%s/ecp/%s/exporttool/microsoft.exchange.ediscovery.exporttool.application' % (ip, build), verify=False)
            result = re.search(
                "<assemblyIdentity.*version=\"(\d+.\d+.\d+.\d+)\"", r.text)
            if(result):
                return result.group(1)

    return None


def get_owa_build(ip):
    r = requests.get('https://%s/owa/' % ip, verify=False)
    versions = get_versions_map()

    # x-owa-version header method
    if r.headers.get("x-owa-version"):
        return versions[r.headers["x-owa-version"]]

    # get partial build from urls
    build = None
    result = re.search("/owa/auth/(\d+.\d+.\d+)", r.text)
    if(result):
        build = result.group(1)
    else:
        result = re.search("/owa/auth/(\d+.\d+.\d+)", r.text)
        if(result):
            build = result.group(1)

    if build is not None:
        ecp_build = get_build_via_exporttool(ip, build)

        if ecp_build is not None:
            return versions[ecp_build]

        return versions[build]

    return None


if __name__ == "__main__":
    main(sys.argv[1:])
