local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local json = require "json"

description = [[
  Check for Microsoft Exchange Server version using OWA path data or X-OWA-Version header or ecp/exporttool response.

  References:
    - https://docs.microsoft.com/en-us/exchange/new-features/build-numbers-and-release-dates
]]

author = "Luciano Righetti"
license = "GPLv3"
categories = {"version", "safe"}

portrule = shortport.service({"http", "https"})

local function get_http_options(host, port)
    return {
        scheme = port.service,
        max_body_size = -1,
        header = {
            ["User-Agent"] = "nmap: ms-exchange-version.nse",
            ["Content-Type"] = "text/html; charset=utf-8"
        }
    }
end

local function get_versions_map()
    local response = http.get_url("https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-versions-dict.json", {})
    if response.status == 200 then
        _, versions = json.parse(response.body)
        return versions
    end

    return nil
end

local function get_build_via_exporttool(host, port, build)
    local http_options = get_http_options(host, port)
    local version = nil

    local response = http.get(host.ip, port, "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application", http_options)
    if response.status == 200 then
        version = string.match(response.body, '<assemblyIdentity.*version="(%d+.%d.%d+.%d+)"')
        if (version ~= nil) then return version end
    end

    -- brute force for the exporttool path
    local possible_versions = build_version_map[build]
    if (version == nil) then
        for _, v in ipairs(possible_versions) do
            http.get(host.ip, port, ("/ecp/%s/exporttool/microsoft.exchange.ediscovery.exporttool.application"):format(v.build), http_options)
            if response.status == 200 then return v.build end
        end
    end

    return nil
end

local function get_owa_build(host, port)
    -- method 1: get build from X-OWA-Version header
    local http_options = get_http_options(host, port)
    local response = http.generic_request(host.ip, port, "GET", "/owa/", http_options)
    if response.header["x-owa-version"] ~= nil then
        return response.header["x-owa-version"]
    end

    -- method 2: get build from OWA path
    response = http.get(host.ip, port, "/owa", http_options)
    local build = nil
    build = string.match(response.body, '/owa/auth/(%d+.%d.%d+)')
    if (build == nil) then
        build = string.match(response.body, '/owa/(%d+.%d.%d+)')
    end
    if (build ~= nil) then
        -- method 3: get build from exporttool
        local ecp_build = get_build_via_exporttool(host, port, build)
        if (ecp_build ~= nil) then return ecp_build end

        return build -- not exact, but better than nothing
    end

    return nil
end

action = function(host, port)
    local build = get_owa_build(host, port)
    if build == nil then return "ERROR: could not get OWA version" end

    local build_version_map = get_versions_map()

    -- get build cpe
    local version = build_version_map[build]
    if (version == nil) then
        return ("ERROR: could not find version for detected build=%s"):format(build)
    end

    local output = {}

    for _, v in ipairs(version) do
        output[v.build] = {version = v.version, package = v.info, release = v.release}
    end

    return output
end
