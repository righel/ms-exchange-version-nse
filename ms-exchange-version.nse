local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local json = require "json"
local stdnse = require "stdnse"

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
    
    local headers = {
        ["User-Agent"] = "nmap: ms-exchange-version.nse",
        ["Content-Type"] = "text/html; charset=utf-8"
    }

    if stdnse.get_script_args("browser") then
        headers = {
            ["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            ["Content-Type"] = "text/html; charset=utf-8",
            ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            ["Accept-Language"] = "en-US,en;q=0.5",
            ["Accept-Encoding"] = "gzip, deflate, br",
            ["Connection"] = "keep-alive"
        }
    end
    
    return {
        scheme = port.service,
        max_body_size = -1,
        header = headers
    }
end

local function get_versions_map()
    local response = http.get_url("https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-unique-versions-dict.json", {max_body_size = -1})
    if response.status == 200 then
        _, versions = json.parse(response.body)
        return versions
    end

    return nil
end

local function get_main_versions_map()
    local response = http.get_url("https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-versions-dict.json", {max_body_size = -1})
    if response.status == 200 then
        _, versions = json.parse(response.body)
        return versions
    end

    return nil
end

local function get_cves_map()
    local response = http.get_url("https://raw.githubusercontent.com/righel/ms-exchange-version-nse/main/ms-exchange-versions-cves-dict.json", {max_body_size = -1})
    if response.status == 200 then
        _, cves = json.parse(response.body)
        return cves
    end

    return nil
end

local function get_build_via_exporttool(host, port, build, build_version_map)
    local http_options = get_http_options(host, port)
    local version = nil

    local response = http.get(host.targetname or host.ip, port, "/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application", http_options)
    if response.status == 200 then
        version = string.match(response.body, '<assemblyIdentity.*version="(%d+.%d+.%d+.%d+)"')
        if (version ~= nil) then return version end
    end

    -- brute force for the exporttool path
    local possible_versions = build_version_map[build]
    if (possible_versions == nil) then
    	return build
    end
    if (version == nil and build ~= nil) then
        for _, v in ipairs(possible_versions) do
            http.get(host.targetname or host.ip, port, ("/ecp/%s/exporttool/microsoft.exchange.ediscovery.exporttool.application"):format(v.build), http_options)
            if response.status == 200 then
                version = string.match(response.body, '<assemblyIdentity.*version="(%d+.%d+.%d+.%d+)"')
                if (version ~= nil) then return version end
            end
        end
    end

    return nil
end

local function get_owa_build(host, port, build_version_map)
    -- method 1: get build from X-OWA-Version header
    local http_options = get_http_options(host, port)
    local response = http.generic_request(host.targetname or host.ip, port, "GET", "/owa/", http_options)
    if response.header["x-owa-version"] ~= nil and response.header["x-owa-version"] ~= "" then
        return response.header["x-owa-version"]
    end

    -- method 2: get build from OWA path
    response = http.get(host.targetname or host.ip, port, "/owa", http_options)
    local build = nil
    build = string.match(response.body, '/owa/auth/(%d+.%d+.%d+)')
    if (build == nil) then
        build = string.match(response.body, '/owa/(%d+.%d+.%d+)')
    end

    -- method 3: get build from exporttool
    local ecp_build = get_build_via_exporttool(host, port, build, build_version_map)
    if (ecp_build ~= nil) then return ecp_build end

    if (build ~= nil) then
        return build -- not exact, but better than nothing
    end

    return nil
end

local function get_cves(host, port, cves_map, build)
    local cves = {}
    if cves_map[build] ~= nil then
        cves = cves_map[build]["cves"]
    end

    return cves
end

local function get_version_output(host, port, build, version, showcpes, showcves, cves_map)
    local output = {}
    if showcpes then
        -- vulners format
        key = cves_map[version.build]["cpe"]
        output[key] = {}
        
        if showcves then
            output[key] = get_cves(host, port, cves_map, version.build)
        end
    else
        key = build
        output[key] = {
            product = version.name,
            build = version.build,
            release_date = version.release_date
        }
        if showcves then
            output[key]["cves"] = get_cves(host, port, cves_map, version.build)
        end
    end

    return output
end

local function guesstimate_version_from_build(build, build_version_map)
    local major_version = string.match(build, "%d+.%d+.%d+")
    local minor_version = tonumber(string.match(build, "%d+$")) - 1

    while minor_version > 0 do
        local closest_build = major_version .. "." .. minor_version
        if build_version_map[closest_build] ~= nil then
            return build_version_map[closest_build]
        end
        minor_version = minor_version - 1
     end

    return nil
end

action = function(host, port)
    local build_version_map = get_versions_map()
    local main_build_version_map = get_main_versions_map()
    local cves_map = get_cves_map()
    local build = get_owa_build(host, port, build_version_map)
    if build == nil then return "ERROR: Host not running MS Exchange or could not get OWA version" end

    local output = {}

    local version = build_version_map[build]
    if (version == nil) then
        version = guesstimate_version_from_build(build, build_version_map)
    end


    if (version ~= nil) then
        return get_version_output(host, port, build, version, stdnse.get_script_args("showcpe"), stdnse.get_script_args("showcves"), cves_map)
    end

    local possible_versions = main_build_version_map[build]

    if (possible_versions == nil) then
        return ("ERROR: could not find version details for detected build=%s"):format(build)
    end

    for _, v in ipairs(possible_versions) do
        output[#output+1] = get_version_output(host, port, build, v, stdnse.get_script_args("showcpe"), stdnse.get_script_args("showcves"), cves_map)
    end

    return output
end
