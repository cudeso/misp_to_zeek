import requests
from keys import misp_url, misp_key, misp_verifycert

def process_intel(intel_type, indicator_type, new_file = True):
    data = { "returnFormat": "json", "type": intel_type}
    for el in misp_config:
        data[el] = misp_config[el]

    try:        
        result = requests.post("{}/{}".format(misp_url, "attributes/restSearch"), headers=misp_headers, verify=misp_verifycert, json=data)
        intel_type_blob = "#fields	indicator	indicator_type	meta.source"

        for attr in result.json()["response"]["Attribute"]:
            intel_type_blob = "{}\n{}\t{}\t{} (event ID {})".format(intel_type_blob, attr["value"], indicator_type, attr["Event"]["info"], attr["event_id"])
        intel_type_blob = "{}\n".format(intel_type_blob)

        if new_file:
            f_intel = open("misp-{}.intel".format(intel_type), "w")
        else:
            f_intel = open("misp-{}.intel".format(intel_type), "a")
        f_intel.write(intel_type_blob)
    except:
        print("Unable to process data for {}".format(intel_type))


misp_headers = { "Authorization": misp_key, "Content-Type": "application/json", "Accept": "application/json" }
misp_config = { "last": "30d", "to_ids": 1 , "enforceWarninglist": 1, "tags": [ "!tlp:red" ]}

if misp_verifycert is False:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

process_intel("domain", "Intel::DOMAIN")
process_intel("hostname", "Intel::DOMAIN", False)

process_intel("url", "Intel::URL")

process_intel("ip-src", "Intel::ADDR")
process_intel("ip-dst", "Intel::ADDR", False)

process_intel("md5", "Intel::FILE_HASH")
process_intel("sha1", "Intel::FILE_HASH", False)
process_intel("sha256", "Intel::FILE_HASH", False)
process_intel("sha512", "Intel::FILE_HASH", False)

process_intel("ja3-fingerprint-md5", "Intel::IN_JA3")
