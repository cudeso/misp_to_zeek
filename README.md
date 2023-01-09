# Zeek

## Setup the intel framework

Clone the repository in `/opt/zeek/share/zeek/site` or make a directory to contain all the files. Assume this is **misp_to_zeek** for now.

Add the below setting to `/opt/zeek/share/zeek/site/local.zeek` . This will load all the rules in the **misp_to_zeek** directory.

```
@load misp_to_zeek
```

If you want to test the Zeek intel framework with your settings then add the below option to `local.zeek` to ignore checksum validation.

```
redef ignore_checksums = T;
```

## Zeek file locations

Make sure the the references to the intel files in `main` refer to the correct paths (`/opt/zeek/share/zeek/site`).

# MISP Import

## Config

Create a copy of keys.py.default to keys.py and then update the MISP API and URL in `keys.py`.

## Execute

Execute the script manually to ensure all things are working as expected. Then restart Zeek.

```
python update_intel.py
zeekctl deploy
````

You can then add the execute commands to cron.
