# isc-threat-feeds
Parser, and the output files, for converting thread feeds from the Internet Storm Center into IPv4 lists for consumption by other tools/processes.

Current endpoints the application supports are:
* http://isc-threat-feeds.projectlaunchpad.net:8080/threatcategory/bots
* http://isc-threat-feeds.projectlaunchpad.net:8080/threatcategory/malware
* http://isc-threat-feeds.projectlaunchpad.net:8080/threatcategory/research
* http://isc-threat-feeds.projectlaunchpad.net:8080/threatlist/alltor
* http://isc-threat-feeds.projectlaunchpad.net:8080/threatlist/torexit

## Environment Setup
A basic pattern for setting up virtual environment when performing development

```bash
# create a virtual environment
python3 -m venv .venv
# activate the newly created environment
source .venv/bin/activate
# update pip
python -m pip install --upgrade pip
# install required python libraries
pip install -r requirements.txt
```

## Server Setup

* Copy the unit file `isc-threat-feeds-server.service` to `/etc/systemd/system/s`
* Realod Systemd `systemctl daemon-reload`
* Start the service `systemctl start isc-threat-feeds-server.service`
* Enable the service `systemctl enable isc-threat-feeds-server.service`
