# isc-threat-feeds
Parses and outputs feeds from the Internet Storm Center into IPv4 lists for consumption by other tools/processes.

Current endpoints the application supports are:
* http://isc-threat-feeds.projectlaunchpad.net/threatcategory/bots
* http://isc-threat-feeds.projectlaunchpad.net/threatcategory/malware
* http://isc-threat-feeds.projectlaunchpad.net/threatcategory/research
* http://isc-threat-feeds.projectlaunchpad.net/threatlist/alltor
* http://isc-threat-feeds.projectlaunchpad.net/threatlist/torexit

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
### Nginx
1. Install nginx `apt install nginx`
2. Disable the default nginx site `unlink /etc/nginx/sites-enabled/default`
3. Copy `isc-threat-feeds-proxy` to `/etc/nginx/sites-available` and enable site `ln -s /etc/nginx/sites-available/isc-threat-feeds-proxy /etc/nginx/sites-enabled/`
5. Start and enable Nginx `systemctl start nginx` and `systemctl enable nginx`

### Gunicorn
1. Copy the unit file `isc-threat-feeds-server.service` to `/etc/systemd/system`
2. Realod Systemd `systemctl daemon-reload`
3. Start and enable service `systemctl start isc-threat-feeds-server.service` and `systemctl enable isc-threat-feeds-server.service`
