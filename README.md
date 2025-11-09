# isc-threat-feeds
Parses and outputs feeds from the Internet Storm Center into IPv4 lists for consumption by other tools/processes.

Current endpoints the application supports are:
* http://isc-threat-feeds.projectlaunchpad.net/threatcategory/bots
* http://isc-threat-feeds.projectlaunchpad.net/threatcategory/malware
* http://isc-threat-feeds.projectlaunchpad.net/threatcategory/research
* http://isc-threat-feeds.projectlaunchpad.net/threatlist/alltor
* http://isc-threat-feeds.projectlaunchpad.net/threatlist/torexit

## Building and Deployment

The application is built through GitHub Actions and published to the GitHub Container Registry. An example deployment of the container as follows.

```bash
docker run \
  -d \
  --name isc-threat-feeds \
  -p 80:8080 \
  --restart unless-stopped \
  ghcr.io/edepree/isc-threat-feeds:v1.1.0
```
