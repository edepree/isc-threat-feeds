# isc-threat-feeds
Parses feeds from the Internet Storm Center into IPv4 CIDR lists for consumption by other tools/processes.

A GitHub Action refreshes the lists daily and commits them to [`feeds/`](feeds/). The lists carry the SANS ISC data license (CC BY-NC-SA 4.0); see [`feeds/README.md`](feeds/README.md). Available lists:
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/bots.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/malware.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/research.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/alltor.txt
* https://raw.githubusercontent.com/edepree/isc-threat-feeds/master/feeds/torexit.txt

If ISC has no IPs for a feed in the last 7 days (the source went quiet), that list keeps its last contents instead of being emptied. Check a list's commit history to see when it last changed, and the [ISC Threat Feeds page](https://isc.sans.edu/data/threatfeed.html) for each source's activity.

## Projects

* [`isc-feeds/`](isc-feeds/README.md): generates the lists above.
* [`unifi-connector/`](unifi-connector/README.md): container that syncs the lists into UniFi Network traffic matching lists.
