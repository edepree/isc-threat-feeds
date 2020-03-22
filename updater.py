import urllib.request
import xml.etree.ElementTree as ET 

isc_feeds = {'research': ['blindferret', 'cybergreen', 'erratasec', 'onyphe', 'rapid7sonar', 'shadowserver', 'shodan', 'univmichigan']}

for category, feeds in isc_feeds.items():
    with open(f'{category}.txt', 'w') as output_file:
        for feed in feeds:
            feed_url = f'https://isc.sans.edu/api/threatlist/{feed}'
            html_request = urllib.request.urlopen(feed_url).read()
            root = ET.fromstring(html_request)
            for element in root.findall(feed):
                output_file.write(element.find('ipv4').text + '\n')
