import urllib.request
import xml.etree.ElementTree as ET 

feeds = ['blindferret', 'cybergreen', 'erratasec', 'onyphe', 'rapid7sonar', 'shadowserver', 'shodan', 'univmichigan']

for feed in feeds:
    feed_url = f'https://isc.sans.edu/api/threatlist/{feed}'
    print(f'Processing: {feed_url}')
    html_request = urllib.request.urlopen(feed_url).read()
    
    with open(f'{feed}.txt', 'w') as output_file:
        print(f'Writing: {output_file.name}')
        root = ET.fromstring(html_request)
        for element in root.findall(feed):
            output_file.write(element.find('ipv4').text + '\n')