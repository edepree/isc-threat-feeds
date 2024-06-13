import requests

from boto3 import client
from ipaddress import IPv4Address
from ipaddress import collapse_addresses

def lambda_handler(event, context):
    threat_category_names = ['research']
    threat_feed_names = ['torexit']

    for threat_category_name in threat_category_names:
        response = requests.get(f'https://isc.sans.edu/api/threatcategory/{threat_category_name}?json')
        process_response(response, threat_category_name)

    for threat_feed_name in threat_feed_names:
        response = requests.get(f'https://isc.sans.edu/api/threatlist/{threat_feed_name}?json')
        process_response(response, threat_feed_name)

def process_response(response, file_name):
    print(f'HTTP Response: {response.status_code}')

    if response.status_code == requests.codes.ok:
        response_content = response.json()
        
        network_addresses = []

        for element in response_content:
            network_addresses.append(IPv4Address(element['ipv4']))

        condensed_addresses = collapse_addresses(network_addresses)
        condensed_addresses_str = '\n'.join([x.with_prefixlen for x in condensed_addresses])

        s3 = client('s3')
        s3.put_object(Bucket='isc-threat-feed-storage', Key=f'{file_name}.txt', Body=condensed_addresses_str, ACL='public-read')

if __name__ == '__main__':
   lambda_handler(None, None)
