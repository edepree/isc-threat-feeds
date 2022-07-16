import json
import boto3
import requests

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
        
        ipv4_addresses = set()
        for element in response_content:
            ipv4_address = element['ipv4']
            ipv4_addresses.add(ipv4_address)

        ipv4_addresses_string = '\n'.join(ipv4_addresses)

        s3 = boto3.client('s3')
        s3.put_object(Bucket='REPLACE_ME', Key=f'{file_name}.txt', Body=ipv4_addresses_string, ACL='public-read')


# if __name__ == '__main__':
#    lambda_handler(None, None)
