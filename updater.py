import json
import boto3
import urllib.request
import xml.etree.ElementTree as ET 

def lambda_handler(event, context):
    research_list_names = ['blindferret', 'cybergreen', 'erratasec', 'onyphe',
                           'rapid7sonar', 'shadowserver', 'shodan', 'univmichigan']
    research_list_ips = ''

    s3_bucket = 'REPLACE_ME'
    s3 = boto3.client('s3')

    threat_feeds_url = 'https://isc.sans.edu/api/threatfeeds/'
    html_request = urllib.request.urlopen(threat_feeds_url).read()
    root = ET.fromstring(html_request)

    for element in root.findall('threatfeed'):
        if element.find('datatype').text == 'is_ipv4':
            threat_list_name = element.find('type').text
            threat_list_url = f'https://isc.sans.edu/api/threatlist/{threat_list_name}'
            #print(f'Found {threat_list_name}')

            html_request = urllib.request.urlopen(threat_list_url).read()
            root = ET.fromstring(html_request)

            threat_list_ips = ''
            for element in root.findall(threat_list_name):
                threat_list_ips += element.find('ipv4').text + '\n'

            if len(threat_list_ips) > 0:
                #print(threat_list_ips)
                s3.put_object(Bucket=s3_bucket, Key=f'{threat_list_name}.txt',
                              Body=threat_list_ips, ACL='public-read')

                if threat_list_name in research_list_names:
                    research_list_ips += threat_list_ips

    s3.put_object(Bucket=s3_bucket, Key='research-combine.txt',
                  Body=research_list_ips, ACL='public-read')


#if __name__ == '__main__':
#    lambda_handler(None, None)
