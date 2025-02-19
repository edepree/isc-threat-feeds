from flask import Flask, Response, abort, redirect
import requests
import ipaddress

app = Flask(__name__)

def process_response(response):
    if response.status_code == requests.codes.ok:
        response_content = response.json()

        # convert addresses returned into IPv4Address
        network_addresses = [ipaddress.IPv4Address(i['ipv4']) for i in response_content]

        # condense contigious addresses returned into larger subnets
        condensed_addresses = ipaddress.collapse_addresses(network_addresses)

        # extract relevant network information and format into a new line delimited string
        results = '\n'.join([x.with_prefixlen for x in condensed_addresses])
        return results
    else:
        abort(response.status_code)

@app.errorhandler(404)
def page_not_found():
    return redirect('https://github.com/edepree/isc-threat-feeds'), 302

@app.route('/threatcategory/<any(bots, malware, research):threat_category_name>', methods=['GET'])
def get_threat_category(threat_category_name):
    response = requests.get(f'https://isc.sans.edu/api/threatcategory/{threat_category_name}?json')
    addresses = process_response(response)
    return Response(addresses, mimetype='text/plain')

@app.route('/threatlist/<any(alltor, torexit):threat_feed_name>', methods=['GET'])
def get_threat_list(threat_feed_name):
    response = requests.get(f'https://isc.sans.edu/api/threatlist/{threat_feed_name}?json')
    addresses = process_response(response)
    return Response(addresses, mimetype='text/plain')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
