import ipaddress
import logging
from typing import Any

import requests
from flask import Flask, Response, abort, redirect, request

app = Flask(__name__)

if __name__ != '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)

def process_response(response: requests.Response) -> str:
    """
    Processes the HTTP response from the ISC SANS API, extracts IPv4 addresses,
    condenses contiguous addresses into larger subnets, and formats the result
    as a newline-delimited string of subnets in CIDR notation.
    """
    try:
        response_content = response.json()

        network_addresses = [ipaddress.IPv4Address(i['ipv4']) for i in response_content]
        condensed_addresses = ipaddress.collapse_addresses(network_addresses)

        return '\n'.join([x.with_prefixlen for x in condensed_addresses])
    except Exception as e:
        app.logger.error(f'Processing Error: {e}')
        abort(500, description='Processing error')

@app.errorhandler(404)
def page_not_found(error: Any) -> Response:
    return redirect('https://github.com/edepree/isc-threat-feeds'), 302

@app.route('/health', methods=['GET'])
def health() -> Response:
    return Response('ok', mimetype='text/plain')

@app.route('/threatcategory/<any(bots, malware, research):threat_category_name>', methods=['GET'])
def get_threat_category(threat_category_name: str) -> Response:
    try:
        response = requests.get(
            f'https://isc.sans.edu/api/threatcategory/{threat_category_name}?json',
            timeout=10
        )
        response.raise_for_status()

        addresses = process_response(response)
        app.logger.info(f'request from "{request.remote_addr}" for threat category "{threat_category_name}"')

        return Response(addresses, mimetype='text/plain')
    except requests.RequestException as e:
        app.logger.error(f'Upstream Error: {e}')
        abort(502, description='Upstream Service Error')

@app.route('/threatlist/<any(alltor, torexit):threat_feed_name>', methods=['GET'])
def get_threat_list(threat_feed_name: str) -> Response:
    try:
        response = requests.get(
            f'https://isc.sans.edu/api/threatlist/{threat_feed_name}?json',
            timeout=10
        )
        response.raise_for_status()

        addresses = process_response(response)
        app.logger.info(f'request from "{request.remote_addr}" for threat list "{threat_feed_name}"')

        return Response(addresses, mimetype='text/plain')
    except requests.RequestException as e:
        app.logger.error(f'Upstream Error: {e}')
        abort(502, description='Upstream Service Error')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
