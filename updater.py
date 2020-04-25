import os
import logging
import argparse
import urllib.request
import xml.etree.ElementTree as ET 

def process_feed(feed_name, output_folder):
    """Download, parse, and output feeds from the Internet Storm Center into flat files with one IP per line."""

    isc_feeds = {'research': ['blindferret', 'cybergreen', 'erratasec', 'onyphe', 'rapid7sonar', 'shadowserver', 'shodan', 'univmichigan'],
                 'others': ['torexit', 'miner']}

    for category, feeds in isc_feeds.items():
        if feed_name != 'all' and category != feed_name:
            logging.debug(f'Ignoring feed: {category}')
        else:
            logging.debug(f'Processing feed: {category}')

            with open(f'{output_folder}{os.sep}{category}.txt', 'w') as output_file:
                logging.debug(f'Writing to file: {output_file.name}')

                for feed in feeds:
                    feed_url = f'https://isc.sans.edu/api/threatlist/{feed}'
                    html_request = urllib.request.urlopen(feed_url).read()
                    root = ET.fromstring(html_request)
                    
                    for element in root.findall(feed):
                        output_file.write(element.find('ipv4').text + '\n')


def validate_directory(path):
    """An argparse validator to confirm user input is a valid directory."""

    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f'cannot find directory {path}')


def main():
    """Bootstrapping function including argument parsing and setting up logging."""

    parser = argparse.ArgumentParser(description="""A parser for converting thread feeds from the
                                                    Internet Storm Center into IPv4 lists for consumption
                                                    by other tools/processes.""",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    
    parser.add_argument('--feed', dest='threat_feed', choices=['research', 'others', 'all'], default='all',
                        help='the thread feed(s) to process')
    parser.add_argument('--output', dest='output_directory', type=validate_directory, default=os.getcwd(),
                        help='the output directory for the parsed feeds')
    parser.add_argument('--debug', dest='logging_level', action='store_const', const=logging.DEBUG,
                        default=logging.INFO, help='enable debug logging')
    
    args = parser.parse_args()
    logging.basicConfig(format='%(levelname)-8s %(message)s', level=args.logging_level)

    logging.info(f'Processing the threat feed: {args.threat_feed}')
    logging.info(f'Outputting results to: {args.output_directory}') 
    process_feed(args.threat_feed, args.output_directory)


if __name__ == '__main__':
    main()
