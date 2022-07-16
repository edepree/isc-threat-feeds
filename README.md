# isc-threat-feeds
A parser, and the output files, for converting thread feeds from the Internet Storm Center into IPv4 lists for consumption by other tools/processes.

This is running as a daily AWS Lambda job and results can be found at https://isc-threat-feed-storage.s3.amazonaws.com/

As the requests library is use, it must be packaged with the `lambda-function.py` file before being uploaded to Amazon.
