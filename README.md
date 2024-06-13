# isc-threat-feeds
A parser, and the output files, for converting thread feeds from the Internet Storm Center into IPv4 lists for consumption by other tools/processes.

This is running as a daily AWS Lambda job and results can be found at https://isc-threat-feed-storage.s3.amazonaws.com/

As the requests library is use, it must be packaged with the `lambda-function.py` file before being uploaded to Amazon.

## Environment Setup
A basic pattern for setting up virtual environment when performing development

```bash
# create a virtual environment
python3 -m venv .venv
# activate the newly created environment
source .venv/bin/activate
# update pip
python -m pip install --upgrade pip
# install required python libraries
pip install -r requirements.txt
```
