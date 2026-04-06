from sqli import check_sqli
from xss import check_xss
from utils import send_request
import argparse
from headers import check_headers

parser = argparse.ArgumentParser(
    description="Web Vulnerability Scanner — Detect SQLi, XSS, and insecure headers.",
    epilog="Example: %(prog)s -u https://example.com -c 'session=abc123'",
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

parser.add_argument(
    "-u", "--url",
    required=True,
    metavar="URL",
    help="Target website URL to scan",
)
parser.add_argument(
    "-c", "--cookie",
    metavar="COOKIE",
    help="Authentication cookie string (e.g. 'key1=val1; key2=val2')",
)

args = parser.parse_args()

url = args.url

cookies = {}
if args.cookie:
    for item in args.cookie.split(";"):
        item = item.strip()
        if "=" in item:
            key, value = item.split("=", 1)
            cookies[key.strip()] = value.strip()

response = send_request(url, cookies=cookies)

check_xss(url, cookies)
check_headers(response)
check_sqli(url, cookies)