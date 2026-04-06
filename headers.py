def check_headers(response):
    print("\n[+] Checking Headers")
    headers = response.headers

    # List of headers
    headers_list = ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

    # Loops through the headers list and prints if found or not
    for header in headers_list:
        if header not in headers:
            print(f"[!] Missing Header: {header}")
        else:
            print(f"[+] Header Found: {header}: {headers[header]}")
