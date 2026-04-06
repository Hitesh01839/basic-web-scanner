import requests

def send_request(url, method="GET", data=None, cookies=None):
    try:
        if method == "GET":
            response = requests.get(url, timeout=5, cookies=cookies) 
            return response

        elif method == "POST":
            response = requests.post(url, data=data, timeout=5, cookies=cookies)
            return response
        

    except requests.exceptions.MissingSchema: # Hanldes missing schema error
        print("Error: Invalid URL add http:// or https://")
        return None

    except requests.exceptions.ConnectionError: # Error handling for connection error
        print("Connection Error")
        return None

    except requests.exceptions.Timeout: # Error handling for timeout error
        print("Timeout Error")
        return None

    except requests.exceptions.RequestException as e: # Error handling for any other error
        print(e)
        return None