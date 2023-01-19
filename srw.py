from flask import Flask, request, jsonify
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import requests

# Configure the options for the headless browser
options = Options()
options.add_argument("--headless")
options.add_argument("--disable-extensions")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--remote-debugging-port=9222")
options.add_argument("--no-sandbox")
options.add_argument("start-maximized")
options.add_argument("disable-infobars")
options.add_argument("--disable-dev-shm-usage")
options.add_argument("--disable-browser-side-navigation")
options.add_argument("--disable-gpu")

app = Flask(__name__)

class AnalysisServer:
    def __init__(self):
        self.protocol = "h2c"

    def analyze_domain(self, domain):
        try:
            # Send an HTTPS request to the domain
            response = requests.get("https://"+ domain, headers={"Upgrade-Insecure-Requests": "1"}, timeout=10)

            # Check if the response is using SOAP
            if "application/soap+xml" in response.headers.get("Content-Type"):
                print("SOAP detected")
                # Extract and print the SOAP parameters and values
                soap_data = response.text
                return jsonify({"Protocol": "SOAP", "Data": soap_data})
                
            # Check if the response is using REST
            elif "application/json" in response.headers.get("Content-Type"):
                print("REST detected")
                # Extract and print the REST parameters and values
                rest_data = json.loads(response.text)
                return jsonify({"Protocol": "REST", "Data": rest_data})
                
            # Check if the response is using WebSocket
            elif "Sec-WebSocket-Accept" in response.headers:
                print("WebSocket detected")
                # Extract and print the WebSocket parameters and values
                ws_param = response.headers.get("Sec-WebSocket-Accept")
                return jsonify({"Protocol": "WebSocket", "Data": ws_param})

            else:
                return jsonify({"Error": "No supported protocols detected"})
                
        except requests.exceptions.RequestException as e:
            return jsonify({"Error": "Error connecting to the domain: " + str(e)})

@app.route('/analyze', methods=['GET'])
def analyze():
    domain = request.args.get('domain')
    if domain is None:
        return jsonify({"Error": "No domain provided"})
    # Create the browser instance
    browser = webdriver.Chrome(chrome_options=options)
    # Navigate to the page
    browser.get(domain)
    # Extract the URLs of all the asynchronous requests being made
    requests = browser.execute_script("return window.performance.getEntries()")
    # Initialize an empty list to hold the analysis results
    results = []
    # Iterate through the list of requests
    for request in requests:
        if request["initiatorType"] == "xmlhttprequest":
            url = request["name"]
            server = AnalysisServer()
            result = server.analyze_domain(url)
            results.append(result)
    # Close the browser
    browser.quit()
    return jsonify({"Results": results})

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
