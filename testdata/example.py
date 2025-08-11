print("Hello world")
import requests
import os
from requests import Session
from requests.adapters import HTTPAdapter

response = requests.get("https://api.github.com")
print(response.status_code)

requests.post("https://httpbin.org/post", json={"key": "value"})
os.path.join("/", "home")
session = Session()
adapter = HTTPAdapter()
# requests.auth.HTTPBasicAuth("user", "pass")