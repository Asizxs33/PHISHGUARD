import urllib.request
import json

try:
    req = urllib.request.Request("http://localhost:8000/api/dangerous-domains")
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        print("Success:", data)
except Exception as e:
    print("Error:", e)
    if hasattr(e, 'read'):
        print("Response body:", e.read().decode())
