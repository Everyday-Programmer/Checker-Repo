# IOC Checker API
IP Check
The `ipCheck` endpoint is used to verify if an IP is an Indicator of Compromise (IOC).
Endpoint:
``` GET /ipCheck/ ```
# Query Parameters
- ip (required): The IP address to be checked.
Headers
- X-API-Key (required): The API key used for authentication.
Response
- 200 OK: Indicates that the IP address exists in the database, marking it as an Indicator of Compromise (IOC).
- 404 Not Found: Indicates that the IP address does not exist in the database.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
Curl
```
curl -G "http://localhost:8000/ipCheck/" \
     --data-urlencode "ip=192.168.0.1" \
     -H "X-API-Key: your_api_key"
```
