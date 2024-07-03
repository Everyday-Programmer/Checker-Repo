# IOC Checker API
IP Check
The `ipCheck` endpoint is used to verify if an IP is an Indicator of Compromise (IOC).<br>
Endpoint:
```
GET /ipCheck/
```
# Query Parameters
- ip (required): The IP address to be checked.
Headers
- X-API-Key (required): The API key used for authentication.<br>
# Response
- 200 OK: Indicates that the given IP address exists in blocklist, marking it as an Indicator of Compromise (IOC).
- 404 Not Found: Indicates that the IP address does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
Curl
```
curl -G "http://localhost:8000/ipCheck/" \
     --data-urlencode "ip=192.168.0.1" \
     -H "X-API-Key: your_api_key"
```
# Example Responses
200 OK
```
{
    "exists": "True",
    "ip": "192.168.0.1",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 10
}
```
