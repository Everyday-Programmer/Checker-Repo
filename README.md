# IOC Checker API
### IP Check
The `ipCheck` endpoint verifies if a given ip is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /ipCheck/
```
# Query Parameters
- ip (required): The IP address to be checked.
# Headers
- X-API-Key (required): The API key used for authentication.<br>
# Response
- 200 OK (Found): Indicates that the given IP address exists in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the IP address does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
# Curl
```
curl -G "http://localhost:8000/ipCheck/" \
     --data-urlencode "ip=192.168.0.1" \
     -H "X-API-Key: your_api_key"
```
# Example Responses
200 OK (IP found)
```
{
    "exists": "True",
    "ip": "192.168.0.1",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 10
}
```
200 OK (IP not found)
```
{
    "exists": "False",
    "last_updated": "2024-07-04T12:00:00Z"
}
```
401 Unauthorized
```
{
  "detail": "Invalid API Key"
}
```
Domain Check API
The `domainCheck` endpoint verifies if a given domain is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /domainCheck/
```
# Query Parameters
- domain (required): The domain name to be checked.
# Headers
- X-API-Key (required): The API key used for authentication.
# Response
- 200 OK (Found): Indicates that the given domain exists in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the domain does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
# Curl
```
curl -G "http://localhost:8000/domainCheck/" \
     --data-urlencode "domain=example.com" \
     -H "X-API-Key: your_api_key"
```
# Example Responses
200 OK (IP found)
```
{
    "exists": "True",
    "domain": "example.com",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 5
}
```
200 OK (IP not found)
```
{
    "exists": "False",
    "last_updated": "2024-07-04T12:00:00Z"
}
```
401 Unauthorized
```
{
  "detail": "Invalid API Key"
}
```
URL Check API
The `urlCheck` endpoint verifies if a given url is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /urlCheck/
```
# Query Parameters
- url (required): The url to be checked.
# Headers
- X-API-Key (required): The API key used for authentication.
# Response
- 200 OK (Found): Indicates that the given url in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the url does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
# Curl
```
curl -G "http://localhost:8000/urlCheck/" \
     --data-urlencode "url=http://example.com/path" \
     -H "X-API-Key: your_api_key"
```
# Example Responses
200 OK (IP found)
```
{
    "exists": "True",
    "url": "http://example.com/path",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 3
}
```
200 OK (IP not found)
```
{
    "exists": "False",
    "last_updated": "2024-07-04T12:00:00Z"
}
```
401 Unauthorized
```
{
  "detail": "Invalid API Key"
}
```

The `count` field gives the number of times the IP or domain or url was checked.
