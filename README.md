# IOC Checker API
### IP Check
The `ipCheck` endpoint verifies if a given ip is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /ipCheck/
```
### Query Parameters
- ip (required): The IP address to be checked.
### Headers
- X-API-Key (required): The API key used for authentication.<br>
### Response
- 200 OK (Found): Indicates that the given IP address exists in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the IP address does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
### Curl
```
curl -G "http://localhost:8000/ipCheck/" \
     --data-urlencode "ip=192.168.0.1" \
     -H "X-API-Key: your_api_key"
```
### Example Responses
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
### Domain Check API
The `domainCheck` endpoint verifies if a given domain is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /domainCheck/
```
### Query Parameters
- domain (required): The domain name to be checked.
### Headers
- X-API-Key (required): The API key used for authentication.
### Response
- 200 OK (Found): Indicates that the given domain exists in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the domain does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
### Curl
```
curl -G "http://localhost:8000/domainCheck/" \
     --data-urlencode "domain=example.com" \
     -H "X-API-Key: your_api_key"
```
### Example Responses
200 OK (Domain found)
```
{
    "exists": "True",
    "domain": "example.com",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 5
}
```
200 OK (Domain not found)
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
### URL Check API
The `urlCheck` endpoint verifies if a given url is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /urlCheck/
```
### Query Parameters
- url (required): The url to be checked.
### Headers
- X-API-Key (required): The API key used for authentication.
### Response
- 200 OK (Found): Indicates that the given url is in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the url does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
### Curl
```
curl -G "http://localhost:8000/urlCheck/" \
     --data-urlencode "url=http://example.com/path" \
     -H "X-API-Key: your_api_key"
```
### Example Responses
200 OK (URL found)
```
{
    "exists": "True",
    "url": "http://example.com/path",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 3
}
```
200 OK (URL not found)
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
### MD5 Check API
The `md5Check` endpoint verifies if a given md5 is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /md5Check/
```
### Query Parameters
- md5 (required): The md5 to be checked.
### Headers
- X-API-Key (required): The API key used for authentication.
### Response
- 200 OK (Found): Indicates that the given md5 is in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the md5 does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
### Curl
```
curl -G "http://localhost:8000/md5Check/" \
     --data-urlencode "md5=1a79a4d60de6718e8e5b326e338ae533" \
     -H "X-API-Key: your_api_key"
```
### Example Responses
200 OK (SHA256 found)
```
{
    "exists": "True",
    "md5": "1a79a4d60de6718e8e5b326e338ae533",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 3
}
```
200 OK (MD5 not found)
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
### SHA256 Check API
The `sha256Check` endpoint verifies if a given sha256 is present in the blocklist, indicating it as a potential Indicator of Compromise (IOC).
Endpoint:
```
GET /sha256Check/
```
### Query Parameters
- sha256 (required): The sha256 to be checked.
### Headers
- X-API-Key (required): The API key used for authentication.
### Response
- 200 OK (Found): Indicates that the given sha256 is in blocklist, marking it as an Indicator of Compromise (IOC).
- 200 OK (Not Found): Indicates that the sha256 does not exist in the blocklist.
- 401 Unauthorized: Indicates that the provided API key is missing or invalid.
### Curl
```
curl -G "http://localhost:8000/sha256Check/" \
     --data-urlencode "sha256=2d711642b726b04401627ca9fbac32f5d9d4c3033f1d8b0b8d1378c42d7cc13d" \
     -H "X-API-Key: your_api_key"
```
### Example Responses
200 OK (SHA256 found)
```
{
    "exists": "True",
    "sha256": "2d711642b726b04401627ca9fbac32f5d9d4c3033f1d8b0b8d1378c42d7cc13d",
    "source": "Blocklist.de",
    "last_updated": "2024-07-04T12:00:00Z",
    "count": 3
}
```
200 OK (SHA256 not found)
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
The `count` field gives the number of times the IP or domain or url or md5 or sha256 was checked.
