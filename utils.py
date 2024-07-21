import ipaddress
import logging
import os
import re
from datetime import datetime
from typing import List
from urllib.parse import urlparse

import motor.motor_asyncio
import pytz
import requests
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()

client = motor.motor_asyncio.AsyncIOMotorClient(os.getenv('MONGO_DB'))
db = client[os.getenv('DB')]
collection = db[os.getenv('IP_COLLECTION')]
domain_collection = db[os.getenv('DOMAIN_COLLECTION')]
url_collection = db[os.getenv('URL_COLLECTION')]
md5_collection = db[os.getenv('MD5_COLLECTION')]
sha256_collection = db[os.getenv('SHA256_COLLECTION')]
meta_collection = db[os.getenv('META_COLLECTION')]
ip_url_collection = db[os.getenv('IP_URLS_COLLECTION')]
domain_url_collection = db[os.getenv('DOMAIN_URLS_COLLECTION')]
url_urls_collection = db[os.getenv('URL_URLS_COLLECTION')]
md5_url_collection = db[os.getenv('MD5_URL_COLLECTION')]
sha256_url_collection = db[os.getenv('SHA256_URL_COLLECTION')]
settings_collection = db[os.getenv('SETTINGS_COLLECTION')]


async def get_url_dict():
    url_dict = {}
    cursor = ip_url_collection.find()
    async for entry in cursor:
        url_dict[entry["source"]] = entry["url"]
    return url_dict


async def get_domain_url_dict():
    url_dict = {}
    cursor = domain_url_collection.find()
    async for entry in cursor:
        url_dict[entry["source"]] = entry["url"]
    return url_dict


async def get_url_url_dict():
    url_dict = {}
    cursor = url_urls_collection.find()
    async for entry in cursor:
        url_dict[entry["source"]] = entry["url"]
    return url_dict


async def get_md5_url_dict():
    url_dict = {}
    cursor = md5_url_collection.find()
    async for entry in cursor:
        url_dict[entry["source"]] = entry["url"]
    return url_dict


async def get_sha256_url_dict():
    url_dict = {}
    cursor = sha256_url_collection.find()
    async for entry in cursor:
        url_dict[entry["source"]] = entry["url"]
    return url_dict


def read_local_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    except Exception as e:
        logging.error(f"Failed to read local file {file_path}: {e}")
        return []


def convert_utc_to_ist(utc_time_str):
    IST = pytz.timezone('Asia/Kolkata')

    utc_time = datetime.fromisoformat(utc_time_str)

    utc_time = utc_time.astimezone(pytz.utc)

    ist_time = utc_time.astimezone(IST)

    return ist_time


def extract_ips_from_text(text):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ips = re.findall(ip_pattern, text)
    return ips


async def fetch_and_store_ips():
    last_updated = datetime.utcnow()
    new_ips = []
    seen_ips = set()
    url_dict = await get_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url or '194.146.13.235' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '').replace('http://194.146.13.235:8000', '')
                if file_path.startswith('/'):
                    file_path = file_path[1:]
                ip_list = read_local_file(file_path)
            else:
                response = requests.get(url)
                response.raise_for_status()
                ip_list = response.text.splitlines()

            for line in ip_list:
                ips_in_line = extract_ips_from_text(line)

                for ip in ips_in_line:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_global and ip not in seen_ips:
                            new_ips.append({"ip": ip, "source": label})
                            seen_ips.add(ip)
                        elif ip in seen_ips:
                            logging.info(f"Duplicate IP {ip} removed from {url}")
                    except ValueError:
                        logging.warning(f"Invalid IP address {ip} extracted from {url}")
        except requests.RequestException as e:
            logging.error(f"Failed to fetch IPs from {url}: {e}")

    if new_ips:
        await collection.delete_many({})
        await collection.insert_many(new_ips)
        await meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"IP addresses updated at {last_updated}")
        await cleanup_duplicates()


def extract_domains_from_text(text):
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    domains = re.findall(domain_pattern, text)
    return domains


async def fetch_and_store_domains():
    last_updated = datetime.utcnow()
    new_domains = []
    seen_domains = set()
    url_dict = await get_domain_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url or '194.146.13.235' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '').replace('http://194.146.13.235:8000', '')
                if file_path.startswith('/'):
                    file_path = file_path[1:]
                domain_list = read_local_file(file_path)
            else:
                response = requests.get(url)
                response.raise_for_status()
                domain_list = response.text.splitlines()

            for line in domain_list:
                domains_in_line = extract_domains_from_text(line)

                for domain in domains_in_line:
                    if domain not in seen_domains:
                        new_domains.append({"domain": domain, "source": label})
                        seen_domains.add(domain)
                    elif domain in seen_domains:
                        logging.info(f"Duplicate domain {domain} removed from {url}")
        except requests.RequestException as e:
            logging.error(f"Failed to fetch domains from {url}: {e}")

    if new_domains:
        await domain_collection.delete_many({})
        await domain_collection.insert_many(new_domains)
        await meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"Domains updated at {last_updated}")
        await cleanup_duplicate_domains()


def extract_urls_from_text(text):
    url_pattern = r'\b(?:https?|ftp):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|]'
    urls = re.findall(url_pattern, text, re.IGNORECASE)
    return urls


async def fetch_and_store_urls():
    last_updated = datetime.utcnow()
    new_urls = []
    seen_urls = set()
    url_dict = await get_url_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url or '194.146.13.235' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '').replace('http://194.146.13.235:8000', '')
                if file_path.startswith('/'):
                    file_path = file_path[1:]
                url_list = read_local_file(file_path)
            else:
                response = requests.get(url)
                response.raise_for_status()
                url_list = response.text.splitlines()

            for line in url_list:
                urls_in_line = extract_urls_from_text(line)

                for url1 in urls_in_line:
                    try:
                        parsed_url = urlparse(url1)
                        # Check if scheme and netloc are present
                        if parsed_url.scheme and parsed_url.netloc and url1 not in seen_urls:
                            new_urls.append({"url": url1, "source": label})
                            seen_urls.add(url1)
                        elif url1 not in seen_urls:
                            logging.info(f"Duplicate url {url1} removed from {url}")
                    except Exception as e:
                        logging.warning(f"Invalid URL {url1} extracted from {url}: {e}")
        except requests.RequestException as e:
            logging.error(f"Failed to fetch URLs from {url}: {e}")

    if new_urls:
        await url_collection.delete_many({})
        await url_collection.insert_many(new_urls)
        await meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"URLs updated at {last_updated}")
        cleanup_duplicate_urls()


def extract_md5_from_text(text: str) -> List[str]:
    md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
    return md5_pattern.findall(text)


async def fetch_and_store_md5s():
    last_updated = datetime.utcnow()
    new_md5s = []
    seen_md5s = set()
    url_dict = await get_md5_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url or '194.146.13.235' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '').replace('http://194.146.13.235:8000', '')
                if file_path.startswith('/'):
                    file_path = file_path[1:]
                md5_list = read_local_file(file_path)
            else:
                response = requests.get(url)
                response.raise_for_status()
                md5_list = extract_md5_from_text(response.text)

            for md5 in md5_list:
                if md5 not in seen_md5s:
                    new_md5s.append({"md5": md5, "source": label})
                    seen_md5s.add(md5)
                else:
                    logging.info(f"Duplicate MD5 {md5} removed from {url}")
        except requests.RequestException as e:
            logging.error(f"Failed to fetch MD5s from {url}: {e}")

    if new_md5s:
        await md5_collection.delete_many({})
        await md5_collection.insert_many(new_md5s)
        await meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"MD5 values updated at {last_updated}")


def extract_sha256_from_text(text: str) -> List[str]:
    sha256_pattern = re.compile(r'\b[A-Fa-f0-9]{64}\b')
    return sha256_pattern.findall(text)


async def fetch_and_store_sha256s():
    last_updated = datetime.utcnow()
    new_sha256s = []
    seen_sha256s = set()
    url_dict = await get_sha256_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url or '194.146.13.235' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '').replace('http://194.146.13.235:8000', '')
                if file_path.startswith('/'):
                    file_path = file_path[1:]
                sha256_list = read_local_file(file_path)
            else:
                response = requests.get(url)
                response.raise_for_status()
                sha256_list = extract_sha256_from_text(response.text)

            for sha256 in sha256_list:
                if sha256 not in seen_sha256s:
                    new_sha256s.append({"sha256": sha256, "source": label})
                    seen_sha256s.add(sha256)
                else:
                    logging.info(f"Duplicate SHA256 {sha256} removed from {url}")
        except requests.RequestException as e:
            logging.error(f"Failed to fetch SHA256s from {url}: {e}")

    if new_sha256s:
        await sha256_collection.delete_many({})
        await sha256_collection.insert_many(new_sha256s)
        await meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"SHA256 values updated at {last_updated}")


async def cleanup_duplicates():
    pipeline = [
        {"$group": {
            "_id": "$ip",
            "count": {"$sum": 1},
            "docs": {"$push": "$$ROOT"}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]

    async for duplicate in collection.aggregate(pipeline):
        docs_to_remove = duplicate["docs"][1:]
        ids_to_remove = [doc["_id"] for doc in docs_to_remove]
        await collection.delete_many({"_id": {"$in": ids_to_remove}})
        logging.info(f"Removed {len(ids_to_remove)} duplicate(s) for IP {duplicate['_id']}")


async def cleanup_duplicate_domains():
    pipeline = [
        {"$group": {
            "_id": "$domain",
            "count": {"$sum": 1},
            "docs": {"$push": "$$ROOT"}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]

    async for duplicate in domain_collection.aggregate(pipeline):
        docs_to_remove = duplicate["docs"][1:]
        ids_to_remove = [doc["_id"] for doc in docs_to_remove]
        await domain_collection.delete_many({"_id": {"$in": ids_to_remove}})
        logging.info(f"Removed {len(ids_to_remove)} duplicate(s) for domain {duplicate['_id']}")


async def cleanup_duplicate_urls():
    pipeline = [
        {"$group": {
            "_id": "$url",
            "count": {"$sum": 1},
            "docs": {"$push": "$$ROOT"}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]

    async for duplicate in url_collection.aggregate(pipeline):
        docs_to_remove = duplicate["docs"][1:]
        ids_to_remove = [doc["_id"] for doc in docs_to_remove]
        await url_collection.delete_many({"_id": {"$in": ids_to_remove}})
        logging.info(f"Removed {len(ids_to_remove)} duplicate(s) for URL {duplicate['_id']}")
