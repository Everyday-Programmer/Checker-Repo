import ipaddress
import logging
import os
import re
import threading
from datetime import datetime
from urllib.parse import urlparse

import requests
import socketio
from apscheduler.schedulers.blocking import BlockingScheduler
from dotenv import load_dotenv
from fastapi import FastAPI
from flask_socketio import emit
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError, OperationFailure

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()

app = FastAPI()

# Create a Socket.IO server
sio = socketio.AsyncServer(async_mode='asgi')
app.mount("/socket.io", socketio.ASGIApp(sio))

client = MongoClient(os.getenv('MONGO_DB'))
db = client["checker"]
collection = db["ip_addresses"]
domain_collection = db["domains"]
url_collection = db["urls"]
meta_collection = db["metadata"]
ip_url_collection = db["ip_urls"]
domain_url_collection = db["domain_urls"]
url_url_collection = db["url_urls"]


# collection.create_index([("ip", ASCENDING)], unique=True)
# domain_collection.create_index([("domain", ASCENDING)], unique=True)
# url_collection.create_index([("url", ASCENDING)], unique=True)

def get_url_dict():
    url_dict = {}
    for entry in ip_url_collection.find():
        if entry["source"] != "trigger":
            url_dict[entry["source"]] = entry["url"]
    return url_dict


def get_domain_url_dict():
    url_dict = {}
    for entry in domain_url_collection.find():
        url_dict[entry["source"]] = entry["url"]
    return url_dict


def get_url_url_dict():
    url_dict = {}
    for entry in url_url_collection.find():
        url_dict[entry["source"]] = entry["url"]
    return url_dict


def read_local_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    except Exception as e:
        logging.error(f"Failed to read local file {file_path}: {e}")
        return []


def extract_ips_from_text(text):
    # Regex to find IPv4 and IPv6 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'

    # Find all occurrences of IPs in the text
    ips = re.findall(ip_pattern, text)

    return ips


@sio.event
async def connect(sid, environ):
    await sio.emit('log_message', {'data': 'Connected to server'})


def fetch_and_store_ips():
    last_updated = datetime.utcnow()
    new_ips = []
    seen_ips = set()
    url_dict = get_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '')
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
                            sio.emit('log_message', {'data': f"Duplicate IP {ip} removed from {url}"})
                    except ValueError:
                        logging.warning(f"Invalid IP address {ip} extracted from {url}")
                        sio.emit('log_message', {'data': f"Invalid IP address {ip} extracted from {url}"})
        except requests.RequestException as e:
            sio.emit('log_message', {'data': f"Failed to fetch IPs from {url}: {e}"})
            logging.error(f"Failed to fetch IPs from {url}: {e}")

    if new_ips:
        collection.delete_many({})
        collection.insert_many(new_ips)
        meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"IP addresses updated at {last_updated}")
        sio.emit('log_message', {'data': f"IP addresses updated at {last_updated}"})
        # cleanup_duplicates()


def extract_domains_from_text(text):
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'

    domains = re.findall(domain_pattern, text)

    return domains


def fetch_and_store_domains():
    last_updated = datetime.utcnow()
    new_domains = []
    seen_domains = set()
    url_dict = get_domain_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '')
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
                        sio.emit('log_message', {'data': f"Duplicate domain {domain} removed from {url}"})
        except requests.RequestException as e:
            logging.error(f"Failed to fetch domains from {url}: {e}")
            sio.emit('log_message', {'data': f"Failed to fetch domains from {url}: {e}"})

    if new_domains:
        domain_collection.delete_many({})
        domain_collection.insert_many(new_domains)
        meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"Domains updated at {last_updated}")
        sio.emit('log_message', {'data': f"Domains updated at {last_updated}"})
        # cleanup_duplicate_domains()


def extract_urls_from_text(text):
    url_pattern = r'\b(?:https?|ftp):\/\/[-A-Z0-9+&@#\/%?=~_|!:,.;]*[-A-Z0-9+&@#\/%=~_|]'

    urls = re.findall(url_pattern, text, re.IGNORECASE)

    return urls


def fetch_and_store_urls():
    last_updated = datetime.utcnow()
    new_urls = []
    seen_urls = set()
    url_dict = get_url_url_dict()

    for label, url in url_dict.items():
        try:
            if 'localhost' in url or '127.0.0.1' in url or '156.67.80.79' in url:
                file_path = url.replace('http://localhost:8000', '').replace('http://127.0.0.1:8000', '').replace(
                    'http://156.67.80.79:8000', '')
                if file_path.startswith('/'):
                    file_path = file_path[1:]
                url_list = read_local_file(file_path)
            else:
                response = requests.get(url)
                response.raise_for_status()
                url_list = response.text.splitlines()

            for line in url_list:
                # Extract URLs from each line of text
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
                            sio.emit('log_message', {'data': f"Domains updated at {last_updated}"})
                    except Exception as e:
                        logging.warning(f"Invalid URL {url} extracted from {url}: {e}")
                        sio.emit('log_message', {'data': f"Invalid URL {url} extracted from {url}: {e}"})
        except requests.RequestException as e:
            logging.error(f"Failed to fetch URLs from {url}: {e}")
            sio.emit('log_message', {'data': f"Failed to fetch URLs from {url}: {e}"})

    if new_urls:
        url_collection.delete_many({})
        url_collection.insert_many(new_urls)
        meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        logging.info(f"URLs updated at {last_updated}")
        sio.emit('log_message', {'data': f"URLs updated at {last_updated}"})
        # cleanup_duplicate_urls()


def listen_for_updates():
    previous_ips = get_url_dict()
    previous_domains = get_domain_url_dict()
    previous_urls = get_url_url_dict()

    while True:
        current_ips = get_url_dict()
        current_domains = get_domain_url_dict()
        current_urls = get_url_url_dict()

        if previous_ips != current_ips:
            fetch_and_store_ips()
            previous_ips = current_ips

        if previous_domains != current_domains:
            fetch_and_store_domains()
            previous_domains = current_domains

        if previous_urls != current_urls:
            fetch_and_store_urls()
            previous_urls = current_urls


def cleanup_duplicates():
    pipeline = [
        {"$group": {
            "_id": "$ip",
            "count": {"$sum": 1},
            "docs": {"$push": "$$ROOT"}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]

    duplicates = list(collection.aggregate(pipeline))

    for duplicate in duplicates:
        docs_to_remove = duplicate["docs"][1:]
        ids_to_remove = [doc["_id"] for doc in docs_to_remove]
        collection.delete_many({"_id": {"$in": ids_to_remove}})
        logging.info(f"Removed {len(ids_to_remove)} duplicate(s) for IP {duplicate['_id']}")


def cleanup_duplicate_domains():
    pipeline = [
        {"$group": {
            "_id": "$domain",
            "count": {"$sum": 1},
            "docs": {"$push": "$$ROOT"}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]

    duplicates = list(domain_collection.aggregate(pipeline))

    for duplicate in duplicates:
        docs_to_remove = duplicate["docs"][1:]
        ids_to_remove = [doc["_id"] for doc in docs_to_remove]
        domain_collection.delete_many({"_id": {"$in": ids_to_remove}})
        logging.info(f"Removed {len(ids_to_remove)} duplicate(s) for domain {duplicate['_id']}")


def cleanup_duplicate_urls():
    pipeline = [
        {"$group": {
            "_id": "$url",
            "count": {"$sum": 1},
            "docs": {"$push": "$$ROOT"}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]

    duplicates = list(url_collection.aggregate(pipeline))

    for duplicate in duplicates:
        docs_to_remove = duplicate["docs"][1:]
        ids_to_remove = [doc["_id"] for doc in docs_to_remove]
        url_collection.delete_many({"_id": {"$in": ids_to_remove}})
        logging.info(f"Removed {len(ids_to_remove)} duplicate(s) for URL {duplicate['_id']}")


scheduler = BlockingScheduler()
scheduler.add_job(fetch_and_store_ips, 'interval', hours=2)
scheduler.add_job(fetch_and_store_domains, 'interval', hours=2)
scheduler.add_job(fetch_and_store_urls, 'interval', hours=2)


# scheduler.add_job(listen_for_updates, 'interval', minutes=1)

def ensure_replica_set_initiated():
    global sync_client
    try:
        sync_client = MongoClient("mongodb://host.docker.internal:27017/")
        # Attempt to check the replica set status
        rs_status = client.admin.command("replSetGetStatus")
        logging.info("Replica set already initiated")
    except OperationFailure as e:
        if e.details.get('code') == 94:
            logging.info("Initiating replica set")
            sync_client.admin.command("replSetInitiate")
        else:
            raise e
    except ServerSelectionTimeoutError:
        logging.error("Could not connect to MongoDB server. Ensure MongoDB is running.")


if __name__ == "__main__":
    # ensure_replica_set_initiated()
    threading.Thread(target=listen_for_updates, daemon=True).start()
    fetch_and_store_ips()
    fetch_and_store_domains()
    fetch_and_store_urls()
    scheduler.start()
