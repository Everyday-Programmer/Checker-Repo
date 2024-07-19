import asyncio
import logging
import os
import threading

import motor.motor_asyncio
from apscheduler.schedulers.blocking import BlockingScheduler
#from cachetools import TTLCache
from dotenv import load_dotenv

from utils import fetch_and_store_ips, fetch_and_store_domains, fetch_and_store_urls

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

#cache = TTLCache(maxsize=1000, ttl=3600)

asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())


#def reset_all_cache():
    #cache.clear()


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


async def listen_for_updates():
    previous_ips = await get_url_dict()
    previous_domains = await get_domain_url_dict()
    previous_urls = await get_url_url_dict()
    previous_md5s = await get_md5_url_dict()
    previous_sha256s = await get_sha256_url_dict()

    while True:
        current_ips = await get_url_dict()
        current_domains = await get_domain_url_dict()
        current_urls = await get_url_url_dict()
        current_md5s = await get_md5_url_dict()
        current_sha256 = await get_sha256_url_dict()

        if previous_ips != current_ips:
            logging.info("IP list changed. Fetching and storing new IPs.")
            await fetch_and_store_ips()
            # reset_all_cache()
            previous_ips = current_ips

        if previous_domains != current_domains:
            logging.info("Domain list changed. Fetching and storing new domains.")
            await fetch_and_store_domains()
            # reset_all_cache()
            previous_domains = current_domains

        if previous_urls != current_urls:
            logging.info("URL list changed. Fetching and storing new URLs.")
            await fetch_and_store_urls()
            # reset_all_cache()
            previous_urls = current_urls

        if previous_md5s != current_md5s:
            logging.info("MD5 list changed. Fetching and storing new URLs.")
            await fetch_and_store_md5s()
            # reset_all_cache()
            previous_urls = current_urls

        if previous_sha256s != current_sha256:
            logging.info("SHA256 list changed. Fetching and storing new URLs.")
            await fetch_and_store_sha256s()
            # reset_all_cache()
            previous_urls = current_urls

async def listen_for_settings_updates():
    global update_interval
    global automatic_update
    global scheduler

    previous_interval = update_interval
    previous_automatic_update = automatic_update

    settings_document = await settings_collection.find_one({"_id": 1})
    current_update_interval = settings_document["update_interval"] if settings_document else 1
    current_automatic_update = settings_document["enable_automatic_update"] if settings_document else True

    if previous_interval != current_update_interval:
        logging.info("Update interval changed. Updating scheduler.")
        update_interval = current_update_interval

        if scheduler.get_job("fetch_and_store_ips"):
            scheduler.remove_job(job_id="fetch_and_store_ips")
        if scheduler.get_job("fetch_and_store_domains"):
            scheduler.remove_job(job_id="fetch_and_store_domains")
        if scheduler.get_job("fetch_and_store_urls"):
            scheduler.remove_job(job_id="fetch_and_store_urls")
        if scheduler.get_job("fetch_and_store_md5s"):
            scheduler.remove_job(job_id="fetch_and_store_md5s")
        if scheduler.get_job("fetch_and_store_sha256s"):
            scheduler.remove_job(job_id="fetch_and_store_sha256s")
        if automatic_update:
            scheduler.add_job(fetch_and_store_ips, 'interval', hours=update_interval, id="fetch_and_store_ips")
            scheduler.add_job(fetch_and_store_domains, 'interval', hours=update_interval,
                              id="fetch_and_store_domains")
            scheduler.add_job(fetch_and_store_urls, 'interval', hours=update_interval, id="fetch_and_store_urls")
            scheduler.add_job(fetch_and_store_md5s, 'interval', hours=update_interval, id="fetch_and_store_md5s")
            scheduler.add_job(fetch_and_store_sha256s, 'interval', hours=update_interval, id="fetch_and_store_sha256s")

    if previous_automatic_update != current_automatic_update:
        logging.info("Automatic update setting changed. Updating scheduler.")
        automatic_update = current_automatic_update

        if scheduler.get_job("fetch_and_store_ips"):
            scheduler.remove_job(job_id="fetch_and_store_ips")
        if scheduler.get_job("fetch_and_store_domains"):
            scheduler.remove_job(job_id="fetch_and_store_domains")
        if scheduler.get_job("fetch_and_store_urls"):
            scheduler.remove_job(job_id="fetch_and_store_urls")
        if scheduler.get_job("fetch_and_store_md5s"):
            scheduler.remove_job(job_id="fetch_and_store_md5s")
        if scheduler.get_job("fetch_and_store_sha256s"):
            scheduler.remove_job(job_id="fetch_and_store_sha256s")
        if current_automatic_update:
            scheduler.add_job(fetch_and_store_ips, 'interval', hours=update_interval, id="fetch_and_store_ips")
            scheduler.add_job(fetch_and_store_domains, 'interval', hours=update_interval,
                              id="fetch_and_store_domains")
            scheduler.add_job(fetch_and_store_urls, 'interval', hours=update_interval, id="fetch_and_store_urls")
            scheduler.add_job(fetch_and_store_md5s, 'interval', hours=update_interval, id="fetch_and_store_md5s")
            scheduler.add_job(fetch_and_store_sha256s, 'interval', hours=update_interval, id="fetch_and_store_sha256s")


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


global update_interval
global automatic_update
global scheduler


def run_async_loop():
    asyncio.run(listen_for_settings_updates())


async def initialize():
    await fetch_and_store_ips()
    await fetch_and_store_domains()
    await fetch_and_store_urls()

    global update_interval
    global automatic_update
    global scheduler

    settings_doc = await settings_collection.find_one({"_id": 1})
    update_interval = settings_doc["update_interval"] if settings_doc else 1
    automatic_update = settings_doc["enable_automatic_update"] if settings_doc else True

    # Start the threading part
    #threading.Thread(target=listen_for_updates, daemon=True).start()

    # Scheduler configuration
    scheduler = BlockingScheduler()
    # threading.Thread(target=run_async_loop, daemon=True).start()
    scheduler.add_job(listen_for_settings_updates, 'interval', seconds=10, id="listen_for_settings_updates")

    if automatic_update:
        scheduler.add_job(fetch_and_store_ips, 'interval', hours=update_interval, id="fetch_and_store_ips")
        scheduler.add_job(fetch_and_store_domains, 'interval', hours=update_interval, id="fetch_and_store_domains")
        scheduler.add_job(fetch_and_store_urls, 'interval', hours=update_interval, id="fetch_and_store_urls")
        scheduler.add_job(fetch_and_store_md5s, 'interval', hours=update_interval, id="fetch_and_store_md5s")
        scheduler.add_job(fetch_and_store_sha256s, 'interval', hours=update_interval, id="fetch_and_store_sha256s")

    scheduler.start()


if __name__ == "__main__":
    asyncio.run(initialize())
