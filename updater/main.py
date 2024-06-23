from pymongo import MongoClient, ASCENDING
import requests
from apscheduler.schedulers.blocking import BlockingScheduler
from datetime import datetime
import threading

client = MongoClient("mongodb+srv://hostUser:n73utRfJqmZ5Cvtk@checkercluster.leiqmez.mongodb.net/")
db = client["checker"]
collection = db["ip_addresses"]
meta_collection = db["metadata"]
url_collection = db["url_dict"]

collection.create_index([("ip", ASCENDING)], unique=True)


def get_url_dict():
    url_dict = {}
    for entry in url_collection.find():
        if entry["source"] != "trigger":
            url_dict[entry["source"]] = entry["url"]
    return url_dict


def fetch_and_store_ips():
    last_updated = datetime.utcnow()

    new_ips = []
    seen_ips = set()
    url_dict = get_url_dict()

    for label, url in url_dict.items():
        try:
            response = requests.get(url)
            response.raise_for_status()
            ip_list = response.text.splitlines()

            for ip in ip_list:
                if ip not in seen_ips:
                    new_ips.append({"ip": ip, "source": label})
                    seen_ips.add(ip)
        except requests.RequestException as e:
            print(f"Failed to fetch IPs from {url}: {e}")

    if new_ips:
        collection.delete_many({})
        collection.insert_many(new_ips)
        meta_collection.update_one(
            {"_id": "last_updated"},
            {"$set": {"timestamp": last_updated}},
            upsert=True
        )
        print(f"IP addresses updated at {last_updated}")
    cleanup_duplicates()


def listen_for_updates():
    pipeline = [{"$match": {"operationType": {"$in": ["insert", "delete"]}}}]
    with url_collection.watch(pipeline, full_document='updateLookup') as stream:
        for change in stream:
            try:
                fetch_and_store_ips()
                #if change["fullDocument"]["label"] == "trigger":
                # url_collection.delete_one({"_id": change["fullDocument"]["_id"]})
            except KeyError:
                continue


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
        print(f"Removed {len(ids_to_remove)} duplicate(s) for IP {duplicate['_id']}")


scheduler = BlockingScheduler()
scheduler.add_job(fetch_and_store_ips, 'interval', hours=1)

if __name__ == "__main__":
    threading.Thread(target=listen_for_updates, daemon=True).start()
    fetch_and_store_ips()
    scheduler.start()
