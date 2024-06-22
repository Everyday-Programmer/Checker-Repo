import ipaddress

from fastapi import FastAPI, Query
from pydantic import BaseModel
from pymongo import MongoClient

app = FastAPI()

client = MongoClient("mongodb+srv://hostUser:n73utRfJqmZ5Cvtk@checkercluster.leiqmez.mongodb.net/")
db = client["checker"]
collection = db["ip_addresses"]
meta_collection = db["metadata"]


class IPAddress(BaseModel):
    ip: str
    source: str


def is_ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        ip_network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in ip_network
    except ValueError:
        return False


@app.get("/")
def hello():
    return {"message": "Hello World"}


@app.get("/ipCheck/")
async def ip_check(ip: str = Query(..., description="IP address to check")):
    last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
    last_updated = last_updated_doc["timestamp"] if last_updated_doc else None

    for record in collection.find():
        cidr = record["ip"]
        if is_ip_in_cidr(ip, cidr):
            return {"exists": "True", "source": record["source"], "last_updated": last_updated}

    return {"exists": "False", "last_updated": last_updated}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
