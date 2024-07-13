import ipaddress
import json
import logging
import os

import aioredis
import httpx

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader
from starlette.middleware.sessions import SessionMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from pymongo import MongoClient, ASCENDING
from starlette.status import HTTP_401_UNAUTHORIZED

from utils import fetch_and_store_ips, fetch_and_store_domains, fetch_and_store_urls

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()
UPLOAD_FOLDER = 'uploads'

app.add_middleware(SessionMiddleware, secret_key=os.getenv('SESSION_SECRET_KEY'))

API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

client = MongoClient(os.getenv('MONGO_DB'))
db = client[os.getenv('DB')]
collection = db[os.getenv('IP_COLLECTION')]
domain_collection = db[os.getenv('DOMAIN_COLLECTION')]
url_collection = db[os.getenv('URL_COLLECTION')]
meta_collection = db[os.getenv('META_COLLECTION')]
ip_url_collection = db[os.getenv('IP_URLS_COLLECTION')]
domain_url_collection = db[os.getenv('DOMAIN_URLS_COLLECTION')]
url_urls_collection = db[os.getenv('URL_URLS_COLLECTION')]
api_key_collection = db[os.getenv('KEYS_COLLECTION')]
ip_score_collection = db[os.getenv('IP_SCORES_COLLECTION')]
domain_score_collection = db[os.getenv('DOMAIN_SCORES_COLLECTION')]
url_score_collection = db[os.getenv('URL_SCORES_COLLECTION')]
settings_collection = db[os.getenv('SETTINGS_COLLECTION')]
users_collection = db[os.getenv('USERS_COLLECTION')]

collection.create_index([("ip", ASCENDING)])
domain_collection.create_index([("domain", ASCENDING)])
url_collection.create_index([("url", ASCENDING)])
ip_score_collection.create_index([("url", ASCENDING)])
domain_score_collection.create_index([("url", ASCENDING)])
url_score_collection.create_index([("url", ASCENDING)])
api_key_collection.create_index([("api_key", ASCENDING), ("user_id", ASCENDING)])

redis = aioredis.from_url("redis://localhost")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.mount("/uploads", StaticFiles(directory=UPLOAD_FOLDER), name="uploads")


class APIKeyModel(BaseModel):
    api_key: str
    user_id: str


class SettingsModel(BaseModel):
    enable_automatic_update: bool
    update_interval: int


class APISettingsModel(BaseModel):
    default_api_limit: int


origins = [
    "http://localhost",
    "http://localhost:81",
    "http://156.67.80.79.1:8000",
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def authenticate(credentials: HTTPBasicCredentials):
    correct_username = "admin"
    correct_password = "password"
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


def validate_api_key(api_key: str = Depends(API_KEY_HEADER)):
    result = api_key_collection.find_one({"api_key": api_key})
    if not result or not result["valid"] and result["limit"] <= result["usage"] and result["user_id"] != "admin":
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
            headers={"WWW-Authenticate": "API key"},
        )
    else:
        api_key_collection.update_one({"api_key": api_key}, {"$inc": {"usage": 1}})
        result1 = api_key_collection.find_one({"api_key": api_key})
        if result["limit"] <= result1["usage"]:
            api_key_collection.update_one({"api_key": api_key}, {"$set": {"valid": False}})


async def get_cache(key: str):
    cached_data = await redis.get(key)
    if cached_data:
        return json.loads(cached_data)
    return None


async def set_cache(key: str, data, expire: int = 86400):
    await redis.set(key, json.dumps(data), ex=expire)


def get_url_dict():
    url_dict = {}
    for entry in ip_url_collection.find():
        url_dict[entry["source"]] = entry["url"]
    return url_dict


def get_domain_url_dict():
    url_dict = {}
    for entry in domain_url_collection.find():
        url_dict[entry["source"]] = entry["url"]
    return url_dict


def get_url_url_dict():
    url_dict = {}
    for entry in url_urls_collection.find():
        url_dict[entry["source"]] = entry["url"]
    return url_dict


@app.get("/", response_class=HTMLResponse)
def hello():
    return "Hello World!"


def is_ip_in_cidr(ip: str, cidr: str) -> bool:
    try:
        ip_network = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(ip) in ip_network
    except ValueError:
        return False


@app.get("/ipCheck/")
async def ip_check(ip: str = Query(..., description="IP address to check"), api_key: str = Depends(validate_api_key)):
    cache_key = f"ipCheck:{ip}"
    #cached_response = await get_cache(cache_key)

    #if cached_response:
        #return cached_response

    ip_doc = ip_score_collection.find_one_and_update(
        {"ip": ip},
        {"$inc": {"count": 1}},
        return_document=True,
        upsert=True
    )

    count = ip_doc["count"]

    last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
    last_updated = last_updated_doc["timestamp"] if last_updated_doc else None

    matching_record = collection.find_one({"ip": {"$in": [ip]}})

    if matching_record and is_ip_in_cidr(ip, matching_record["ip"]):
        response = {
            "exists": "True",
            "ip": ip,
            "source": matching_record["source"],
            "last_updated": last_updated,
            "count": count
        }
        #await set_cache(cache_key, response)
        return response

    response = {
        "exists": "False",
        "last_updated": last_updated
    }
    return response


@app.get("/domainCheck/")
async def domain_check(domain: str = Query(..., description="Domain to check"),
                       api_key: str = Depends(validate_api_key)):
    cache_key = f"domainCheck:{domain}"
    cached_response = await get_cache(cache_key)

    if cached_response:
        return cached_response

    try:
        domain_doc = await domain_score_collection.find_one_and_update(
            {"domain": domain},
            {"$inc": {"count": 1}},
            return_document=True,
            upsert=True
        )

        count = domain_doc["count"]

        result = await domain_collection.find_one({"domain": domain})
        last_updated_doc = await meta_collection.find_one({"_id": "last_updated"})
        last_updated = last_updated_doc["timestamp"] if last_updated_doc else "N/A"

        if result:
            response = {
                "exists": "True",
                "domain": result["domain"],
                "source": result["source"],
                "last_updated": last_updated,
                "count": count
            }
            await set_cache(cache_key, response)
        else:
            response = {
                "exists": "False",
                "last_updated": last_updated
            }

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error {e}")


@app.get("/urlCheck/")
async def url_check(url: str = Query(..., description="Url to check"), api_key: str = Depends(validate_api_key)):
    cache_key = f"urlCheck:{url}"
    cached_response = await get_cache(cache_key)

    if cached_response:
        return cached_response

    try:
        url_doc = await url_score_collection.find_one_and_update(
            {"url": url},
            {"$inc": {"count": 1}},
            return_document=True,
            upsert=True
        )

        count = url_doc["count"]

        result = await url_collection.find_one({"url": url})
        last_updated_doc = await meta_collection.find_one({"_id": "last_updated"})
        last_updated = last_updated_doc["timestamp"] if last_updated_doc else "N/A"

        if result:
            response = {
                "exists": "True",
                "url": result["url"],
                "source": result["source"],
                "last_updated": last_updated,
                "count": count
            }
            await set_cache(cache_key, response)
        else:
            response = {
                "exists": "False",
                "last_updated": last_updated
            }

        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {e}")


@app.post("/api_generated")
async def save_api_key(api_key_model: APIKeyModel):
    api_key = api_key_model.api_key
    if not api_key:
        raise HTTPException(status_code=400, detail="API key is required")

    api_settings_doc = settings_collection.find_one({"_id": 2})
    default_api_limit = api_settings_doc["default_api_limit"] if api_settings_doc else 100

    result = api_key_collection.insert_one({"api_key": api_key, "user_id": api_key_model.user_id,
                                            "limit": default_api_limit, "usage": 0, "valid": True})
    return {"id": str(result.inserted_id)}


@app.post("/update_settings")
async def update_settings(settings_model: SettingsModel):
    document = {
        '$set': {
            '_id': 1,
            'enable_automatic_update': settings_model.enable_automatic_update,
            'update_interval': settings_model.update_interval
        }
    }

    result = settings_collection.update_one({'_id': 1}, document, upsert=True)

    return {"id": str(result.upserted_id)}


@app.post("/update_api_settings")
async def update_settings(api_settings_model: APISettingsModel):
    document = {
        '$set': {
            '_id': 2,
            'default_api_limit': api_settings_model.default_api_limit
        }
    }

    result = settings_collection.update_one({'_id': 2}, document, upsert=True)

    return {"id": str(result.upserted_id)}


@app.post("/update_now")
async def update_now():
    try:
        fetch_and_store_ips()
        fetch_and_store_domains()
        fetch_and_store_urls()
        return {"msg": "Updated request sent successfully!"}
    except:
        return {"msg": "There was an error while updating database"}


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    #authenticate(credentials)
    admin = os.getenv('ADMIN_USERNAME')
    password = os.getenv('ADMIN_PASSWORD')

    if 'admin' not in request.session or 'password' not in request.session or request.session['admin'] != admin or \
            request.session['password'] != password:
        return RedirectResponse(url="/admin/login")

    ip_url_dict = get_url_dict()
    domain_url_dict = get_domain_url_dict()
    url_url_dict = get_url_url_dict()
    last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
    last_updated = last_updated_doc["timestamp"] if last_updated_doc else None
    settings_doc = settings_collection.find_one({"_id": 1})
    api_settings_doc = settings_collection.find_one({"_id": 2})
    update_interval = settings_doc["update_interval"] if settings_doc else 1
    automatic_update = settings_doc["enable_automatic_update"] if settings_doc else True
    default_api_limit = api_settings_doc["default_api_limit"] if api_settings_doc else 100
    api_doc = api_key_collection.find_one({"user_id": "admin"})
    api_key = api_doc["api_key"] if api_doc else ""

    return templates.TemplateResponse("admin.html",
                                      {"request": request, "ip_urls": ip_url_dict, "domain_urls": domain_url_dict,
                                       "url_urls": url_url_dict, "last_updated": last_updated,
                                       "update_interval": update_interval, "automatic_update": automatic_update,
                                       "api_key": api_key, "admin": admin, "password": password,
                                       "api_limit": default_api_limit})


@app.get("/admin/login", response_class=HTMLResponse)
async def login_page(request: Request):
    admin = os.getenv('ADMIN_USERNAME')
    password = os.getenv('ADMIN_PASSWORD')

    if 'admin' in request.session and 'password' in request.session and request.session['admin'] == admin and \
            request.session['password'] == password:
        return RedirectResponse(url="/admin")

    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/admin/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    admin1 = os.getenv('ADMIN_USERNAME')
    password1 = os.getenv('ADMIN_PASSWORD')

    logging.info(f"{admin1} : {password1}")
    logging.info(f"{username} : {password}")

    if admin1 != username and password1 != password:
        return RedirectResponse(url="/admin/login", status_code=302)

    request.session['admin'] = username
    request.session['password'] = password
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/add_url", response_class=HTMLResponse)
async def add_url(request: Request, label: str = Form(...), url: str = Form(...), add_to: str = Form(...)):
    # credentials: HTTPBasicCredentials = Depends(security), add_to: str = Form(...)):
    #authenticate(credentials)

    if add_to == "IP Address":
        ip_url_collection.insert_one({"source": label, "url": url})
    elif add_to == "Domain":
        domain_url_collection.insert_one({"source": label, "url": url})
    elif add_to == "URL":
        url_urls_collection.insert_one({"source": label, "url": url})
    return RedirectResponse(url="/admin?s=success", status_code=302)


@app.post("/admin/delete_url", response_class=HTMLResponse)
async def delete_url(request: Request, opt: str = Query(...), label: str = Form(...)):
    #credentials: HTTPBasicCredentials = Depends(security)):
    #authenticate(credentials)
    try:
        if opt == "ip":
            ip_url_collection.delete_one({"source": label})
        elif opt == "domain":
            domain_url_collection.delete_one({"source": label})
        elif opt == "url":
            url_urls_collection.delete_one({"source": label})
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/upload", response_class=HTMLResponse)
async def upload_form(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request})


@app.post("/upload")
async def upload_file(request: Request, file: UploadFile = File(...), source: str = Form(...),
                      upload_to: str = Form(...), ):
    file_location = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(file_location, "wb") as f:
        f.write(await file.read())

    file_url = str(request.url_for('uploaded_file', filename=file.filename))
    if upload_to == "IP Address":
        ip_url_collection.insert_one({"source": source, "url": file_url})
    elif upload_to == "Domain":
        domain_url_collection.insert_one({"source": source, "url": file_url})
    elif upload_to == "URL":
        url_urls_collection.insert_one({"source": source, "url": file_url})
    return RedirectResponse(url="/admin", status_code=302)


@app.get("/uploads/{filename}")
async def uploaded_file(filename: str):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return {"error": "File not found"}


@app.get("/login", response_class=HTMLResponse)
async def authenticate_page(request: Request):
    return templates.TemplateResponse("authenticate.html", {"request": request})


@app.get("/auth/github")
async def github_login():
    github_client_id = os.getenv('GITHUB_CLIENT_ID')
    redirect_uri = os.getenv('GITHUB_REDIRECT_URI')
    github_authorize_url = f"https://github.com/login/oauth/authorize?client_id={github_client_id}&redirect_uri={redirect_uri}&scope=user"
    return RedirectResponse(github_authorize_url)


@app.get("/auth/github/callback")
async def github_callback(request: Request, code: str = Query(...)):
    github_client_id = os.getenv('GITHUB_CLIENT_ID')
    github_client_secret = os.getenv('GITHUB_CLIENT_SECRET')
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": github_client_id,
        "client_secret": github_client_secret,
        "code": code,
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, headers=headers, data=data)
        response_data = response.json()
        access_token = response_data.get("access_token")

    if access_token:
        request.session['access_token'] = access_token
        user_info_url = "https://api.github.com/user"
        headers = {"Authorization": f"Bearer {access_token}"}
        async with httpx.AsyncClient() as client:
            user_response = await client.get(user_info_url, headers=headers)
            user_data = user_response.json()
            username = user_data.get("login")
            user_id = user_data.get("id")
            user_image = user_data.get("avatar_url")
            request.session['user_id'] = user_id
            if username:
                user_doc = {
                    '$set': {
                        "username": username,
                        "user_id": user_id,
                        "user_image": user_image
                    }
                }
                users_collection.update_one({'user_id': user_id}, user_doc, upsert=True)
                return templates.TemplateResponse("welcome.html",
                                                  {"request": request, "username": username, "user_id": user_id,
                                                   "user_data": user_data})

    raise HTTPException(status_code=400, detail="Failed to authenticate with GitHub")


@app.get("/api_user", response_class=HTMLResponse)
async def api_user(request: Request):
    if 'access_token' not in request.session or 'user_id' not in request.session:
        return RedirectResponse(url="/login")
    user_id = request.session['user_id']
    api_doc = api_key_collection.find_one({"user_id": f"{user_id}"})
    api_key = api_doc["api_key"] if api_doc else ""
    limit = api_doc["limit"] if api_doc else 100
    usage = api_doc["usage"] if api_doc else 0

    return templates.TemplateResponse("api_user.html",
                                      {"request": request, "api_key": api_key, "limit": limit, "usage": usage,
                                       "user_id": request.session['user_id']})
