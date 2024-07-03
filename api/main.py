import ipaddress
import os

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials, APIKeyHeader
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel
from bson import ObjectId
from starlette.status import HTTP_401_UNAUTHORIZED

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()
UPLOAD_FOLDER = 'uploads'

API_KEY_HEADER = APIKeyHeader(name="X-API-Key")

client = MongoClient(os.getenv('MONGO_DB'))
db = client["checker"]
collection = db["ip_addresses"]
domain_collection = db["domains"]
url_collection = db["urls"]
meta_collection = db["metadata"]
ip_url_collection = db["ip_urls"]
domain_url_collection = db["domain_urls"]
url_urls_collection = db["url_urls"]
api_key_collection = db["api_keys"]
ip_score_collection = db["ip_scores"]
domain_score_collection = db["domain_scores"]
url_score_collection = db["url_scores"]

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.mount("/uploads", StaticFiles(directory=UPLOAD_FOLDER), name="uploads")


class APIKeyModel(BaseModel):
    api_key: str
    user_id: str


origins = [
    "http://localhost",
    "http://localhost:8000",
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
    if not result:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
            headers={"WWW-Authenticate": "API key"},
        )


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
    ip_doc = ip_score_collection.find_one({"ip": ip})
    if ip_doc:
        ip_score_collection.update_one({"ip": ip}, {"$inc": {"count": 1}})
        count = ip_doc["count"] + 1
    else:
        ip_score_collection.insert_one({"ip": ip, "count": 1})
        count = 1

    last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
    last_updated = last_updated_doc["timestamp"] if last_updated_doc else None

    for record in collection.find():
        cidr = record["ip"]
        if is_ip_in_cidr(ip, cidr):
            return {"exists": "True", "ip": ip, "source": record["source"], "last_updated": last_updated,
                    "count": count}

    return {"exists": "False", "last_updated": last_updated}


@app.get("/domainCheck/")
async def domain_check(domain: str = Query(..., description="Domain to check"),
                       api_key: str = Depends(validate_api_key)):
    try:
        domain_doc = domain_score_collection.find_one({"domain": domain})
        if domain_doc:
            domain_score_collection.update_one({"domain": domain}, {"$inc": {"count": 1}})
            count = domain_doc["count"] + 1
        else:
            domain_score_collection.insert_one({"domain": domain, "count": 1})
            count = 1

        result = domain_collection.find_one({"domain": domain})
        last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
        last_updated = last_updated_doc["timestamp"] if last_updated_doc else "N/A"
        if result:
            return {"exists": "True", "domain": result["domain"], "source": result["source"],
                    "last_updated": last_updated, "count": count}
        else:
            return {"exists": "False", "last_updated": last_updated}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal Server Error {e}")


@app.get("/urlCheck/")
async def url_check(url: str = Query(..., description="Url to check"), api_key: str = Depends(validate_api_key)):
    try:
        url_doc = url_score_collection.find_one({"url": url})
        if url_doc:
            url_score_collection.update_one({"url": url}, {"$inc": {"count": 1}})
            count = url_doc["count"] + 1
        else:
            url_score_collection.insert_one({"url": url, "count": 1})
            count = 1

        result = url_collection.find_one({"url": url})
        last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
        last_updated = last_updated_doc["timestamp"] if last_updated_doc else "N/A"
        if result:
            return {"exists": "True", "url": result["url"], "source": result["source"], "last_updated": last_updated,
                    "count": count}
        else:
            return {"exists": "False", "last_updated": last_updated}
    except Exception:
        raise HTTPException(status_code=500, detail="Internal Server Error")


@app.post("/api_generated")
async def save_api_key(api_key_model: APIKeyModel):
    api_key = api_key_model.api_key
    if not api_key:
        raise HTTPException(status_code=400, detail="API key is required")

    result = api_key_collection.insert_one({"api_key": api_key, "user_id": api_key_model.user_id})
    return {"id": str(result.inserted_id)}


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    """, credentials: HTTPBasicCredentials = Depends(security)):"""
    #authenticate(credentials)
    ip_url_dict = get_url_dict()
    domain_url_dict = get_domain_url_dict()
    url_url_dict = get_url_url_dict()
    last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
    last_updated = last_updated_doc["timestamp"] if last_updated_doc else None

    return templates.TemplateResponse("admin.html",
                                      {"request": request, "ip_urls": ip_url_dict, "domain_urls": domain_url_dict,
                                       "url_urls": url_url_dict, "last_updated": last_updated})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    credentials = HTTPBasicCredentials(username=username, password=password)
    authenticate(credentials)
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
