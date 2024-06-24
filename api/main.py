import ipaddress

from fastapi import FastAPI, Request, Form, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.templating import Jinja2Templates
from pymongo import MongoClient
from starlette.status import HTTP_401_UNAUTHORIZED

app = FastAPI()
templates = Jinja2Templates(directory="templates")
security = HTTPBasic()

client = MongoClient("mongodb+srv://hostUser:n73utRfJqmZ5Cvtk@checkercluster.leiqmez.mongodb.net/")
db = client["checker"]
collection = db["ip_addresses"]
meta_collection = db["metadata"]
url_collection = db["url_dict"]


def authenticate(credentials: HTTPBasicCredentials):
    correct_username = "admin"
    correct_password = "password"
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(
            status_code=HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )


def get_url_dict():
    url_dict = {}
    for entry in url_collection.find():
        url_dict[entry["source"]] = entry["url"]
    return url_dict


def trigger_updater():
    url_collection.insert_one({"label": "trigger", "url": "trigger"})


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
async def ip_check(ip: str = Query(..., description="IP address to check")):
    last_updated_doc = meta_collection.find_one({"_id": "last_updated"})
    last_updated = last_updated_doc["timestamp"] if last_updated_doc else None

    for record in collection.find():
        cidr = record["ip"]
        if is_ip_in_cidr(ip, cidr):
            return {"exists": True, "ip": ip, "source": record["source"], "last_updated": last_updated}

    return {"exists": False, "last_updated": last_updated}


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, credentials: HTTPBasicCredentials = Depends(security)):
    authenticate(credentials)
    url_dict = get_url_dict()
    return templates.TemplateResponse("admin.html", {"request": request, "url_dict": url_dict})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    credentials = HTTPBasicCredentials(username=username, password=password)
    authenticate(credentials)
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/add_url", response_class=HTMLResponse)
async def add_url(request: Request, label: str = Form(...), url: str = Form(...),
                  credentials: HTTPBasicCredentials = Depends(security)):
    authenticate(credentials)
    url_collection.insert_one({"source": label, "url": url})
    # trigger_updater()
    return RedirectResponse(url="/admin", status_code=302)


@app.post("/admin/delete_url", response_class=HTMLResponse)
async def delete_url(request: Request, label: str = Form(...), credentials: HTTPBasicCredentials = Depends(security)):
    authenticate(credentials)
    url_collection.delete_one({"source": label})
    # trigger_updater()
    return RedirectResponse(url="/admin", status_code=302)
