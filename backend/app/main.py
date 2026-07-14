from fastapi import FastAPI
from app.services.scan_engine import run_full_scan
from app.scanners.headers import check_security_headers
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "Welcome to WebShield"}


@app.get("/scan")
def scan(domain: str):
    return run_full_scan(domain)


@app.get("/headers")
def headers(domain: str):
    return check_security_headers(domain)