from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.scanners.headers import check_security_headers
from app.services.scan_engine import run_full_scan
from app.utils.domain import (
    DomainValidationError,
    validate_public_domain,
)


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
    try:
        return run_full_scan(domain)

    except DomainValidationError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@app.get("/headers")
def headers(domain: str):
    try:
        safe_domain = validate_public_domain(domain)
        return check_security_headers(safe_domain)

    except DomainValidationError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error