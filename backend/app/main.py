import os
from typing import Literal
from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from app.scanners.headers import check_security_headers
from app.services.scan_engine import run_full_scan
from app.utils.domain import (
    DomainValidationError,
    validate_public_domain,
)
from app.scanners.dkim import (
    DKIMSelectorError,
    clean_selector,
)
from app.services.domain_verification import (
    VerificationError,
    create_verification_challenge,
    create_authorization_receipt,
    validate_authorization_receipt,
    verify_dns_proof,
    verify_http_file_proof,
)
from app.deep_scanners.crawler import (
    crawl_verified_site,
)
from app.deep_scanners.exposure_checks import (
    check_sensitive_exposures,
)
from app.deep_scanners.subdomains import (
    discover_subdomains,
)
from app.deep_scanners.ports import (
    scan_open_ports,
)

app = FastAPI()

class VerificationChallengeRequest(BaseModel):
    domain: str


class VerificationCheckRequest(BaseModel):
    domain: str
    token: str
    method: Literal["dns", "file"]

class DeepScanAccessRequest(BaseModel):
    domain: str



class DeepScanCrawlRequest(BaseModel):
    domain: str

    max_pages: int = Field(
        default=25,
        ge=1,
        le=50,
    )

    max_depth: int = Field(
        default=2,
        ge=0,
        le=3,
    )

def get_verification_secret() -> str:
    secret = os.getenv(
        "WEBSHIELD_VERIFICATION_SECRET",
        "",
    )

    if len(secret) < 32:
        raise HTTPException(
            status_code=503,
            detail=(
                "Domain verification is not configured "
                "on this WebShield server."
            ),
        )

    return secret

def require_deep_scan_access(
    domain: str,
    authorization: str | None,
):
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail=(
                "A deep-scan authorization receipt "
                "is required."
            ),
        )

    scheme, separator, receipt = (
        authorization.partition(" ")
    )

    if (
        not separator
        or scheme.lower() != "bearer"
        or not receipt.strip()
    ):
        raise HTTPException(
            status_code=401,
            detail=(
                "Use the Authorization header with "
                "the Bearer receipt format."
            ),
        )

    try:
        return validate_authorization_receipt(
            receipt.strip(),
            domain,
            get_verification_secret(),
        )

    except (
        DomainValidationError,
        VerificationError,
    ) as error:
        raise HTTPException(
            status_code=403,
            detail=str(error),
        ) from error    

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
def scan(
    domain: str,
    dkim_selector: str | None = None,
):
    try:
        clean_dkim_selector = (
            clean_selector(dkim_selector)
            if dkim_selector
            else None
        )

        return run_full_scan(
            domain,
            dkim_selector=clean_dkim_selector,
        )

    except (
        DomainValidationError,
        DKIMSelectorError,
    ) as error:
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

@app.post("/verification/challenge")
def verification_challenge(
    request: VerificationChallengeRequest,
):
    try:
        return create_verification_challenge(
            request.domain,
            get_verification_secret(),
        )

    except (
        DomainValidationError,
        VerificationError,
    ) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@app.post("/verification/check")
def verification_check(
    request: VerificationCheckRequest,
):
    try:
        secret = get_verification_secret()

        if request.method == "dns":
            result = verify_dns_proof(
                request.domain,
                request.token,
                secret,
            )
        else:
            result = verify_http_file_proof(
                request.domain,
                request.token,
                secret,
            )

        if not result["verified"]:
            return result

        authorization = create_authorization_receipt(
            request.domain,
            result["method"],
            secret,
        )

        return {
            **result,
            "authorization_receipt": (
                authorization["receipt"]
            ),
            "authorization_scope": (
                authorization["scope"]
            ),
            "authorization_expires_at": (
                authorization["expires_at"]
            ),
        }

    except (
        DomainValidationError,
        VerificationError,
    ) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error      

@app.post("/deep-scan/access-check")
def deep_scan_access_check(
    request: DeepScanAccessRequest,
    authorization: str | None = Header(
        default=None,
    ),
):
    authorization_payload = (
        require_deep_scan_access(
            request.domain,
            authorization,
        )
    )

    return {
        "authorized": True,
        "domain": authorization_payload["domain"],
        "scope": authorization_payload["scope"],
        "expires_at": (
            authorization_payload["expires_at"]
        ),
        "message": (
            "This domain is authorized for verified "
            "deep scanning."
        ),
    }   

@app.post("/deep-scan/crawl")
def deep_scan_crawl(
    request: DeepScanCrawlRequest,
    authorization: str | None = Header(
        default=None,
    ),
):
    authorization_payload = (
        require_deep_scan_access(
            request.domain,
            authorization,
        )
    )

    return crawl_verified_site(
        authorization_payload["domain"],
        max_pages=request.max_pages,
        max_depth=request.max_depth,
        delay_seconds=0.2,
    ) 

@app.post("/deep-scan/exposures")
def deep_scan_exposures(
    request: DeepScanAccessRequest,
    authorization: str | None = Header(
        default=None,
    ),
):
    authorization_payload = (
        require_deep_scan_access(
            request.domain,
            authorization,
        )
    )

    return check_sensitive_exposures(
        authorization_payload["domain"],
        delay_seconds=0.15,
    ) 

@app.post("/deep-scan/subdomains")
def deep_scan_subdomains(
    request: DeepScanAccessRequest,
    authorization: str | None = Header(
        default=None,
    ),
):
    authorization_payload = (
        require_deep_scan_access(
            request.domain,
            authorization,
        )
    )

    return discover_subdomains(
        authorization_payload["domain"],
    ) 

@app.post("/deep-scan/ports")
def deep_scan_ports(
    request: DeepScanAccessRequest,
    authorization: str | None = Header(
        default=None,
    ),
):
    authorization_payload = (
        require_deep_scan_access(
            request.domain,
            authorization,
        )
    )

    return scan_open_ports(
        authorization_payload["domain"],
        timeout=0.75,
        max_workers=20,
    )