import os
from pathlib import Path
from typing import Literal
from fastapi import (
    FastAPI,
    Header,
    HTTPException,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from app.scanners.headers import check_security_headers
from app.services.scan_engine import run_full_scan
from app.services.deep_scan_engine import (
    run_verified_deep_scan,
)
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
from app.deep_scanners.js_advisories import (
    check_javascript_advisories,
)
from app.deep_scanners.zap_baseline import (
    run_zap_baseline,
)
from app.services.development_access import (
    DevelopmentAccessError,
    validate_development_admin_access,
)
from app.services.subdomain_scope import (
    SubdomainScopeError,
    build_authorized_subdomain_scope,
    create_scoped_authorization_receipt,
)
from app.services.source_archive import (
    MAX_ARCHIVE_BYTES,
    SourceArchiveError,
    scan_authorized_source_archive,
)
from app.services.source_scan_engine import (
    SourceScanAuthorizationError,
)
from app.services.engagement_profile import (
    BUG_BOUNTY_FINDING_EXCLUSIONS,
    BUG_BOUNTY_SCANNERS,
    DEFAULT_SCANNERS,
    ENGAGEMENT_VERSION,
    EngagementProfileError,
    create_bug_bounty_engagement_profile,
    create_engagement_profile,
    validate_engagement_profile,
)
from app.services.credential_vault import (
    CredentialVaultError,
    delete_test_account,
    store_test_account,
)
from app.services.login_session import (
    LoginSessionError,
    create_browser_session,
    create_login_session,
    delete_login_session,
)
from app.services.protected_page import (
    ProtectedPageError,
    verify_protected_page,
)
from app.services.authenticated_crawl import (
    AuthenticatedCrawlError,
    run_authenticated_crawl,
)
from app.services.logout_invalidation import (
    LogoutInvalidationError,
    cancel_logout_invalidation_test,
    check_logout_invalidation_test,
    prepare_logout_invalidation_test,
)
from app.services.object_access_control import (
    ObjectAccessControlError,
    check_api_authentication_boundary,
    check_object_access_control,
)

BACKEND_DIRECTORY = (
    Path(__file__).resolve().parent.parent
)

load_dotenv(
    BACKEND_DIRECTORY / ".env",
    override=False,
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

class SubdomainScopeRequest(BaseModel):
    parent_domain: str

    selected_domains: list[str] = Field(
        min_length=1,
        max_length=10,
    )

    authority_attested: bool
class FullDeepScanRequest(BaseModel):
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

    include_zap: bool = False

    zap_spider_minutes: int = Field(
        default=1,
        ge=1,
        le=3,
    )

    zap_maximum_minutes: int = Field(
        default=5,
        ge=2,
        le=10,
    )


class EngagementProfileRequest(BaseModel):
    domain: str
    client_reference: str = Field(min_length=2, max_length=120)
    authorized_by: str = Field(min_length=2, max_length=120)
    environment: Literal["production", "staging", "development"] = "production"
    max_pages: int = Field(default=25, ge=1, le=50)
    max_depth: int = Field(default=2, ge=0, le=3)
    include_zap: bool = False
    zap_spider_minutes: int = Field(default=1, ge=1, le=3)
    zap_maximum_minutes: int = Field(default=5, ge=2, le=10)
    approved_scanners: list[str] = Field(
        default_factory=lambda: list(DEFAULT_SCANNERS),
        min_length=1,
    )
    authorization_confirmed: bool


class BugBountyProfileRequest(BaseModel):
    domain: str
    program_name: str = Field(min_length=2, max_length=120)
    program_url: str = Field(min_length=12, max_length=500)
    researcher_handle: str = Field(min_length=2, max_length=80)
    scope_reference: str = Field(min_length=2, max_length=200)
    policy_saved_date: str = Field(min_length=10, max_length=10)
    approved_scanners: list[str] = Field(
        default_factory=lambda: sorted(BUG_BOUNTY_SCANNERS),
        min_length=1,
        max_length=len(BUG_BOUNTY_SCANNERS),
    )
    excluded_finding_types: list[str] = Field(
        default_factory=list,
        max_length=len(BUG_BOUNTY_FINDING_EXCLUSIONS),
    )
    asset_in_scope_confirmed: bool
    program_rules_confirmed: bool
    safe_harbor_confirmed: bool
    researcher_owned_accounts_only: bool
    authenticated_testing_approved: bool = False


class TestAccountRequest(BaseModel):
    domain: str
    login_url: str = Field(min_length=8, max_length=2048)
    username: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=8, max_length=512)
    ttl_minutes: int = Field(default=60, ge=5, le=240)


class LoginSessionRequest(BaseModel):
    domain: str
    credential_id: str = Field(min_length=12, max_length=200)


class BrowserSessionRequest(BaseModel):
    domain: str
    cookie_header: str = Field(min_length=3, max_length=16_384)
    ttl_minutes: int = Field(default=15, ge=5, le=60)
    researcher_owned_account_confirmed: bool


class ProtectedPageRequest(BaseModel):
    domain: str
    session_id: str = Field(min_length=12, max_length=200)
    protected_url: str = Field(min_length=8, max_length=2048)


class AuthenticatedCrawlRequest(ProtectedPageRequest):
    max_pages: int = Field(default=15, ge=1, le=25)
    max_depth: int = Field(default=2, ge=0, le=2)
    accept_medium_confidence: bool = False
    anonymous_access_denial_confirmed: bool = False


class LogoutTestPrepareRequest(ProtectedPageRequest):
    anonymous_access_denial_confirmed: bool = False
    verification_endpoint_url: str | None = Field(
        default=None,
        min_length=8,
        max_length=2048,
    )
    verification_method: Literal["GET", "POST"] = "GET"
    verification_json_body: dict | None = None
    read_only_post_confirmed: bool = False


class LogoutTestCheckRequest(BaseModel):
    domain: str
    test_id: str = Field(min_length=12, max_length=200)
    logout_completed_confirmed: bool


class ObjectAccessControlRequest(BaseModel):
    domain: str
    session_a_id: str = Field(min_length=12, max_length=200)
    session_b_id: str = Field(min_length=12, max_length=200)
    endpoint_template: str = Field(min_length=20, max_length=2048)
    object_a_id: str = Field(min_length=1, max_length=128)
    object_b_id: str = Field(min_length=1, max_length=128)
    read_only_get_confirmed: bool
    test_accounts_own_objects_confirmed: bool


class ApiAuthenticationBoundaryRequest(BaseModel):
    domain: str
    session_id: str = Field(min_length=12, max_length=200)
    endpoint_template: str = Field(min_length=20, max_length=2048)
    object_id: str = Field(min_length=1, max_length=128)
    read_only_get_confirmed: bool
    private_test_object_confirmed: bool

class DeepScanZapRequest(BaseModel):
    domain: str

    spider_minutes: int = Field(
        default=1,
        ge=1,
        le=3,
    )

    maximum_minutes: int = Field(
        default=5,
        ge=2,
        le=10,
    )



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


def get_credential_vault_secret() -> str:
    secret = os.getenv("WEBSHIELD_CREDENTIAL_VAULT_SECRET", "")
    if len(secret) < 32:
        raise HTTPException(
            status_code=503,
            detail=(
                "The encrypted test-account vault is not configured "
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


def require_engagement_or_deep_scan_access(
    domain: str,
    authorization: str | None,
):
    if authorization:
        scheme, separator, receipt = authorization.partition(" ")
        clean_receipt = receipt.strip()
        if (
            separator
            and scheme.lower() == "bearer"
            and clean_receipt.startswith(f"{ENGAGEMENT_VERSION}.")
        ):
            try:
                return validate_engagement_profile(
                    clean_receipt,
                    domain,
                    get_verification_secret(),
                )
            except (
                DomainValidationError,
                EngagementProfileError,
            ) as error:
                raise HTTPException(
                    status_code=403,
                    detail=str(error),
                ) from error

    return require_deep_scan_access(domain, authorization)


def require_engagement_access(
    domain: str,
    authorization: str | None,
):
    payload = require_engagement_or_deep_scan_access(domain, authorization)
    if payload.get("purpose") != "verified_engagement":
        raise HTTPException(
            status_code=403,
            detail="A signed Engagement Profile is required.",
        )
    if (
        payload.get("assessment_mode") == "bug_bounty"
        and payload.get("authenticated_testing_approved") is not True
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Authenticated testing was not approved in this signed "
                "bug bounty profile. Create a new profile and explicitly "
                "enable own-account authenticated testing."
            ),
        )
    return payload

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {"message": "Welcome to WebShield"}


@app.post("/source-scan/archive")
async def source_scan_archive(
    request: Request,
    project_name: str | None = Header(
        default=None,
        alias="X-WebShield-Project-Name",
    ),
    authorization_attestation: str | None = Header(
        default=None,
        alias="X-WebShield-Source-Authorization",
    ),
    client_reference: str | None = Header(
        default=None,
        alias="X-WebShield-Client-Reference",
    ),
    dependency_advisories: str | None = Header(
        default=None,
        alias="X-WebShield-Dependency-Advisories",
    ),
):
    if authorization_attestation != "authorized":
        raise HTTPException(
            status_code=403,
            detail=(
                "Confirm explicit source-code authorization using "
                "the X-WebShield-Source-Authorization header."
            ),
        )

    if not client_reference or len(client_reference.strip()) > 200:
        raise HTTPException(
            status_code=400,
            detail=(
                "Provide a short client approval, contract, or ticket "
                "reference before scanning source code."
            ),
        )

    content_type = request.headers.get("content-type", "")
    media_type = content_type.partition(";")[0].strip().lower()

    if media_type not in {
        "application/zip",
        "application/x-zip-compressed",
    }:
        raise HTTPException(
            status_code=415,
            detail="Upload the authorized project as a ZIP archive.",
        )

    chunks = []
    total_bytes = 0

    async for chunk in request.stream():
        total_bytes += len(chunk)

        if total_bytes > MAX_ARCHIVE_BYTES:
            raise HTTPException(
                status_code=413,
                detail="The source archive exceeds the upload limit.",
            )

        chunks.append(chunk)

    try:
        return scan_authorized_source_archive(
            b"".join(chunks),
            project_name=project_name or "Authorized project",
            authorization_attested=True,
            client_reference=client_reference.strip(),
            dependency_advisory_lookup=(
                dependency_advisories == "enabled"
            ),
            work_directory=os.getenv("WEBSHIELD_WORK_DIRECTORY"),
        )

    except SourceScanAuthorizationError as error:
        raise HTTPException(
            status_code=403,
            detail=str(error),
        ) from error

    except SourceArchiveError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


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


@app.post("/engagement/profile")
def engagement_profile(
    request: EngagementProfileRequest,
    http_request: Request,
    authorization: str | None = Header(default=None),
    x_webshield_admin_token: str | None = Header(default=None),
):
    if x_webshield_admin_token:
        try:
            ownership_payload = validate_development_admin_access(
                request.domain,
                x_webshield_admin_token,
                (
                    http_request.client.host
                    if http_request.client
                    else None
                ),
            )
            ownership_payload["verification_method"] = (
                ownership_payload.get("method")
                or "Development Admin"
            )
        except (
            DomainValidationError,
            DevelopmentAccessError,
        ) as error:
            raise HTTPException(
                status_code=403,
                detail=str(error),
            ) from error
    else:
        ownership_payload = require_deep_scan_access(
            request.domain,
            authorization,
        )

    try:
        return create_engagement_profile(
            request.domain,
            ownership_payload,
            request.model_dump(exclude={"domain"}),
            get_verification_secret(),
        )
    except (
        DomainValidationError,
        EngagementProfileError,
    ) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@app.post("/engagement/bug-bounty-profile")
def bug_bounty_engagement_profile(
    request: BugBountyProfileRequest,
):
    try:
        return create_bug_bounty_engagement_profile(
            request.domain,
            {
                **request.model_dump(exclude={"domain"}),
                "client_reference": (
                    f"{request.program_name} public bug bounty"
                ),
                "authorized_by": "Published HackerOne program",
            },
            get_verification_secret(),
        )
    except (
        DomainValidationError,
        EngagementProfileError,
    ) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error


@app.post("/engagement/test-account")
def create_engagement_test_account(
    request: TestAccountRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return store_test_account(
            engagement_payload,
            request.login_url,
            request.username,
            request.password,
            get_credential_vault_secret(),
            ttl_seconds=request.ttl_minutes * 60,
        )
    except CredentialVaultError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.delete("/engagement/test-account/{credential_id}")
def remove_engagement_test_account(
    credential_id: str,
    domain: str,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(domain, authorization)
    try:
        return delete_test_account(
            credential_id,
            engagement_payload,
        )
    except CredentialVaultError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/engagement/login-session")
def create_engagement_login_session(
    request: LoginSessionRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return create_login_session(
            request.credential_id,
            engagement_payload,
            get_credential_vault_secret(),
        )
    except (
        CredentialVaultError,
        LoginSessionError,
    ) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/engagement/browser-session")
def create_engagement_browser_session(
    request: BrowserSessionRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    if request.researcher_owned_account_confirmed is not True:
        raise HTTPException(
            status_code=400,
            detail="Confirm that the browser session belongs to your own test account.",
        )
    try:
        browser_session_payload = engagement_payload
        if engagement_payload.get("assessment_mode") == "owner_verified":
            browser_session_payload = {
                **engagement_payload,
                "researcher_owned_accounts_only": True,
            }
        return create_browser_session(
            request.cookie_header,
            browser_session_payload,
            ttl_seconds=request.ttl_minutes * 60,
        )
    except LoginSessionError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.delete("/engagement/login-session/{session_id}")
def remove_engagement_login_session(
    session_id: str,
    domain: str,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(domain, authorization)
    try:
        return delete_login_session(session_id, engagement_payload)
    except LoginSessionError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error


@app.post("/engagement/protected-page/verify")
def verify_engagement_protected_page(
    request: ProtectedPageRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return verify_protected_page(
            request.session_id,
            request.protected_url,
            engagement_payload,
        )
    except (
        LoginSessionError,
        ProtectedPageError,
    ) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/engagement/authenticated-crawl")
def run_engagement_authenticated_crawl(
    request: AuthenticatedCrawlRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return run_authenticated_crawl(
            request.session_id,
            request.protected_url,
            engagement_payload,
            max_pages=request.max_pages,
            max_depth=request.max_depth,
            accept_medium_confidence=request.accept_medium_confidence,
            anonymous_access_denial_confirmed=(
                request.anonymous_access_denial_confirmed
            ),
        )
    except (
        AuthenticatedCrawlError,
        LoginSessionError,
        ProtectedPageError,
    ) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/engagement/logout-test/prepare")
def prepare_engagement_logout_test(
    request: LogoutTestPrepareRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return prepare_logout_invalidation_test(
            request.session_id,
            request.protected_url,
            engagement_payload,
            anonymous_access_denial_confirmed=(
                request.anonymous_access_denial_confirmed
            ),
            verification_endpoint_url=request.verification_endpoint_url,
            verification_method=request.verification_method,
            verification_json_body=request.verification_json_body,
            read_only_post_confirmed=request.read_only_post_confirmed,
        )
    except (
        LogoutInvalidationError,
        LoginSessionError,
        ProtectedPageError,
    ) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/engagement/object-access/check")
def check_engagement_object_access(
    request: ObjectAccessControlRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return check_object_access_control(
            request.session_a_id,
            request.session_b_id,
            request.endpoint_template,
            request.object_a_id,
            request.object_b_id,
            engagement_payload,
            read_only_get_confirmed=request.read_only_get_confirmed,
            test_accounts_own_objects_confirmed=(
                request.test_accounts_own_objects_confirmed
            ),
        )
    except (
        LoginSessionError,
        ObjectAccessControlError,
    ) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/engagement/api-auth-boundary/check")
def check_engagement_api_authentication_boundary(
    request: ApiAuthenticationBoundaryRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return check_api_authentication_boundary(
            request.session_id,
            request.endpoint_template,
            request.object_id,
            engagement_payload,
            read_only_get_confirmed=request.read_only_get_confirmed,
            private_test_object_confirmed=(
                request.private_test_object_confirmed
            ),
        )
    except (
        LoginSessionError,
        ObjectAccessControlError,
    ) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/engagement/logout-test/check")
def check_engagement_logout_test(
    request: LogoutTestCheckRequest,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(
        request.domain,
        authorization,
    )
    try:
        return check_logout_invalidation_test(
            request.test_id,
            engagement_payload,
            request.logout_completed_confirmed,
        )
    except (
        LogoutInvalidationError,
        LoginSessionError,
    ) as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.delete("/engagement/logout-test/{test_id}")
def cancel_engagement_logout_test(
    test_id: str,
    domain: str,
    authorization: str | None = Header(default=None),
):
    engagement_payload = require_engagement_access(domain, authorization)
    try:
        return cancel_logout_invalidation_test(test_id, engagement_payload)
    except LogoutInvalidationError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error

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

@app.post("/deep-scan/subdomain-scope")
def create_subdomain_scan_scope(
    request: SubdomainScopeRequest,
    http_request: Request,
    authorization: str | None = Header(
        default=None,
    ),
    x_webshield_admin_token: str | None = Header(
        default=None,
    ),
):
    if x_webshield_admin_token:
        try:
            authorization_payload = (
                validate_development_admin_access(
                    request.parent_domain,
                    x_webshield_admin_token,
                    (
                        http_request.client.host
                        if http_request.client
                        else None
                    ),
                )
            )

        except (
            DomainValidationError,
            DevelopmentAccessError,
        ) as error:
            raise HTTPException(
                status_code=403,
                detail=str(error),
            ) from error

    else:
        authorization_payload = (
            require_deep_scan_access(
                request.parent_domain,
                authorization,
            )
        )

    discovery = discover_subdomains(
        authorization_payload["domain"]
    )

    if discovery.get("status") == "Unavailable":
        raise HTTPException(
            status_code=503,
            detail=(
                "Fresh subdomain discovery could not "
                "complete. WebShield did not issue an "
                "expanded authorization receipt."
            ),
        )

    try:
        validated_scope = (
            build_authorized_subdomain_scope(
                authorization_payload["domain"],
                request.selected_domains,
                discovery.get("checks", []),
                request.authority_attested,
            )
        )

        verification_method = (
            authorization_payload.get(
                "verification_method"
            )
            or authorization_payload.get("method")
            or "Verified Parent Domain"
        )

        scoped_authorization = (
            create_scoped_authorization_receipt(
                validated_scope,
                verification_method,
                get_verification_secret(),
            )
        )

    except (
        DomainValidationError,
        SubdomainScopeError,
    ) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    return {
        **validated_scope,
        "discovery_refreshed": True,
        "scoped_authorization_receipt": (
            scoped_authorization["receipt"]
        ),
        "authorization_expires_at": (
            scoped_authorization["expires_at"]
        ),
    }

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

@app.post("/deep-scan/js-advisories")
def deep_scan_javascript_advisories(
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

    return check_javascript_advisories(
        authorization_payload["domain"],
    )

@app.post("/deep-scan/zap-baseline")
def deep_scan_zap_baseline(
    request: DeepScanZapRequest,
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

    return run_zap_baseline(
        authorization_payload["domain"],
        spider_minutes=request.spider_minutes,
        maximum_minutes=request.maximum_minutes,
    )

@app.post("/deep-scan/run")
def run_complete_deep_scan(
    request: FullDeepScanRequest,
    http_request: Request,
    authorization: str | None = Header(
        default=None,
    ),
    x_webshield_admin_token: str | None = Header(
        default=None,
    ),
):
    if x_webshield_admin_token:
        try:
            authorization_payload = (
                validate_development_admin_access(
                    request.domain,
                    x_webshield_admin_token,
                    (
                        http_request.client.host
                        if http_request.client
                        else None
                    ),
                )
            )

        except (
            DomainValidationError,
            DevelopmentAccessError,
        ) as error:
            raise HTTPException(
                status_code=403,
                detail=str(error),
            ) from error

    else:
        authorization_payload = (
            require_engagement_or_deep_scan_access(
                request.domain,
                authorization,
            )
        )

    engagement_active = (
        authorization_payload.get("purpose")
        == "verified_engagement"
    )
    max_pages = (
        authorization_payload["max_pages"]
        if engagement_active
        else request.max_pages
    )
    max_depth = (
        authorization_payload["max_depth"]
        if engagement_active
        else request.max_depth
    )
    include_zap = (
        authorization_payload["include_zap"]
        if engagement_active
        else request.include_zap
    )
    zap_spider_minutes = (
        authorization_payload["zap_spider_minutes"]
        if engagement_active
        else request.zap_spider_minutes
    )
    zap_maximum_minutes = (
        authorization_payload["zap_maximum_minutes"]
        if engagement_active
        else request.zap_maximum_minutes
    )

    assessment_mode = authorization_payload.get(
        "assessment_mode",
        "owner_verified",
    )
    owner_controlled_assessment = (
        assessment_mode != "bug_bounty"
    )

    scan_options = {
        "max_pages": max_pages,
        "max_depth": max_depth,
        "include_zap": include_zap,
        "zap_spider_minutes": zap_spider_minutes,
        "zap_maximum_minutes": zap_maximum_minutes,
        # Owner-controlled scans may preserve page-level evidence even when
        # the certificate itself is the failure being diagnosed. Published
        # third-party programs remain strict and policy-limited.
        "baseline_scanner": (
            run_full_scan
            if owner_controlled_assessment
            else None
        ),
        "allow_invalid_tls": owner_controlled_assessment,
    }
    if engagement_active:
        scan_options.update({
            "approved_scanners": authorization_payload[
                "approved_scanners"
            ],
            "request_delay_seconds": authorization_payload.get(
                "request_delay_seconds"
            ),
            "excluded_finding_types": authorization_payload.get(
                "excluded_finding_types",
                [],
            ),
        })

    report = run_verified_deep_scan(
        authorization_payload["domain"],
        **scan_options,
    )

    if engagement_active:
        report["engagement"] = {
            "engagement_id": authorization_payload["engagement_id"],
            "client_reference": authorization_payload["client_reference"],
            "authorized_by": authorization_payload["authorized_by"],
            "environment": authorization_payload["environment"],
            "approved_scanners": authorization_payload["approved_scanners"],
            "excluded_finding_types": authorization_payload.get(
                "excluded_finding_types",
                [],
            ),
            "expires_at": authorization_payload["expires_at"],
            "limits_enforced": True,
            "assessment_mode": authorization_payload.get(
                "assessment_mode", "owner_verified"
            ),
            "program_name": authorization_payload.get("program_name"),
            "program_url": authorization_payload.get("program_url"),
            "researcher_handle": authorization_payload.get(
                "researcher_handle"
            ),
            "policy_saved_date": authorization_payload.get(
                "policy_saved_date"
            ),
            "request_delay_seconds": authorization_payload.get(
                "request_delay_seconds"
            ),
            "max_concurrency": authorization_payload.get("max_concurrency"),
        }

    return report
