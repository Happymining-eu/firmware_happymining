"""Runtime configuration and the DEMO / LIVE startup guard.

The mode is always explicit. There is no default mode and no fallback: a LIVE
process that is missing configuration fails to start, or reports the missing
integration as an explicit error. It never switches to demo behaviour.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from cryptography.fernet import Fernet
from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Values that ship in .env.example, docker-compose or tests. LIVE refuses all of them.
KNOWN_DEFAULT_SECRETS = frozenset(
    {
        "change-me",
        "changeme",
        "dev-secret-key-not-for-production-0000000000000000",
        "demo-secret-key-demo-secret-key-demo-secret-key",
        "test-secret-key-test-secret-key-test-secret-key",
    }
)
PLACEHOLDER_PREFIXES = (
    "change",
    "demo",
    "test",
    "dev-",
    "pytest",
    "example",
    "placeholder",
    "secret",
    "password",
)
# The Fernet key published in .env.example for DEMO. Never valid in LIVE.
DEMO_FIELD_ENCRYPTION_KEY = "ZGVtby1maWVsZC1lbmNyeXB0aW9uLWtleS0wMDAwMDA="
WEAK_DB_PASSWORDS = frozenset(
    {
        "change-me",
        "changeme",
        "password",
        "postgres",
        "happymining",
        "happymining_dev",
        "secret",
        "admin",
        "placeholder-for-validation",
    }
)
VAST_API_HOST = "console.vast.ai"
# The release-signing key published in appliance/testdata/release-vector.json.
# Its private half is public: LIVE refuses to trust it.
TEST_RELEASE_PUBLIC_KEY = "gHPPGWpeVAtEETEw6EPbGEVXn56F7ba5C0P2+Sxm5pQ="
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


class ConfigError(RuntimeError):
    """Raised when the configuration is not acceptable for the selected mode."""


CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HM_", extra="ignore")

    # --- mode ---------------------------------------------------------------
    mode: Literal["demo", "live"]

    # --- core ---------------------------------------------------------------
    database_url: str
    secret_key: SecretStr
    field_encryption_key: SecretStr
    public_base_url: str = "http://localhost:8000"
    allowed_hosts: CsvList = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    cors_allowed_origins: CsvList = Field(default_factory=list)
    cookie_secure: bool = True
    session_ttl_minutes: int = Field(default=480, ge=5, le=1440)
    trusted_proxy_hops: int = Field(default=0, ge=0, le=5)
    log_level: str = "INFO"
    metrics_token: SecretStr | None = None

    # --- authentication -----------------------------------------------------
    demo_login_enabled: bool = False
    login_rate_limit_per_minute: int = Field(default=10, ge=1)
    pairing_rate_limit_per_minute: int = Field(default=10, ge=1)

    # --- devices ------------------------------------------------------------
    pairing_code_ttl_minutes: int = Field(default=15, ge=1, le=120)
    pairing_max_attempts: int = Field(default=5, ge=1, le=20)
    heartbeat_interval_s: int = Field(default=60, ge=15, le=3600)
    device_stale_after_s: int = Field(default=300, ge=60)
    operation_ttl_s: int = Field(default=600, ge=60, le=3600)
    disruptive_operations_enabled: bool = False
    credential_rotation_grace_hours: int = Field(default=24, ge=1, le=168)
    # A normal agent sends one request a minute; a backlog flush after a long
    # outage needs a few dozen. Anything faster is throttled.
    device_heartbeat_rate_limit_per_minute: int = Field(default=60, ge=5)
    # Every authenticated device request counts here (heartbeats, polls, acks,
    # rotations), whether or not its body turns out to be valid.
    device_request_rate_limit_per_minute: int = Field(default=240, ge=10)
    device_rotation_limit_per_hour: int = Field(default=6, ge=1)
    # Integration API: requests per minute for one API client.
    integration_rate_limit_per_minute: int = Field(default=600, ge=10)
    # Refused integration tokens from one address, per minute, before it gets 429.
    integration_auth_failure_limit_per_minute: int = Field(default=30, ge=5)
    # Operations one API client may have queued or running on one machine.
    integration_max_open_operations_per_machine: int = Field(default=8, ge=1, le=32)
    telemetry_retention_days: int = Field(default=30, ge=1, le=3650)

    # --- provider -----------------------------------------------------------
    provider: Literal["fake", "vast"]
    vast_api_key: SecretStr | None = None
    vast_base_url: str = "https://console.vast.ai"
    # Free-text reference to the written agreement with Vast that authorises
    # HappyMining to operate third-party machines and use the API for it.
    # Empty means "unverified": the LIVE adapter refuses to call Vast.
    vast_commercial_authorization_ref: str = ""
    # Whether Vast's reported host earnings are net of Vast's own fee is not
    # documented (docs/integration-evidence.md, C11). Until an operator has
    # verified it, LIVE earnings are held and never posted to the ledger.
    vast_earnings_basis: Literal["unverified", "net_of_provider_fee"] = "unverified"
    # Day unit and range boundaries of the earnings endpoint are not documented
    # (C8). Same rule: held until verified.
    vast_earnings_buckets_verified: bool = False
    provider_mutations_enabled: bool = False
    provider_state_max_age_s: int = Field(default=60, ge=5, le=600)

    # --- money --------------------------------------------------------------
    settlement_currency: Literal["USD"] = "USD"
    payout_provider: Literal["manual_export", "mock"] = "manual_export"
    payouts_enabled: bool = False
    payout_minimum: str = "1.00"
    payout_require_distinct_approver: bool = True

    # --- appliance (docs/appliance.md) ---------------------------------------
    # The plugin catalog the control plane offers. Empty: the catalog shipped
    # with this code (appliance/catalog next to the api directory).
    catalog_dir: str = ""
    # Ed25519 public keys (base64 of 32 bytes) a firmware release must be
    # signed with. Empty: no release can be published.
    release_public_keys: CsvList = Field(default_factory=list)
    release_max_bytes: int = Field(default=128 * 1024 * 1024, ge=1024, le=512 * 1024 * 1024)
    # How long a remote-access grant may last when it has an expiry.
    remote_access_max_hours: int = Field(default=90 * 24, ge=1, le=366 * 24)

    # --- worker -------------------------------------------------------------
    worker_tick_s: int = Field(default=30, ge=5)
    worker_machine_sync_interval_s: int = Field(default=600, ge=60)
    worker_earnings_import_interval_s: int = Field(default=21600, ge=600)
    worker_earnings_lookback_days: int = Field(default=14, ge=1, le=90)

    @field_validator("allowed_hosts", "cors_allowed_origins", "release_public_keys", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_live(self) -> bool:
        return self.mode == "live"

    @property
    def is_demo(self) -> bool:
        return self.mode == "demo"

    def problems(self) -> list[str]:
        """Return every reason this configuration must not start."""
        out: list[str] = []
        secret = self.secret_key.get_secret_value()
        if len(secret) < 32:
            out.append("HM_SECRET_KEY must be at least 32 characters")
        try:
            Fernet(self.field_encryption_key.get_secret_value().encode())
        except Exception:
            out.append("HM_FIELD_ENCRYPTION_KEY is not a valid Fernet key")

        if self.is_demo:
            if self.provider != "fake":
                out.append("DEMO mode only runs with HM_PROVIDER=fake; it never calls a real provider")
            if self.payouts_enabled and self.payout_provider != "mock":
                out.append("DEMO mode can only enable payouts with HM_PAYOUT_PROVIDER=mock")
            if self.vast_api_key is not None and self.vast_api_key.get_secret_value().strip():
                out.append(
                    "HM_VAST_API_KEY is set in DEMO mode; a demo never holds a real provider credential"
                )
            return out

        # LIVE
        out.extend(_weak_secret_problems(secret))
        if self.field_encryption_key.get_secret_value() == DEMO_FIELD_ENCRYPTION_KEY:
            out.append("HM_FIELD_ENCRYPTION_KEY is the published demo key")
        if self.demo_login_enabled:
            out.append("HM_DEMO_LOGIN_ENABLED must be false in LIVE mode")
        if self.provider != "vast":
            out.append("LIVE mode requires HM_PROVIDER=vast; the fake provider is demo-only")
        if self.payout_provider == "mock":
            out.append("LIVE mode rejects the mock payout provider")
        if not self.cookie_secure:
            out.append("HM_COOKIE_SECURE must be true in LIVE mode")
        out.extend(_database_url_problems(self.database_url))
        if not self.public_base_url.startswith("https://"):
            out.append("HM_PUBLIC_BASE_URL must be https:// in LIVE mode")
        if not self.allowed_hosts or "*" in self.allowed_hosts:
            out.append("HM_ALLOWED_HOSTS must list explicit host names in LIVE mode")
        if "*" in self.cors_allowed_origins:
            out.append("HM_CORS_ALLOWED_ORIGINS must not contain * in LIVE mode")
        out.extend(_vast_url_problems(self.vast_base_url))
        if TEST_RELEASE_PUBLIC_KEY in self.release_public_keys:
            out.append(
                "HM_RELEASE_PUBLIC_KEYS contains the published test key; anyone could sign a release with it"
            )
        return out

    def validate_for_startup(self) -> None:
        problems = self.problems()
        if problems:
            raise ConfigError(
                f"refusing to start in {self.mode.upper()} mode:\n  - " + "\n  - ".join(problems)
            )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    try:
        settings = Settings()  # type: ignore[call-arg]
    except Exception as exc:  # pydantic ValidationError: missing HM_MODE etc.
        raise ConfigError(f"invalid or incomplete configuration: {exc}") from exc
    return settings


def reset_settings_cache() -> None:
    get_settings.cache_clear()


def _weak_secret_problems(secret: str) -> list[str]:
    """Reasons a LIVE secret key is not acceptable. The length check is done by the caller."""
    if secret != secret.strip():
        return ["HM_SECRET_KEY has leading or trailing whitespace"]
    if any(ch.isspace() for ch in secret):
        return ["HM_SECRET_KEY contains whitespace; use a generated value, not a phrase"]
    lowered = secret.lower()
    if secret in KNOWN_DEFAULT_SECRETS or lowered.startswith(PLACEHOLDER_PREFIXES):
        return ["HM_SECRET_KEY is a default or placeholder value"]
    if len(set(secret)) < 16:
        return ["HM_SECRET_KEY has too little variety to be a generated secret; use a random value"]
    return []


def _database_url_problems(url: str) -> list[str]:
    from sqlalchemy.engine import make_url
    from sqlalchemy.exc import ArgumentError

    try:
        parsed = make_url(url)
    except ArgumentError:
        return ["HM_DATABASE_URL is not a valid database URL"]
    password = parsed.password or ""
    if not password:
        return ["HM_DATABASE_URL has no password"]
    if password.lower() in WEAK_DB_PASSWORDS or password == (parsed.username or ""):
        return ["HM_DATABASE_URL uses a default development password"]
    if len(password) < 12:
        return ["HM_DATABASE_URL password is shorter than 12 characters"]
    return []


def _vast_url_problems(url: str) -> list[str]:
    """The account key is only ever sent to Vast itself, over TLS."""
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    if host in LOOPBACK_HOSTS:
        return []  # a local stand-in for tests; the key never leaves the machine
    if parts.scheme != "https" or host != VAST_API_HOST:
        return [f"HM_VAST_BASE_URL must be https://{VAST_API_HOST}"]
    return []
