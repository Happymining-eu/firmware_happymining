"""Application errors and the single JSON error envelope."""

from __future__ import annotations


class AppError(Exception):
    status_code = 400
    code = "invalid_request"

    def __init__(self, message: str | None = None, *, code: str | None = None, headers: dict | None = None):
        super().__init__(message or self.default_message())
        self.message = message or self.default_message()
        if code:
            self.code = code
        self.headers = headers or {}

    def default_message(self) -> str:
        return "The request could not be processed."


class InvalidRequest(AppError):
    status_code = 400
    code = "invalid_request"


class Unauthorized(AppError):
    status_code = 401
    code = "unauthorized"

    def default_message(self) -> str:
        return "Authentication is required."


class PairingFailed(AppError):
    """Deliberately generic: wrong, expired, used and locked codes look the same."""

    status_code = 401
    code = "pairing_failed"

    def default_message(self) -> str:
        return "Pairing failed."


class DeviceUnauthorized(AppError):
    status_code = 401
    code = "device_unauthorized"

    def default_message(self) -> str:
        return "The device credential is not valid."


class Forbidden(AppError):
    status_code = 403
    code = "forbidden"

    def default_message(self) -> str:
        return "You are not allowed to do this."


class NotFound(AppError):
    status_code = 404
    code = "not_found"

    def default_message(self) -> str:
        return "Not found."


class Conflict(AppError):
    status_code = 409
    code = "conflict"

    def default_message(self) -> str:
        return "The request conflicts with the current state."


class Gone(AppError):
    status_code = 410
    code = "expired"

    def default_message(self) -> str:
        return "The resource has expired."


class PayloadTooLarge(AppError):
    status_code = 413
    code = "payload_too_large"

    def default_message(self) -> str:
        return "The request body is too large."


class RateLimited(AppError):
    status_code = 429
    code = "rate_limited"

    def __init__(self, retry_after_s: int = 60):
        super().__init__("Too many requests.", headers={"Retry-After": str(retry_after_s)})


class FeatureDisabled(AppError):
    """An explicit refusal. Never replaced by a fake success."""

    status_code = 409
    code = "feature_disabled"

    def default_message(self) -> str:
        return "This feature is disabled in the current configuration."


class NotImplementedFeature(AppError):
    status_code = 501
    code = "not_implemented"

    def default_message(self) -> str:
        return "This feature is not implemented."


class InsufficientFunds(AppError):
    status_code = 409
    code = "insufficient_reconciled_funds"

    def default_message(self) -> str:
        return "The reconciled balance does not cover this amount."


class UpstreamUnavailable(AppError):
    status_code = 503
    code = "provider_unavailable"

    def default_message(self) -> str:
        return "The provider integration is unavailable."
