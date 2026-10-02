"""Explicit provider selection. No fallback between implementations."""

from __future__ import annotations

from ..config import ConfigError, Settings
from .base import Provider
from .fake import FakeProvider
from .vast import VastProvider

_override: Provider | None = None
_cached: tuple[str, Provider] | None = None


def set_override(provider: Provider | None) -> None:
    """Tests only: force a specific provider instance."""
    global _override, _cached
    _override = provider
    _cached = None


def get_provider(settings: Settings) -> Provider:
    global _cached
    if _override is not None:
        return _override
    if settings.provider == "fake":
        if settings.is_live:
            raise ConfigError("the fake provider cannot be used in LIVE mode")
        # Rebuilt per call so the synthetic fixture always tracks today's date.
        return FakeProvider.from_fixture(mutations_enabled=settings.provider_mutations_enabled)
    if settings.is_demo:
        raise ConfigError("DEMO mode never talks to a real provider")
    key = f"vast:{settings.vast_base_url}"
    if _cached is None or _cached[0] != key:
        _cached = (key, VastProvider(settings))
    return _cached[1]
