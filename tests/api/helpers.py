"""Builders and small helpers for the API tests."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal

from fastapi.testclient import TestClient

from happymining.audit import Actor
from happymining.config import Settings, get_settings
from happymining.db import session_factory
from happymining.models import Machine, ProviderMachine
from happymining.providers import registry
from happymining.providers.fake import FakeProvider
from happymining.services import accounts, fees, pairing, provider_sync

BASE_URL = "http://127.0.0.1:8000"
SYSTEM = Actor.system("test")


def make_settings(**overrides: object) -> Settings:
    """A Settings copy with overrides, validated like a real start-up."""
    base = get_settings().model_dump()
    base.update(overrides)
    return Settings.model_validate(base)


LIVE_OVERRIDES: dict[str, object] = {
    "mode": "live",
    "provider": "vast",
    "demo_login_enabled": False,
    "cookie_secure": True,
    "payout_provider": "manual_export",
    "public_base_url": "https://api.example.test",
    "allowed_hosts": ["api.example.test", "127.0.0.1"],
    # Random-looking on purpose: the LIVE guard rejects placeholders and low-variety values.
    "secret_key": "Zq8vN2mK7pXw4RbT9cYh3JdL6sFg1AeU5oPi0QxM",
    "vast_base_url": "http://127.0.0.1:9",  # nothing listens here; tests inject their own
}


def live_settings(**overrides: object) -> Settings:
    """LIVE settings that pass the start-up guard (non-default secret and DB role)."""
    return make_settings(
        **{**LIVE_OVERRIDES, "database_url": os.environ["HM_TEST_LIVE_DATABASE_URL"], **overrides}
    )


# --- factories -------------------------------------------------------------


class World:
    """Small builder for test data, committing as it goes."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.session = session_factory()()
        self.today = datetime.now(UTC).date()

    def close(self) -> None:
        self.session.rollback()
        self.session.close()

    def commit(self) -> None:
        self.session.commit()

    def owner(self, name: str | None = None):
        owner = accounts.create_owner(
            self.session,
            SYSTEM,
            display_name=name or f"Owner {uuid.uuid4().hex[:6]}",
            is_synthetic=self.settings.is_demo,
        )
        self.commit()
        return owner

    def user(
        self,
        role: str,
        owner=None,
        email: str | None = None,
        *,
        demo: bool | None = None,
        password=None,
        org_role: str | None = None,
    ):
        """``org_role`` applies to the owner role only; left out, an owner's user is an org_admin."""
        demo = self.settings.is_demo if demo is None else demo
        user = accounts.create_user(
            self.session,
            SYSTEM,
            email=email or f"{role}-{uuid.uuid4().hex[:8]}@test.invalid",
            role=role,
            owner_id=owner.id if owner else None,
            is_demo=demo,
            password=password,
            org_role=org_role,
        )
        self.commit()
        return user

    def token(self, user) -> str:
        if self.settings.is_demo:
            _, token, _ = accounts.demo_login(
                self.session, self.settings, email=user.email, ip="127.0.0.1", user_agent="t"
            )
        else:
            # LIVE has no demo login: open an MFA-verified session directly.
            _, token = accounts._new_session(
                self.session,
                self.settings,
                user,
                mfa_verified=True,
                is_demo=False,
                ip="127.0.0.1",
                user_agent="t",
            )
        self.commit()
        return token

    def auth(self, user) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(user)}"}

    def fee(self, rate: str = "0.10", days_ago: int = 400, owner=None):
        schedule = fees.create_fee_schedule(
            self.session,
            SYSTEM,
            owner_id=owner.id if owner else None,
            rate=Decimal(rate),
            effective_from=self.today - timedelta(days=days_ago),
            note="test",
            created_by=None,
            is_demo_assumption=True,
        )
        self.commit()
        return schedule

    def pairing(self, owner, label: str = "m1", owned_days: int = 400):
        admin = self.user("admin")
        issued = pairing.create_enrollment(
            self.session,
            self.settings,
            SYSTEM,
            owner_id=owner.id,
            machine_label=label,
            created_by=admin.id,
            owned_since=self.today - timedelta(days=owned_days),
            is_synthetic=self.settings.is_demo,
        )
        self.commit()
        return issued

    def paired_machine(self, owner, label: str = "m1"):
        """Returns (machine, device token)."""
        issued = self.pairing(owner, label)
        result = pairing.enroll_device(
            self.session,
            self.settings,
            pairing_code=issued.code,
            hostname=label,
            fingerprint="sha256:" + "0" * 64,
            agent_version="0.1.0",
            os_info={"id": "ubuntu"},
            ip="127.0.0.1",
        )
        self.commit()
        machine = self.session.get(Machine, issued.machine.id)
        return machine, result.token

    def provider(self, dataset: dict | None = None) -> FakeProvider:
        provider = FakeProvider(
            dataset or {"account_id": "T", "currency": "USD", "machines": [], "earnings": {}}
        )
        registry.set_override(provider)
        return provider

    def account(self, provider: FakeProvider):
        account = provider_sync.ensure_account(self.session, self.settings, provider)
        provider_sync.sync_machines(self.session, provider, account)
        self.commit()
        return account

    def bind(self, account, external_id: str, machine, days_ago: int = 60):
        pm = (
            self.session.query(ProviderMachine)
            .filter_by(provider_account_id=account.id, external_id=external_id)
            .one()
        )
        admin = self.user("admin")
        provider_sync.bind_machine(
            self.session,
            SYSTEM,
            provider_machine_id=pm.id,
            machine_id=machine.id,
            bound_from=self.today - timedelta(days=days_ago),
            user_id=admin.id,
        )
        self.commit()
        return pm

    def day(self, days_ago: int) -> date:
        return self.today - timedelta(days=days_ago)


def dataset(
    machines: dict[str, dict], earnings: dict[str, dict[int, str]], today: date | None = None
) -> dict:
    """Build a FakeProvider dataset. ``earnings`` maps machine id -> {days_ago: amount}."""
    today = today or datetime.now(UTC).date()
    return {
        "account_id": "TEST-SYNTHETIC",
        "currency": "USD",
        "machines": [
            {"id": int(mid), "hostname": f"h{mid}", "gpu_name": "RTX (synthetic)", "num_gpus": 1, **extra}
            for mid, extra in machines.items()
        ],
        "earnings": {
            mid: {
                (today - timedelta(days=days_ago)).isoformat(): {"gpu_earn": amount}
                for days_ago, amount in days.items()
            }
            for mid, days in earnings.items()
        },
    }


IDLE_UNLISTED = {
    "rental": {
        "state": "idle",
        "listed": False,
        "active_contracts": 0,
        "stopped_instances": 0,
        "stored_data": False,
    }
}


def sample(seq: int, *, at: datetime | None = None, synthetic: bool = True, **extra) -> dict:
    return {
        "seq": seq,
        "collected_at": (at or datetime.now(UTC)).isoformat(),
        "uptime_s": 100,
        "synthetic": synthetic,
        "cpu": {"model": "cpu", "cores": 8, "load1": 0.1, "util_pct": 1.0},
        "memory": {"total_bytes": 64 << 30, "available_bytes": 60 << 30},
        "disks": [{"mount": "/", "fs": "ext4", "total_bytes": 10**12, "avail_bytes": 10**11}],
        "gpus": [
            {
                "index": 0,
                "uuid": "GPU-x",
                "name": "RTX 4090",
                "driver_version": "550.1",
                "vram_total_mib": 24564,
                "vram_used_mib": 10,
                "util_pct": 0,
                "power_w": 30.5,
                "temp_c": 40,
                "fan_pct": 30,
            }
        ],
        "services": {"docker": "active", "vastai": "active"},
        "vast": {"daemon_installed": True, "machine_id_hint": None},
        **extra,
    }


def heartbeat(client: TestClient, token: str, samples: list[dict]):
    return client.post(
        "/api/v1/device/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "sent_at": datetime.now(UTC).isoformat(),
            "boot_id": "b",
            "agent_version": "0.1.0",
            "samples": samples,
        },
    )
