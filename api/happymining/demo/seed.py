"""DEMO seed data. Everything created here is flagged synthetic.

Refuses to run in LIVE mode. The 10% management fee is a DEMO assumption, not
an approved commercial rate.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..audit import Actor
from ..config import ConfigError, Settings
from ..models import FeeSchedule, Owner, User
from ..providers.registry import get_provider
from ..services import accounts, fees, provider_sync

DEMO_DOMAIN = "demo.happymining.invalid"
DEMO_USERS = (
    # email local part, role, display name, owner index
    ("admin", "admin", "Demo admin (prepares)", None),
    ("approver", "admin", "Demo admin (approves)", None),
    ("auditor", "auditor", "Demo auditor (read-only)", None),
    ("owner-a", "owner", "Demo owner A", 0),
    ("owner-b", "owner", "Demo owner B", 1),
)
DEMO_OWNERS = ("Owner A (synthetic)", "Owner B (synthetic)")
DEMO_FEE_RATE = Decimal("0.10")


def seed_demo(db: Session, settings: Settings) -> dict[str, object]:
    """Idempotent: running it again changes nothing."""
    if not settings.is_demo:
        raise ConfigError("demo data can only be seeded in DEMO mode")
    actor = Actor.system("demo-seed")

    owners: list[Owner] = []
    for name in DEMO_OWNERS:
        owner = db.execute(select(Owner).where(Owner.display_name == name)).scalar_one_or_none()
        if owner is None:
            owner = accounts.create_owner(db, actor, display_name=name, legal_name=name, is_synthetic=True)
        owners.append(owner)

    users: dict[str, User] = {}
    for local, role, display, owner_index in DEMO_USERS:
        email = f"{local}@{DEMO_DOMAIN}"
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            user = accounts.create_user(
                db,
                actor,
                email=email,
                role=role,
                display_name=display,
                owner_id=owners[owner_index].id if owner_index is not None else None,
                is_demo=True,
            )
        users[local] = user

    if db.execute(select(FeeSchedule.id).where(FeeSchedule.owner_id.is_(None))).first() is None:
        fees.create_fee_schedule(
            db,
            actor,
            owner_id=None,
            rate=DEMO_FEE_RATE,
            effective_from=datetime.now(UTC).date() - timedelta(days=90),
            note="DEMO assumption: 10% management fee. Not an approved commercial rate.",
            created_by=None,
            is_demo_assumption=True,
        )

    provider = get_provider(settings)
    account = provider_sync.ensure_account(db, settings, provider)
    provider_sync.check_health(db, provider, account)
    provider_sync.sync_machines(db, provider, account)
    db.flush()
    return {
        "owners": [str(o.id) for o in owners],
        "users": {k: v.email for k, v in users.items()},
        "provider_account_id": str(account.id),
    }
