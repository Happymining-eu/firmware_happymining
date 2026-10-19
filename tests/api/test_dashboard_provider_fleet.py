"""The admin fleet page: offer terms, floor price, unlist, maintenance window
and renter reports, through the browser forms, on the synthetic provider."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from helpers import BASE_URL
from sqlalchemy import select

from happymining.models import AuditLog, ProviderMachine

FLEET = {
    "account_id": "T",
    "currency": "USD",
    "machines": [
        {
            "id": 7001,
            "hostname": "rack-1",
            "gpu_name": "RTX 4090",
            "num_gpus": 4,
            "listed_gpu_cost": 0.42,
            "min_bid_price": 0.2,
            "reliability2": 0.997,
            "verification": "verified",
            "num_reports": 1,
            "gpu_occupancy": "D D I I",
            "reports": [{"problem": "disk", "message": "slow writes", "created_at": "2026-10-18T09:00:00Z"}],
        },
        {"id": 7002, "hostname": "rack-2", "gpu_name": "RTX 3090", "num_gpus": 1},
    ],
    "earnings": {},
}


def browser_for(app, user) -> TestClient:
    browser = TestClient(app, base_url=BASE_URL)
    r = browser.post("/demo-login", data={"email": user.email}, follow_redirects=False)
    assert r.status_code == 303, r.headers
    return browser


def outcome(response) -> tuple[str, str]:
    assert response.status_code == 303, (response.status_code, response.text[:300])
    query = parse_qs(urlsplit(response.headers["location"]).query)
    ((kind, (text,)),) = query.items()
    return kind, text


def test_fleet_page_shows_the_offer_and_the_forms_change_it(app, world):
    provider = world.provider(FLEET)
    provider.mutations_enabled = True
    account = world.account(provider)
    pm = world.session.execute(
        select(ProviderMachine).where(ProviderMachine.external_id == "7001")
    ).scalar_one()

    admin = browser_for(app, world.user("admin"))
    csrf = admin.get("/api/v1/auth/me").json()["csrf_token"]
    page = admin.get("/admin/provider").text
    assert "Fleet on the provider" in page
    assert "<strong>0.42</strong> $/GPU/h" in page and "floor 0.2 $/GPU/h" in page
    assert "reliability 0.997" in page and "verified" in page and "occupancy D D I I" in page
    assert f"/admin/provider-machines/{pm.id}/list" in page and "List at these prices" in page
    assert "Unlist (no new rentals)" in page and "Cancel maintenance window" in page

    # An auditor sees the fleet and the reports, and none of the forms.
    auditor = browser_for(app, world.user("auditor"))
    read_only = auditor.get("/admin/provider").text
    assert "<strong>0.42</strong> $/GPU/h" in read_only and "List at these prices" not in read_only
    reports = auditor.get(f"/admin/provider-machines/{pm.id}/reports").text
    assert "slow writes" in reports and "2026-10-18T09:00:00Z" in reports
    r = auditor.post(
        f"/admin/provider-machines/{pm.id}/min-bid",
        data={"price": "0.1", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 403

    # Offer with the end date as a day: expires at the end of that UTC day.
    until = (datetime.now(UTC) + timedelta(days=30)).date()
    kind, text = outcome(
        admin.post(
            f"/admin/provider-machines/{pm.id}/list",
            data={
                "price_gpu": "0.39",
                "price_min_bid": "0.15",
                "price_disk": "",
                "price_inet_up": "",
                "price_inet_down": "",
                "min_chunk": "2",
                "end_date": until.isoformat(),
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
    )
    assert kind == "msg" and "Offer sent to the provider" in text, text
    (external_id, terms) = provider.listings[-1]
    assert external_id == "7001" and terms.price_gpu == Decimal("0.39") and terms.min_chunk == 2
    assert terms.end_date.date() == until and terms.end_date.hour == 23 and terms.price_disk is None

    # Bad terms never reach the provider and come back as an error, not a crash.
    before = len(provider.listings)
    for bad in (
        {"price_gpu": "abc", "end_date": until.isoformat()},
        {"price_gpu": "0.39", "end_date": "2020-01-01"},
        {"price_gpu": "0.39", "price_min_bid": "0.80", "end_date": until.isoformat()},
    ):
        kind, text = outcome(
            admin.post(
                f"/admin/provider-machines/{pm.id}/list",
                data={**bad, "csrf_token": csrf},
                follow_redirects=False,
            )
        )
        assert kind == "err", (bad, text)
    assert len(provider.listings) == before

    kind, text = outcome(
        admin.post(
            f"/admin/provider-machines/{pm.id}/min-bid",
            data={"price": "0.11", "csrf_token": csrf},
            follow_redirects=False,
        )
    )
    assert kind == "msg" and "Floor price" in text
    kind, text = outcome(
        admin.post(
            f"/admin/provider-machines/{pm.id}/cancel-maintenance",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
    )
    assert kind == "msg" and provider.cancelled_maintenance == ["7001"]
    kind, text = outcome(
        admin.post(
            f"/admin/provider-machines/{pm.id}/unlist", data={"csrf_token": csrf}, follow_redirects=False
        )
    )
    assert kind == "msg" and "Existing rentals continue" in text

    # After a sync the page shows what the provider now reports.
    world.session.expire_all()
    from happymining.services import provider_sync

    provider_sync.sync_machines(world.session, provider, account)
    world.commit()
    page = admin.get("/admin/provider").text
    assert "<strong>0.39</strong> $/GPU/h" in page and "floor 0.11 $/GPU/h" in page

    actions = [
        r.action
        for r in world.session.execute(select(AuditLog).order_by(AuditLog.id)).scalars()
        if r.action.startswith("provider_machine.")
    ]
    assert actions[-4:] == [
        "provider_machine.list",
        "provider_machine.min_bid",
        "provider_machine.cancel_maintenance",
        "provider_machine.unlist",
    ]


def test_forms_report_disabled_mutations_as_errors(app, world):
    provider = world.provider(FLEET)  # mutations off, as in production by default
    world.account(provider)
    pm = world.session.execute(
        select(ProviderMachine).where(ProviderMachine.external_id == "7002")
    ).scalar_one()
    admin = browser_for(app, world.user("admin"))
    csrf = admin.get("/api/v1/auth/me").json()["csrf_token"]
    kind, text = outcome(
        admin.post(
            f"/admin/provider-machines/{pm.id}/min-bid",
            data={"price": "0.11", "csrf_token": csrf},
            follow_redirects=False,
        )
    )
    assert kind == "err" and "HM_PROVIDER_MUTATIONS_ENABLED" in text
    assert "no offer in the last sync" in admin.get("/admin/provider").text
