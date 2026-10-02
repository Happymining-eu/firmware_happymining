#!/usr/bin/env python3
"""HappyMining OS acceptance demo. DEMO mode only: every figure is SYNTHETIC.

Runs the seven acceptance steps against a running API over real HTTP, using the
simulator binary as the paired agents:

  1. create two owners and simulated machines
  2. pair an agent
  3. display telemetry
  4. import synthetic earnings
  5. apply the management fee
  6. reconcile a simulated receipt
  7. prepare an owner settlement

and then repeats the import and the settlement request to show that neither
creates duplicate earnings or payments.

Usage:  acceptance_demo.py --api-url http://127.0.0.1:8765 --simulator dist/bin/hm-simulator

The API must be running in DEMO mode with demo data seeded
(``python -m happymining.cli seed-demo``). ``make demo`` does all of that.
No real machine, provider account or bank is contacted.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import httpx

ADMIN = "admin@demo.happymining.invalid"
APPROVER = "approver@demo.happymining.invalid"
DEMO_IBAN_A = "FR7630006000011234567890189"  # the public example IBAN from the IBAN registry
DEMO_IBAN_B = "DE89370400440532013000"  # likewise a published example, not a real account


class DemoFailure(Exception):
    pass


class Demo:
    def __init__(self, api_url: str, simulator: Path, quiet: bool = False):
        self.api_url = api_url.rstrip("/")
        self.simulator = simulator
        self.quiet = quiet
        self.http = httpx.Client(base_url=self.api_url, timeout=30, trust_env=False)
        self.checks = 0
        self.tokens: dict[str, dict[str, str]] = {}

    # --- output ------------------------------------------------------------

    def say(self, text: str = "") -> None:
        if not self.quiet:
            print(text, flush=True)

    def step(self, number: int, title: str) -> None:
        self.say(f"\n== Step {number}: {title}")

    def check(self, condition: bool, description: str) -> None:
        self.checks += 1
        if not condition:
            raise DemoFailure(f"FAILED: {description}")
        self.say(f"   ok  {description}")

    # --- HTTP --------------------------------------------------------------

    def login(self, email: str) -> dict[str, str]:
        if email not in self.tokens:
            r = self.http.post("/api/v1/auth/demo-login", json={"email": email})
            if r.status_code != 200:
                raise DemoFailure(f"demo login failed for {email}: {r.status_code} {r.text}")
            self.tokens[email] = {"Authorization": f"Bearer {r.json()['token']}"}
        return self.tokens[email]

    def call(
        self, method: str, path: str, *, as_user: str = ADMIN, expect: tuple[int, ...] = (200, 201), **kw
    ):
        headers = {**self.login(as_user), **kw.pop("headers", {})}
        r = self.http.request(method, path, headers=headers, **kw)
        if r.status_code not in expect:
            raise DemoFailure(f"{method} {path} -> {r.status_code}: {r.text[:400]}")
        return r

    def get(self, path: str, **kw):
        return self.call("GET", path, **kw).json()

    def post(self, path: str, body: dict | None = None, **kw):
        return self.call("POST", path, json=body if body is not None else {}, **kw)

    def journal_entries(self) -> int:
        return self.get("/api/v1/ledger/entries?limit=1")["total"]

    # --- the scenario ------------------------------------------------------

    def run(self) -> None:
        today = datetime.now(UTC).date()
        start, end = today - timedelta(days=7), today - timedelta(days=1)
        run_id = uuid.uuid4().hex[:8]

        ready = self.http.get("/readyz").json()
        self.check(
            ready.get("status") == "ready" and ready.get("mode") == "demo", "API is ready and in DEMO mode"
        )
        me = self.get("/api/v1/auth/me")
        self.check(me["synthetic_data"] is True, "the API declares its data synthetic")

        # 1 ------------------------------------------------------------------
        self.step(1, "create two owners and simulated machines")
        owners = []
        for name in (f"Demo owner North {run_id}", f"Demo owner South {run_id}"):
            owner = self.post("/api/v1/owners", {"display_name": name}).json()
            owners.append(owner)
            self.say(f"   owner {owner['display_name']}  ({owner['id']})")
        self.check(all(o["synthetic"] for o in owners), "both owners are flagged synthetic")
        enrollments = []
        for owner, label in zip(owners, (f"sim-north-{run_id}", f"sim-south-{run_id}"), strict=True):
            enrollment = self.post(
                "/api/v1/enrollment-requests",
                {
                    "owner_id": owner["id"],
                    "machine_label": label,
                    "owned_since": (today - timedelta(days=30)).isoformat(),
                },
            ).json()
            enrollments.append(enrollment)
        self.check(
            all(e["pairing_code"].startswith("HM-") for e in enrollments),
            "one single-use pairing code issued per machine, bound to its owner",
        )
        fees = self.get("/api/v1/fee-schedules")["items"]
        default_fee = next(f for f in fees if f["scope"] == "default")
        self.check(
            default_fee["rate"] == "0.10000000" and default_fee["demo_assumption"],
            "management fee is 10% and marked as a DEMO assumption",
        )

        # 2 ------------------------------------------------------------------
        self.step(2, "pair the agents (simulator, no NVIDIA hardware)")
        with tempfile.TemporaryDirectory(prefix="hm-demo-") as tmp:
            codes = Path(tmp) / "codes.txt"
            codes.write_text("\n".join(e["pairing_code"] for e in enrollments) + "\n")
            codes.chmod(0o600)
            cmd = [
                str(self.simulator),
                "--api-url",
                self.api_url,
                "--allow-insecure-loopback",
                "--machines",
                "2",
                "--codes-file",
                str(codes),
                "--state-dir",
                str(Path(tmp) / "state"),
                "--gpu-model",
                "rtx4090",
                "--gpus",
                "2",
                "--interval",
                "40ms",
                "--samples",
                "24",
                "--seed",
                "11",
                "--outage-after",
                "8",
                "--outage-for",
                "6",
                "--duplicate-every",
                "5",
                "--backoff-base",
                "20ms",
                "--backoff-cap",
                "200ms",
                "--log-level",
                "warn",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
            if proc.returncode != 0:
                raise DemoFailure(
                    f"simulator failed ({proc.returncode}):\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
                )
            output = proc.stdout + proc.stderr
            self.check(
                not any(e["pairing_code"] in output for e in enrollments) and "hmd_" not in output,
                "simulator output contains no pairing code and no device credential",
            )
        machines = {m["id"]: m for m in self.get("/api/v1/machines?limit=200")["items"]}
        mine = [machines[e["machine_id"]] for e in enrollments]
        self.check(
            all(m["status"] == "active" and m["connection"] == "online" for m in mine),
            "both machines are paired and online",
        )
        self.check(
            [m["owner_id"] for m in mine] == [o["id"] for o in owners],
            "each machine belongs to the owner chosen by the admin, not by the device",
        )
        replay = self.http.post(
            "/api/v1/devices/enroll",
            json={
                "pairing_code": enrollments[0]["pairing_code"],
                "hostname": "replay",
                "machine_fingerprint": "sha256:" + "0" * 64,
                "agent_version": "0.1.0",
            },
        )
        self.check(replay.status_code == 401, "a used pairing code cannot be replayed")

        # 3 ------------------------------------------------------------------
        self.step(3, "display telemetry")
        for machine in mine:
            telemetry = self.get(f"/api/v1/machines/{machine['id']}/telemetry?limit=200")["items"]
            seqs = sorted(t["seq"] for t in telemetry)
            self.check(
                seqs == list(range(1, 25)),
                f"{machine['label']}: 24 samples stored once each, despite a simulated outage and resends",
            )
            self.check(
                all(t["synthetic"] for t in telemetry),
                f"{machine['label']}: every sample is marked synthetic",
            )
            latest = telemetry[0]
            self.say(
                f"   {machine['label']}: {latest['gpu_count']} GPUs, avg util {latest['gpu_util_avg']}%, "
                f"{latest['gpu_power_w']} W, max {latest['gpu_temp_max']} C"
            )
        page = self.http.post("/demo-login", data={"email": ADMIN}, follow_redirects=True)
        self.check(
            page.status_code == 200 and mine[0]["label"] in page.text and "SYNTHETIC" in page.text,
            "the dashboard shows the machines and labels the data synthetic",
        )

        # 4 ------------------------------------------------------------------
        self.step(4, "import synthetic provider earnings")
        self.post("/api/v1/provider/sync-machines")
        provider_machines = {p["external_id"]: p for p in self.get("/api/v1/provider/machines")["items"]}
        self.check(
            {"900001", "900002", "900003"} <= set(provider_machines),
            "synthetic provider lists three machines",
        )
        for external_id, machine in zip(("900001", "900002"), mine, strict=True):
            pm = provider_machines[external_id]
            if pm["machine_id"] is None:
                self.post(
                    f"/api/v1/provider/machines/{pm['id']}/bind",
                    {"machine_id": machine["id"], "bound_from": (today - timedelta(days=30)).isoformat()},
                )
        owner_of = {"900001": owners[0], "900002": owners[1]}
        first = self.post(
            "/api/v1/provider/import-earnings", {"start": start.isoformat(), "end": end.isoformat()}
        ).json()
        self.check(
            first["import"]["status"] == "posted" and first["import"]["synthetic"],
            f"earnings imported: {first['import']['stats']['new']} machine-days, flagged synthetic",
        )
        exceptions = self.get("/api/v1/exceptions")["items"]
        self.check(
            any(e["kind"] == "unmapped_machine" and "900003" in e["summary"] for e in exceptions),
            "the unassigned machine's earnings went to the exception queue, not to an owner",
        )

        # 5 ------------------------------------------------------------------
        self.step(5, "apply the management fee")
        balances = {}
        for owner in owner_of.values():
            buckets = self.get(f"/api/v1/earnings/buckets?owner_id={owner['id']}&limit=200")["items"]
            reported = sum((Decimal(b["reported"]) for b in buckets), Decimal(0))
            fee = sum((Decimal(b["fee_reported"]) for b in buckets), Decimal(0))
            share = sum((Decimal(b["owner_share_reported"]) for b in buckets), Decimal(0))
            self.check(
                fee + share == reported and all(b["fee_rate"] == "0.10000000" for b in buckets),
                f"{owner['display_name']}: reported {reported} = fee {fee} + owner share {share}",
            )
            balance = self.get(f"/api/v1/owners/{owner['id']}/balance")
            balances[owner["id"]] = balance
            self.check(
                Decimal(balance["available_to_settle"]) == 0
                and Decimal(balance["accrued_reported"]) == share,
                f"{owner['display_name']}: a provider report is not cash, so nothing is payable yet",
            )
        north = self.get(f"/api/v1/earnings/buckets?owner_id={owners[0]['id']}&limit=200")["items"]
        self.check(
            sum((Decimal(b["reported"]) for b in north), Decimal(0)) == Decimal("100"),
            "spec example: eligible host earnings USD 100.00",
        )

        # 6 ------------------------------------------------------------------
        self.step(6, "reconcile a simulated receipt")
        account_id = self.get("/api/v1/provider/accounts")["items"][0]["id"]
        open_total = sum(
            (
                Decimal(b["reported"]) - Decimal(b["received"])
                for o in owners
                for b in self.get(f"/api/v1/earnings/buckets?owner_id={o['id']}&limit=200")["items"]
            ),
            Decimal(0),
        )
        suspense_extra = Decimal("1.25")
        receipt = self.post(
            "/api/v1/receipts",
            {
                "provider_account_id": account_id,
                "reference": f"SIMULATED-RECEIPT-{run_id}",
                "received_on": today.isoformat(),
                "amount": str(open_total + suspense_extra),
                "currency": "USD",
                "evidence_source": "bank_statement",
                "evidence_note": "SIMULATED receipt for the acceptance demo; no bank statement exists",
            },
        ).json()
        self.check(
            Decimal(self.get(f"/api/v1/owners/{owners[0]['id']}/balance")["available_to_settle"]) == 0,
            "recording the receipt alone releases nothing: it sits in suspense",
        )
        self.post(
            f"/api/v1/receipts/{receipt['id']}/allocate-period",
            {"start": start.isoformat(), "end": end.isoformat()},
            headers={"Idempotency-Key": f"acceptance-alloc-{run_id}"},
        )
        north_balance = self.get(f"/api/v1/owners/{owners[0]['id']}/balance")
        self.check(
            north_balance["available_to_settle"] == "90.00000000" and north_balance["payable_now"] == "90.00",
            "spec example: fee 10% = USD 10.00, owner payable USD 90.00",
        )
        statement = self.get(
            f"/api/v1/owners/{owners[0]['id']}/statement?start={start.isoformat()}&end={end.isoformat()}"
        )
        self.say(
            f"   statement: base {statement['reconciled']['eligible_base']}  "
            f"fee {statement['reconciled']['management_fee']}  "
            f"adjustments {statement['adjustments']['net_amount']}  "
            f"reserve {statement['balances_now']['reserve']}  payable {statement['balances_now']['payable']}"
        )
        remainder = [
            e
            for e in self.get("/api/v1/exceptions")["items"]
            if e["kind"] == "receipt_remainder" and e["details"].get("receipt_id") == receipt["id"]
        ]
        self.check(
            len(remainder) == 1 and Decimal(remainder[0]["details"]["unallocated"]) == suspense_extra,
            f"the unexplained USD {suspense_extra} stays in suspense as an open exception",
        )

        # 7 ------------------------------------------------------------------
        self.step(7, "prepare an owner settlement")
        for owner, iban in zip(owners, (DEMO_IBAN_A, DEMO_IBAN_B), strict=True):
            self.call(
                "PUT",
                f"/api/v1/owners/{owner['id']}/beneficiary",
                json={"account_holder": owner["display_name"], "iban": iban},
            )
        key = f"acceptance-demo-{run_id}"
        body = {"owner_ids": [o["id"] for o in owners], "note": "SIMULATED settlement"}
        batch = self.post("/api/v1/payout-batches", body, headers={"Idempotency-Key": key}).json()
        amounts = {i["owner_id"]: i["amount"] for i in batch["items"]}
        self.check(
            batch["created"] and amounts[owners[0]["id"]] == "90.00",
            f"settlement batch drafted: {', '.join(sorted(amounts.values()))} USD",
        )
        self_approval = self.call("POST", f"/api/v1/payout-batches/{batch['id']}/approve", expect=(403,))
        self.check(self_approval.status_code == 403, "the preparer cannot approve their own batch")
        approved = self.post(f"/api/v1/payout-batches/{batch['id']}/approve", as_user=APPROVER).json()
        self.check(
            approved["status"] == "approved" and approved["changed"],
            "a second admin approved; funds reserved",
        )
        export1 = self.call("POST", f"/api/v1/payout-batches/{batch['id']}/export", json={})
        self.check(
            "90.00" in export1.text and DEMO_IBAN_A in export1.text, "payout export produced for the bank"
        )

        # idempotency --------------------------------------------------------
        self.say("\n== Repeat the same requests: nothing may be duplicated")
        entries_before = self.journal_entries()
        again = self.post(
            "/api/v1/provider/import-earnings", {"start": start.isoformat(), "end": end.isoformat()}
        ).json()
        self.check(
            again["import"]["status"] == "duplicate"
            and again["import"]["stats"]["new"] == 0
            and again["import"]["stats"]["revised"] == 0,
            "re-importing the same earnings posts nothing",
        )
        self.check(self.journal_entries() == entries_before, "the journal has no new entries")
        batch_again = self.call(
            "POST", "/api/v1/payout-batches", json=body, headers={"Idempotency-Key": key}, expect=(200,)
        ).json()
        self.check(
            batch_again["id"] == batch["id"] and batch_again["created"] is False,
            "the same settlement request returns the same batch",
        )
        approve_again = self.post(f"/api/v1/payout-batches/{batch['id']}/approve", as_user=APPROVER).json()
        self.check(approve_again["changed"] is False, "approving again reserves nothing more")
        export2 = self.call("POST", f"/api/v1/payout-batches/{batch['id']}/export", json={})
        self.check(export1.content == export2.content, "exporting again yields the identical file")
        second_key = self.call(
            "POST",
            "/api/v1/payout-batches",
            json=body,
            headers={"Idempotency-Key": key + "-second"},
            expect=(409,),
        )
        self.check(
            second_key.json()["error"]["code"] == "insufficient_reconciled_funds",
            "a different settlement request finds no money left to pay twice",
        )
        after = self.get(f"/api/v1/owners/{owners[0]['id']}/balance")
        self.check(
            (after["available_to_settle"], after["reserved_in_approved_payout"]) == ("0E-8", "90.00000000")
            or (
                Decimal(after["available_to_settle"]) == 0
                and Decimal(after["reserved_in_approved_payout"]) == Decimal("90")
            ),
            "owner balance: 0 available, 90.00 reserved, exactly once",
        )
        self.check(self.journal_entries() == entries_before, "still no new journal entries")

        # close the loop ------------------------------------------------------
        self.say("\n== Finish: submit and confirm with (simulated) evidence")
        submitted = self.post(f"/api/v1/payout-batches/{batch['id']}/submit").json()
        self.check(
            submitted["status"] == "submitted", "batch handed over (mock payout provider; no money moved)"
        )
        for item in submitted["items"]:
            self.post(
                f"/api/v1/payout-items/{item['id']}/confirm",
                {"reference": f"SIMULATED-BANK-{item['id'][:8]}", "note": "simulated evidence"},
            )
        final = self.get(f"/api/v1/owners/{owners[0]['id']}/statement")
        self.check(
            Decimal(final["balances_now"]["confirmed_paid_to_date"]) == Decimal("90"),
            "owner statement shows USD 90.00 paid",
        )
        verify = self.get("/api/v1/ledger/verify")
        self.check(
            verify["ok"], f"ledger verifies: {verify['entries']} balanced entries, cash equals obligations"
        )
        chain = self.get("/api/v1/audit-log/verify")
        self.check(chain["ok"], f"audit chain verifies: {chain['checked']} entries")
        self.say(f"\nAcceptance demo passed: {self.checks} checks. All data above is synthetic.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--simulator", required=True, type=Path)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if not args.simulator.is_file():
        print(
            f"simulator binary not found at {args.simulator}; run `make build-agent` first", file=sys.stderr
        )
        return 2
    try:
        Demo(args.api_url, args.simulator, args.quiet).run()
    except DemoFailure as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
