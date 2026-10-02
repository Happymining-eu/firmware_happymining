"""Serialisers shared by the JSON API and the dashboard."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import (
    EarningBucket,
    ExceptionItem,
    Machine,
    Operation,
    Owner,
    PayoutBatch,
    PayoutItem,
    ProviderMachine,
    ProviderReceipt,
    TelemetrySample,
    utcnow,
)
from ..services.devices import device_state
from ..services.ledger import money_str


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def page(db: Session, query: Any, limit: int, offset: int, render: Any) -> dict[str, Any]:
    total = db.execute(select(func.count()).select_from(query.order_by(None).subquery())).scalar_one()
    rows = db.execute(query.limit(limit).offset(offset)).scalars().all()
    return {"items": [render(r) for r in rows], "limit": limit, "offset": offset, "total": total}


def owner_view(owner: Owner) -> dict[str, Any]:
    return {
        "id": str(owner.id),
        "display_name": owner.display_name,
        "status": owner.status,
        "synthetic": owner.is_synthetic,
        "created_at": iso(owner.created_at),
    }


def machine_view(settings: Settings, machine: Machine, *, staff: bool) -> dict[str, Any]:
    device = machine.device
    pm = machine.provider_machine
    now = utcnow()
    out: dict[str, Any] = {
        "id": str(machine.id),
        "label": machine.label,
        "owner_id": str(machine.owner_id),
        "status": machine.status,
        "synthetic": machine.is_synthetic,
        "connection": device_state(settings, device, now),
        "last_seen_at": iso(device.last_seen_at) if device else None,
        "last_seen_age_s": int((now - device.last_seen_at).total_seconds())
        if device and device.last_seen_at
        else None,
        "agent_version": device.agent_version if device else None,
        "hardware": {k: v for k, v in (machine.hardware or {}).items() if k != "vast_machine_id_hint"},
        "provider": None,
    }
    if pm is not None:
        out["provider"] = {
            "provider": pm.account.provider,
            "external_id": pm.external_id,
            "rental_state": pm.rental_state,
            "listed": pm.listed,
            "state_observed_at": iso(pm.state_observed_at),
            "state_stale": pm.state_observed_at is None
            or (now - pm.state_observed_at).total_seconds() > 3600,
            "state_detail": pm.state_detail,
            "missing_from_provider": pm.missing_since is not None,
        }
    if staff:
        out["device_id"] = str(device.id) if device else None
        out["device_status"] = device.status if device else None
        out["vast_machine_id_hint"] = (machine.hardware or {}).get("vast_machine_id_hint")
    return out


def telemetry_view(sample: TelemetrySample, *, staff: bool = False) -> dict[str, Any]:
    payload = sample.payload
    if not staff and isinstance(payload, dict) and isinstance(payload.get("vast"), dict):
        # The agent's guess at the provider machine is evidence for the admin
        # who binds machines, and for nobody else.
        payload = {**payload, "vast": {k: v for k, v in payload["vast"].items() if k != "machine_id_hint"}}
    return {
        "seq": sample.seq,
        "collected_at": iso(sample.collected_at),
        "received_at": iso(sample.received_at),
        "synthetic": sample.synthetic,
        "gpu_count": sample.gpu_count,
        "gpu_util_avg": float(sample.gpu_util_avg) if sample.gpu_util_avg is not None else None,
        "gpu_power_w": float(sample.gpu_power_w) if sample.gpu_power_w is not None else None,
        "gpu_temp_max": float(sample.gpu_temp_max) if sample.gpu_temp_max is not None else None,
        "payload": payload,
    }


def operation_view(operation: Operation) -> dict[str, Any]:
    return {
        "id": str(operation.id),
        "machine_id": str(operation.machine_id),
        "type": operation.type,
        "params": operation.params,
        "status": operation.status,
        "issued_at": iso(operation.issued_at),
        "expires_at": iso(operation.expires_at),
        "delivered_at": iso(operation.delivered_at),
        "completed_at": iso(operation.completed_at),
        "detail": operation.detail,
        "result": operation.result,
        "safety": operation.safety,
        "requested_by": str(operation.requested_by) if operation.requested_by else None,
        "requested_by_client": str(operation.requested_by_client) if operation.requested_by_client else None,
    }


def provider_machine_view(pm: ProviderMachine) -> dict[str, Any]:
    return {
        "id": str(pm.id),
        "provider_account_id": str(pm.provider_account_id),
        "external_id": pm.external_id,
        "hostname": pm.hostname,
        "gpu_name": pm.gpu_name,
        "num_gpus": pm.num_gpus,
        "machine_id": str(pm.machine_id) if pm.machine_id else None,
        "bound_from": pm.bound_from.isoformat() if pm.bound_from else None,
        "rental_state": pm.rental_state,
        "listed": pm.listed,
        "state_detail": pm.state_detail,
        "state_observed_at": iso(pm.state_observed_at),
        "last_seen_at": iso(pm.last_seen_at),
        "missing_since": iso(pm.missing_since),
    }


def bucket_view(bucket: EarningBucket) -> dict[str, Any]:
    return {
        "id": str(bucket.id),
        "provider_account_id": str(bucket.provider_account_id),
        "external_machine_id": bucket.external_machine_id,
        "machine_id": str(bucket.machine_id) if bucket.machine_id else None,
        "owner_id": str(bucket.owner_id) if bucket.owner_id else None,
        "day": bucket.day.isoformat(),
        "currency": bucket.currency,
        "status": bucket.status,
        "fee_rate": money_str(bucket.fee_rate) if bucket.fee_rate is not None else None,
        "reported": money_str(bucket.reported_amount),
        "received": money_str(bucket.received_amount),
        "owner_share_reported": money_str(bucket.owner_accrued),
        "fee_reported": money_str(bucket.fee_accrued),
        "owner_share_reconciled": money_str(bucket.owner_released),
        "fee_reconciled": money_str(bucket.fee_released),
        "revisions": bucket.revision_count,
        "synthetic": bucket.is_synthetic,
    }


def receipt_view(receipt: ProviderReceipt) -> dict[str, Any]:
    return {
        "id": str(receipt.id),
        "provider_account_id": str(receipt.provider_account_id),
        "reference": receipt.reference,
        "received_on": receipt.received_on.isoformat(),
        "amount": money_str(receipt.amount),
        "allocated": money_str(receipt.allocated_amount),
        "unallocated": money_str(receipt.amount - receipt.allocated_amount),
        "currency": receipt.currency,
        "evidence_source": receipt.evidence_source,
        "evidence_note": receipt.evidence_note,
        "voided": receipt.voided_at is not None,
        "void_reason": receipt.void_reason,
        "synthetic": receipt.is_synthetic,
        "created_at": iso(receipt.created_at),
    }


def item_view(item: PayoutItem, *, staff: bool) -> dict[str, Any]:
    out = {
        "id": str(item.id),
        "batch_id": str(item.batch_id),
        "owner_id": str(item.owner_id),
        "amount": f"{item.amount:.2f}",
        "currency": item.currency,
        "status": item.status,
        "updated_at": iso(item.updated_at),
    }
    if staff:
        out["external_reference"] = item.external_reference
        out["failure_reason"] = item.failure_reason
    return out


def batch_view(batch: PayoutBatch, *, staff: bool = True) -> dict[str, Any]:
    return {
        "id": str(batch.id),
        "status": batch.status,
        "currency": batch.currency,
        "note": batch.note,
        "synthetic": batch.is_synthetic,
        "created_at": iso(batch.created_at),
        "created_by": str(batch.created_by) if batch.created_by else None,
        "approved_at": iso(batch.approved_at),
        "approved_by": str(batch.approved_by) if batch.approved_by else None,
        "submitted_at": iso(batch.submitted_at),
        "export_sha256": batch.export_sha256,
        "export_count": batch.export_count,
        "total": f"{sum((i.amount for i in batch.items), start=0):.2f}",
        "items": [item_view(i, staff=staff) for i in batch.items],
    }


def exception_view(item: ExceptionItem) -> dict[str, Any]:
    return {
        "id": str(item.id),
        "kind": item.kind,
        "status": item.status,
        "summary": item.summary,
        "details": item.details,
        "owner_id": str(item.owner_id) if item.owner_id else None,
        "created_at": iso(item.created_at),
        "resolved_at": iso(item.resolved_at),
        "resolution": item.resolution,
    }
