# Earnings ledger and owner settlements

This is an **operational subledger for owner settlements, pending accounting
review**. It is not a statutory accounting system, it does not determine VAT
treatment, and nothing in it promises that hosting is profitable.

Code: `api/happymining/services/` (`ledger.py`, `earnings.py`, `receipts.py`,
`payouts.py`, `fees.py`, `statements.py`). Database rules: the hand-written
part of `migrations/versions/0001_initial_schema.py`.

## The idea in one paragraph

The provider (Vast) *reports* what each machine earned per day. That report is
an accrual, not money. Later the provider pays HappyMining. An operator records
that payment as a **receipt**, with evidence, and **allocates** it to the
earnings days it pays for. Only then does the owner's share become **available
to settle**. A settlement **reserves** it, a submission puts it **in transit**,
and bank evidence marks it **paid**. Each of these is a separate ledger
account, so "how much can we pay this owner right now" is never an estimate.

## Rules that always hold

| Rule | Enforced by |
|---|---|
| Money is `Decimal`, stored as `NUMERIC(24,8)`. No binary floats. The API accepts amounts only as decimal strings. | `to_decimal`, request schemas, column types |
| Journal entries and lines are immutable. A mistake is corrected by a new entry. | triggers `*_append_only`, `*_no_truncate` |
| Lines can only be added to an entry by the transaction that created it. A committed entry cannot grow. | `created_txid` on the entry, checked by a trigger on `journal_lines` |
| An account's kind, scope, side and overdraft rule never change. | append-only trigger on `ledger_accounts` |
| Every entry balances to zero and has at least two lines. | deferred constraint trigger `journal_lines_balanced` |
| The same business event posts once, however often it is submitted. | unique `idempotency_key` on `journal_entries` |
| Accounts that must not be overdrawn cannot be, even under concurrency. | trigger `journal_lines_apply` (row-locks the balance) |
| The balance cache can only be written by that trigger. | trigger `ledger_balances_guard` |
| A machine has exactly one owner on any day. | exclusion constraint `machine_ownership_no_overlap` |
| Cash on hand equals everything owed out of reconciled money. | `verify_ledger` (API `GET /api/v1/ledger/verify`, CLI `verify`) |
| The API and the worker cannot rewrite the journal or the audit trail, or switch the triggers off. | they connect as `happymining_app`, a role without `UPDATE`/`DELETE` on those tables and without ownership (`cli setup-runtime-role`) |

`verify_ledger` does not trust the running totals. It recomputes every balance
from the journal and compares it with the cache; checks that every account
still matches its definition and its code; checks each bucket and receipt
against the allocations they summarise; checks that every mapped day's owner
share and fee add up to the reported amount; checks that what the provider
still owes equals reported minus received; and checks each owner's accrued
balance against their buckets. Run it after a restore and on a schedule.

These rules bind the application. They do not bind the database owner role or
a superuser, who can disable triggers. That role is used by the migration job
only. See `docs/threat-model.md`.

## Accounts

Amounts are signed: a positive line is a debit, a negative line a credit.

| Account | Side | Overdraft | Meaning |
|---|---|---|---|
| `provider_receivable:<account>` | debit | allowed | Reported by the provider, not yet received. Goes negative when a day is revised down after it was paid. |
| `cash_clearing` | debit | **no** | Cash confirmed received, less payouts confirmed paid. |
| `receipts_unallocated:<account>` | credit | **no** | Suspense: cash received and not yet matched to earnings. |
| `unmapped_earnings:<account>` | credit | allowed | Reported earnings of machines not attributed to an owner. |
| `owner_accrued:<owner>` | credit | allowed | Owner share of reported, unreceived earnings. **Not payable.** |
| `owner_available:<owner>` | credit | **no** | Owner share received and reconciled. Available to settle. |
| `owner_reserved:<owner>` | credit | **no** | Reserved in an approved payout. |
| `owner_in_transit:<owner>` | credit | **no** | Payout submitted, outcome not yet confirmed. |
| `fee_accrued` | credit | allowed | Management fee on reported, unreceived earnings. |
| `fee_earned` | credit | allowed | Management fee on received and reconciled earnings. |

## Entries

| Event | Debit | Credit | Idempotency key |
|---|---|---|---|
| Earnings reported (first time or a correction, amount = delta) | `provider_receivable` | `owner_accrued`, `fee_accrued` | `earning:<bucket>:rev:<n>` |
| ... for a machine with no owner | `provider_receivable` | `unmapped_earnings` | same |
| Unmapped day attributed later | `unmapped_earnings` | `owner_accrued`, `fee_accrued` | `earning:<bucket>:attribute` |
| Receipt recorded | `cash_clearing` | `receipts_unallocated` | `receipt:<id>` |
| Receipt allocated to a day (`receipt_allocation`) | `receipts_unallocated`, `owner_accrued`, `fee_accrued` | `provider_receivable`, `owner_available`, `fee_earned` | `allocation:<id>` |
| Allocation taken back (`receipt_deallocation`, a negative allocation) | the same lines with the signs reversed | | `allocation:<id>` |
| Receipt voided (entered by mistake, nothing allocated) | `receipts_unallocated` | `cash_clearing` | reversal of `receipt:<id>` |
| Payout approved | `owner_available` | `owner_reserved` | `payout:<item>:reserve` |
| Payout submitted (or outcome unknown) | `owner_reserved` | `owner_in_transit` | `payout:<item>:submit` |
| Payout confirmed paid | `owner_in_transit` | `cash_clearing` | `payout:<item>:confirm` |
| Payout failed, on evidence | `owner_in_transit` | `owner_available` | `payout:<item>:fail` |
| Approved batch cancelled, or provider refused outright | `owner_reserved` | `owner_available` | `payout:<item>:release` |
| Confirmed payout returned by the bank | `cash_clearing` | `owner_available` | `payout:<item>:return` |

## Earnings import

**Canonical bucket: one provider machine on one closed UTC day.** Buckets never
overlap, so provider reports that overlap, or the same report fetched twice,
cannot double-count: an import posts only the *difference* between what the
provider says now and what is already recorded for the bucket.

- Unchanged amount: no revision, no entry. The import is recorded as
  `duplicate`.
- Changed amount: a new revision and one adjustment entry for the delta. The
  original entry stays. An `unexplained_adjustment` exception is opened and the
  day cannot be reconciled until someone resolves it.
- Only closed days are imported (`period_end` before today, UTC).
- The provider reports per machine per day. No per-job detail is derived.
- Every provider machine ever seen is asked about, including one that has
  since disappeared from the provider's list: its last days may not have been
  imported yet.

**Who a day belongs to** is decided by the day, not by today's state:

- the provider machine must have been bound to a HappyMining machine *on that
  day* (binding history is kept; unbinding takes effect the next UTC day, so
  the days up to and including the unbind day stay attributed);
- that machine's owner *on that day* gets the share. A transfer of ownership
  takes effect the next UTC day; the transfer day itself belongs to the
  previous owner.

Nothing is posted, and an exception is opened instead, when:

| Situation | Exception | What happens |
|---|---|---|
| Machine not bound, day before its binding date, or no owner on record that day | `unmapped_machine` | Posted to `unmapped_earnings`; not attributable, not payable. |
| No fee schedule in force for that owner and day | `no_fee_schedule` | Same. |
| Currency other than USD | `unknown_currency` | Row skipped. Nothing is converted. |
| Provider's per-machine total differs from the sum of its daily rows | `total_mismatch` | Whole report held. |
| Rows outside the requested period, duplicated rows, a machine filter that was not applied, a day that lacks one of the four documented components | `malformed_report` | Whole report held. A missing or renamed field is never read as "earned nothing". |
| A day imported earlier is absent from a later report that covers that machine and period | `missing_from_report` | Nothing is changed. The recorded amount stays until someone decides. |
| Provider semantics not verified (LIVE default) | `unverified_semantics` | Whole report held. See below. |

### Why LIVE earnings are held today

Two things about Vast's earnings endpoint are not documented
(`docs/integration-evidence.md`, C8 and C11): whether the amounts are net of
Vast's own fee, and the day unit and range boundaries. Posting on a guess could
subtract Vast's fee twice or split days wrongly. So in LIVE mode reports are
fetched and kept as evidence, and held, until an operator has verified both
and set `HM_VAST_EARNINGS_BASIS=net_of_provider_fee` and
`HM_VAST_EARNINGS_BUCKETS_VERIFIED=true`. A gross basis is not supported: the
system has no verified provider fee rate to apply.

## Management fee

- Fee schedules are versioned and never edited. `owner_id` NULL is the default;
  an owner-specific version takes precedence.
- A bucket stores the schedule and rate that applied on its day when first
  posted. Corrections to that bucket reuse the stored rate.
- A new version cannot start on or before a day that already has posted
  earnings in its scope (that owner's days for an owner-specific version, all
  attributed days for the default). Fees are never re-priced retroactively.
- Fee on a bucket = `reported × rate`, rounded half-even to 8 decimals; owner
  share = `reported − fee`, so the two always add up exactly.
- The 10% in the demo is a **DEMO assumption**, flagged as such in the data. It
  is not an approved commercial rate.

Example (DEMO, base already net of provider deductions):

```
Eligible settled host earnings   USD 100.00
HappyMining fee 10%              USD  10.00
Owner payable                    USD  90.00
```

## Reconciliation

- A receipt needs a bank or payout-provider reference, an evidence source and
  a note saying which statement shows it. The evidence source is one of
  `bank_statement` or `payout_provider_statement`: HappyMining's own statements.
  Nothing else is accepted. It is idempotent on (provider account, reference),
  also when two operators enter it at the same moment.
- A provider report is not a receipt. A Vast invoice marked "Paid" is not a
  receipt either: Vast documents that "Paid" means the payout was *submitted*
  (evidence F19).
- Allocation is explicit: to named buckets, or to every open attributed bucket
  in a period the operator states. If the open earnings in that period exceed
  what is left of the receipt, nothing is allocated. Differences are explained,
  not spread by a rule.
- Allocation requests over the API carry an `Idempotency-Key` header. The same
  key posts once; the same key with different content is refused.
- Whatever is not allocated stays in `receipts_unallocated` and shows as an
  open `receipt_remainder` exception.
- A day's received amount stays between zero and its reported amount. A
  receipt's allocations never add up to more than the receipt. Both are checked
  on rows locked and re-read inside the transaction, so two operators
  allocating at once cannot both succeed.
- A receipt entered by mistake is **voided**, not deleted: a reversing entry is
  posted, the original stays in the journal, and the reference becomes free
  again. Only a receipt with nothing allocated can be voided.

### When the provider revises a paid day

A day can be revised down after its cash was allocated, and possibly after the
owner was paid. The ledger then holds more "received" for that day than the
provider now reports.

1. The import posts the correction, opens `unexplained_adjustment` (someone
   must understand the change) and opens `over_received` for the day.
2. The owner is **held**: not included in a new batch, not approvable in an
   existing draft, and an approved batch that has not been exported can be
   neither exported nor submitted. The hold comes from the day itself, not
   only from the exception: closing an `over_received` exception with a note
   is refused while the day is still over-received.
3. The correction is a **negative allocation** (de-allocation) of the
   difference, back to the receipt's unallocated remainder. It takes the money
   out of `owner_available` and `fee_earned`. When the day is back in range the
   `over_received` exception closes itself.
4. If the owner's available balance no longer covers it (already reserved or
   paid out), the de-allocation is refused. Cancel the unexported batch to
   release the reserve; if the money has left, the owner stays held until later
   earnings cover the difference or it is recovered outside the system. The
   software does not create a negative owner balance and does not net it
   silently.

A batch whose file was already exported cannot be cancelled, because the file
may be at the bank. Recording it as submitted is still allowed with the manual
provider (it records a fact); each item is then settled with bank evidence,
paid or failed.

## Settlement

States of a payout item: `draft` → `reserved` → `submitted` →
`confirmed_paid`, with `uncertain`, `failed`, `reversed` and `cancelled` as
the other outcomes.

1. **Prepare** (`POST /payout-batches`, `Idempotency-Key` header required).
   Drafts one item per owner from the available balance, **rounded down to
   cents**. The sub-cent remainder stays available for next time. Reserves
   nothing. Held owners are left out. Synthetic owners are never drafted in
   LIVE, and real owners never in DEMO.
2. **Approve.** Reserves every item or none. By default the approver must be a
   different admin from the preparer. Fails if an owner has no beneficiary on
   file, is held, or if the funds are no longer there.
3. **Export.** A deterministic CSV with the decrypted beneficiary details.
   Admin only, audited, repeatable; moves no money. Cells that a spreadsheet
   would read as a formula are neutralised. After the first export the batch
   can no longer be cancelled.
4. **Submit.** Records that the batch was handed to the bank. Only `reserved`
   items are processed. If the payout provider raises an error, the item
   becomes `uncertain`, not `failed`.
5. **Confirm, with evidence.** Paid, failed or returned, each with a bank
   reference. One bank reference confirms one item. A bulk import applies a
   result file all-or-nothing.

How a double payment is prevented:

- the batch idempotency key: the same request returns the same batch;
- the reserve: two approvals cannot both take the same money, because the
  database refuses to overdraw `owner_available`;
- per-item idempotency keys on every ledger step;
- an exported batch cannot be cancelled and its reserve released;
- **an unknown outcome is not a failure.** A timeout leaves the funds in
  transit. They cannot be paid again until evidence shows the first attempt
  failed.

There is no automatic money transfer. `manual_export` means an operator pays
the exported file at the bank. `mock` exists for DEMO and tests and is rejected
in LIVE. A real provider can be added behind
`payout_providers/base.py`; it must stay disabled until explicitly configured
and separately authorised.

## Owner statement

`GET /api/v1/owners/{id}/statement` shows, separately: provider-reported
earnings; the eligible base (received and reconciled); the fee; adjustments in
the period; the reserve (reserved plus in transit); and what is payable now.

## What this ledger does not do

- No currency conversion. USD only.
- No VAT or tax logic.
- No fee withdrawal flow: `fee_earned` accumulates in `cash_clearing`.
- No automatic matching of provider payouts to earnings days.
- No holdback reserve percentage. "Reserve" on a statement means money in an
  approved or submitted payout.
- No negative owner balance. Money paid to an owner and later taken back by
  the provider is a held exception, recovered by a person.
