---
name: gitnexus-area-spool
description: "Skill for the Spool area of firmware_happymining. 28 symbols across 6 files."
---

# Spool

28 symbols | 6 files | Cohesion: 75%

## When to Use

- Working with code in `agent/`
- Understanding how Open, Stat, TestCorruptFilesAreDroppedNotSent work
- Modifying spool-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/spool/spool_test.go` | TestCorruptFilesAreDroppedNotSent, TestOrderingAndDelete, TestPeekRespectsByteBudget, TestPurgeAndDeviceMarker, TestPutRejectsBadInput (+7) |
| `agent/internal/spool/spool.go` | Open, Stat, parseName, Device, Purge (+6) |
| `agent/internal/redact/redact.go` | AddSecret, addLocked |
| `agent/internal/agent/agent.go` | adopt |
| `agent/internal/backoff/backoff.go` | Reset |
| `agent/internal/spool/sequence.go` | OpenSequence |

## Entry Points

Start here when exploring this area:

- **`Open`** (Function) — `agent/internal/spool/spool.go:66`
- **`Stat`** (Function) — `agent/internal/spool/spool.go:246`
- **`TestCorruptFilesAreDroppedNotSent`** (Function) — `agent/internal/spool/spool_test.go:157`
- **`TestOrderingAndDelete`** (Function) — `agent/internal/spool/spool_test.go:23`
- **`TestPeekRespectsByteBudget`** (Function) — `agent/internal/spool/spool_test.go:59`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Open` | Function | `agent/internal/spool/spool.go` | 66 |
| `Stat` | Function | `agent/internal/spool/spool.go` | 246 |
| `TestCorruptFilesAreDroppedNotSent` | Function | `agent/internal/spool/spool_test.go` | 157 |
| `TestOrderingAndDelete` | Function | `agent/internal/spool/spool_test.go` | 23 |
| `TestPeekRespectsByteBudget` | Function | `agent/internal/spool/spool_test.go` | 59 |
| `TestPurgeAndDeviceMarker` | Function | `agent/internal/spool/spool_test.go` | 174 |
| `TestPutRejectsBadInput` | Function | `agent/internal/spool/spool_test.go` | 135 |
| `TestQuotaEvictsOldestFirst` | Function | `agent/internal/spool/spool_test.go` | 76 |
| `TestReopenKeepsSamplesAndRemovesTempFiles` | Function | `agent/internal/spool/spool_test.go` | 110 |
| `OpenSequence` | Function | `agent/internal/spool/sequence.go` | 28 |
| `TestSequenceAdvanceTo` | Function | `agent/internal/spool/spool_test.go` | 259 |
| `TestSequenceNeverGoesBelowTheSpool` | Function | `agent/internal/spool/spool_test.go` | 236 |
| `TestSequencePersistsAcrossRestart` | Function | `agent/internal/spool/spool_test.go` | 199 |
| `Reset` | Method | `agent/internal/backoff/backoff.go` | 87 |
| `AddSecret` | Method | `agent/internal/redact/redact.go` | 50 |
| `Device` | Method | `agent/internal/spool/spool.go` | 231 |
| `Purge` | Method | `agent/internal/spool/spool.go` | 201 |
| `SetDevice` | Method | `agent/internal/spool/spool.go` | 240 |
| `Peek` | Method | `agent/internal/spool/spool.go` | 139 |
| `Put` | Method | `agent/internal/spool/spool.go` | 120 |

## How to Explore

1. `context({name: "Open"})` — see callers and callees
2. `query({search_query: "spool"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
