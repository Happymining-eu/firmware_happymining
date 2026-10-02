---
name: gitnexus-area-fsx
description: "Skill for the Fsx area of firmware_happymining. 11 symbols across 4 files."
---

# Fsx

11 symbols | 4 files | Cohesion: 59%

## When to Use

- Working with code in `agent/`
- Understanding how IsTempName, SyncDir, WriteFileAtomic work
- Modifying fsx-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/fsx/fsx.go` | IsTempName, SyncDir, WriteFileAtomic, fail |
| `agent/internal/fsx/fsx_test.go` | TestIsTempName, TestWriteFileAtomicFailureKeepsOldFile, TestWriteFileAtomicReplacesAndCleansUp |
| `agent/internal/spool/sequence.go` | AdvanceTo, Next, persist |
| `agent/internal/agent/state.go` | writeState |

## Entry Points

Start here when exploring this area:

- **`IsTempName`** (Function) — `agent/internal/fsx/fsx.go:24`
- **`SyncDir`** (Function) — `agent/internal/fsx/fsx.go:70`
- **`WriteFileAtomic`** (Function) — `agent/internal/fsx/fsx.go:32`
- **`TestIsTempName`** (Function) — `agent/internal/fsx/fsx_test.go:61`
- **`TestWriteFileAtomicFailureKeepsOldFile`** (Function) — `agent/internal/fsx/fsx_test.go:31`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `IsTempName` | Function | `agent/internal/fsx/fsx.go` | 24 |
| `SyncDir` | Function | `agent/internal/fsx/fsx.go` | 70 |
| `WriteFileAtomic` | Function | `agent/internal/fsx/fsx.go` | 32 |
| `TestIsTempName` | Function | `agent/internal/fsx/fsx_test.go` | 61 |
| `TestWriteFileAtomicFailureKeepsOldFile` | Function | `agent/internal/fsx/fsx_test.go` | 31 |
| `TestWriteFileAtomicReplacesAndCleansUp` | Function | `agent/internal/fsx/fsx_test.go` | 8 |
| `AdvanceTo` | Method | `agent/internal/spool/sequence.go` | 65 |
| `Next` | Method | `agent/internal/spool/sequence.go` | 51 |
| `writeState` | Function | `agent/internal/agent/state.go` | 57 |
| `fail` | Function | `agent/internal/fsx/fsx.go` | 39 |
| `persist` | Method | `agent/internal/spool/sequence.go` | 79 |

## How to Explore

1. `context({name: "IsTempName"})` — see callers and callees
2. `query({search_query: "fsx"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
