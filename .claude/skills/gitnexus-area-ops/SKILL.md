---
name: gitnexus-area-ops
description: "Skill for the Ops area of firmware_happymining. 64 symbols across 8 files."
---

# Ops

64 symbols | 8 files | Cohesion: 78%

## When to Use

- Working with code in `agent/`
- Understanding how Discard, OpenJournal, NewHandler work
- Modifying ops-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/ops/ops_test.go` | TestAckErrorsDoNotStopHandling, TestBadParamsAreRejected, TestDefaultEnabledOperationsRun, TestDisabledByDefaultTypesAreRejected, TestExpiredAndBadTimestampsAreRejected (+25) |
| `agent/internal/ops/ops.go` | reject, NewHandler, ParseDiagnosticsParams, ParseRebootParams, isKnown (+11) |
| `agent/internal/ops/journal.go` | OpenJournal, Close, Finish, Lookup, Start (+5) |
| `agent/internal/agent/exec.go` | RefreshInventory, RotateCredential, RunPreflight, Ack |
| `agent/internal/logx/logx.go` | Discard |
| `agent/internal/protocol/protocol.go` | FormatTime |
| `agent/internal/client/client.go` | IsFinalForAck |
| `agent/internal/client/client_test.go` | TestIsFinalForAck |

## Entry Points

Start here when exploring this area:

- **`Discard`** (Function) — `agent/internal/logx/logx.go:48`
- **`OpenJournal`** (Function) — `agent/internal/ops/journal.go:73`
- **`NewHandler`** (Function) — `agent/internal/ops/ops.go:78`
- **`ParseDiagnosticsParams`** (Function) — `agent/internal/ops/ops.go:154`
- **`ParseRebootParams`** (Function) — `agent/internal/ops/ops.go:185`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Discard` | Function | `agent/internal/logx/logx.go` | 48 |
| `OpenJournal` | Function | `agent/internal/ops/journal.go` | 73 |
| `NewHandler` | Function | `agent/internal/ops/ops.go` | 78 |
| `ParseDiagnosticsParams` | Function | `agent/internal/ops/ops.go` | 154 |
| `ParseRebootParams` | Function | `agent/internal/ops/ops.go` | 185 |
| `TestAckErrorsDoNotStopHandling` | Function | `agent/internal/ops/ops_test.go` | 475 |
| `TestBadParamsAreRejected` | Function | `agent/internal/ops/ops_test.go` | 167 |
| `TestDefaultEnabledOperationsRun` | Function | `agent/internal/ops/ops_test.go` | 125 |
| `TestDisabledByDefaultTypesAreRejected` | Function | `agent/internal/ops/ops_test.go` | 242 |
| `TestExpiredAndBadTimestampsAreRejected` | Function | `agent/internal/ops/ops_test.go` | 206 |
| `TestFailureIsReportedAsFailed` | Function | `agent/internal/ops/ops_test.go` | 421 |
| `TestHandleAllBoundsTheBatch` | Function | `agent/internal/ops/ops_test.go` | 463 |
| `TestInterruptedOperationIsNotExecutedAgain` | Function | `agent/internal/ops/ops_test.go` | 352 |
| `TestInvalidIDsAndNonces` | Function | `agent/internal/ops/ops_test.go` | 399 |
| `TestJournalFailureMeansNoExecution` | Function | `agent/internal/ops/ops_test.go` | 387 |
| `TestJournalPruning` | Function | `agent/internal/ops/ops_test.go` | 487 |
| `TestJournalToleratesTornLastLine` | Function | `agent/internal/ops/ops_test.go` | 541 |
| `TestJournaledBeforeExecution` | Function | `agent/internal/ops/ops_test.go` | 374 |
| `TestNotImplementedTypesNeverFakeSuccess` | Function | `agent/internal/ops/ops_test.go` | 278 |
| `TestOptInOperationsRunThroughTheExecutor` | Function | `agent/internal/ops/ops_test.go` | 257 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Append` | cross_community | 3 |

## How to Explore

1. `context({name: "Discard"})` — see callers and callees
2. `query({search_query: "ops"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
