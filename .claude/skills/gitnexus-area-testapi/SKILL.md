---
name: gitnexus-area-testapi
description: "Skill for the Testapi area of firmware_happymining. 17 symbols across 2 files."
---

# Testapi

17 symbols | 2 files | Cohesion: 84%

## When to Use

- Working with code in `agent/`
- Understanding how TestSyntheticSamplesAreValidProtocolSamples, ValidateSample, Summarize work
- Modifying testapi-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/testapi/testapi.go` | ValidateSample, long, newToken, readBody, strictDecode (+11) |
| `agent/internal/sim/sim_test.go` | TestSyntheticSamplesAreValidProtocolSamples |

## Entry Points

Start here when exploring this area:

- **`TestSyntheticSamplesAreValidProtocolSamples`** (Function) — `agent/internal/sim/sim_test.go:44`
- **`ValidateSample`** (Function) — `agent/internal/testapi/testapi.go:509`
- **`Summarize`** (Method) — `agent/internal/testapi/testapi.go:653`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `TestSyntheticSamplesAreValidProtocolSamples` | Function | `agent/internal/sim/sim_test.go` | 44 |
| `ValidateSample` | Function | `agent/internal/testapi/testapi.go` | 509 |
| `Summarize` | Method | `agent/internal/testapi/testapi.go` | 653 |
| `long` | Function | `agent/internal/testapi/testapi.go` | 525 |
| `newToken` | Function | `agent/internal/testapi/testapi.go` | 122 |
| `readBody` | Function | `agent/internal/testapi/testapi.go` | 274 |
| `strictDecode` | Function | `agent/internal/testapi/testapi.go` | 287 |
| `writeError` | Function | `agent/internal/testapi/testapi.go` | 267 |
| `writeJSON` | Function | `agent/internal/testapi/testapi.go` | 261 |
| `auth` | Method | `agent/internal/testapi/testapi.go` | 371 |
| `handleAck` | Method | `agent/internal/testapi/testapi.go` | 560 |
| `handleEnroll` | Method | `agent/internal/testapi/testapi.go` | 328 |
| `handleHeartbeat` | Method | `agent/internal/testapi/testapi.go` | 400 |
| `handleOperations` | Method | `agent/internal/testapi/testapi.go` | 556 |
| `handleRotate` | Method | `agent/internal/testapi/testapi.go` | 618 |
| `handleSelf` | Method | `agent/internal/testapi/testapi.go` | 629 |
| `handleSummary` | Method | `agent/internal/testapi/testapi.go` | 678 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Main → WriteJSON` | cross_community | 5 |
| `HandleAck → WriteJSON` | intra_community | 4 |
| `HandleEnroll → WriteJSON` | intra_community | 4 |
| `HandleRotate → RandomBytes` | cross_community | 3 |
| `HandleHeartbeat → WriteJSON` | intra_community | 3 |

## How to Explore

1. `context({name: "TestSyntheticSamplesAreValidProtocolSamples"})` — see callers and callees
2. `query({search_query: "testapi"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
