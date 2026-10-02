---
name: gitnexus-area-ctl
description: "Skill for the Ctl area of firmware_happymining. 85 symbols across 21 files."
---

# Ctl

85 symbols | 21 files | Cohesion: 80%

## When to Use

- Working with code in `agent/`
- Understanding how Load, Path, Save work
- Modifying ctl-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/ctl/ctl_test.go` | TestBrokenConfigIsAnError, TestIdentityInit, TestPairCodeIsNotReadFromTheEnvironment, TestPairFailures, TestPairRefusesInsecureURL (+11) |
| `agent/internal/ctl/ctl.go` | Run, ensureStateDir, lookupAgentOwner, client, config (+9) |
| `agent/internal/testapi/testapi.go` | New, newUUID, randomBytes, Device, DeviceIDs (+3) |
| `agent/internal/credential/credential_test.go` | TestDelete, TestLoadRefusesLoosePermissions, TestLoadRejectsGarbage, TestSaveIsAtomicAndKeepsOldOnFailure, TestSaveLoadPermissions (+2) |
| `agent/internal/redact/redact_test.go` | TestJSONRedactsStringsAndSensitiveKeys, TestOrdinaryTextIsUntouched, TestRegisteredSecrets, TestStringRedactsTokensBearerAndPairingCodes, TestWriter |
| `agent/internal/ctl/tty.go` | IsTerminal, ReadSecretFromTerminal, getTermios, readLine, setTermios |
| `agent/internal/credential/credential.go` | Load, Path, Save, Validate |
| `agent/internal/sim/sim.go` | Run, simBootID, validate |
| `agent/internal/sim/sim_test.go` | TestSimulatorEndToEnd, TestSimulatorInputValidation, TestSimulatorRefusedInLiveMode |
| `agent/cmd/hm-simulator/main.go` | main, readCodes, run |

## Entry Points

Start here when exploring this area:

- **`Load`** (Function) — `agent/internal/credential/credential.go:60`
- **`Path`** (Function) — `agent/internal/credential/credential.go:45`
- **`Save`** (Function) — `agent/internal/credential/credential.go:96`
- **`TestDelete`** (Function) — `agent/internal/credential/credential_test.go:118`
- **`TestLoadRefusesLoosePermissions`** (Function) — `agent/internal/credential/credential_test.go:55`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Load` | Function | `agent/internal/credential/credential.go` | 60 |
| `Path` | Function | `agent/internal/credential/credential.go` | 45 |
| `Save` | Function | `agent/internal/credential/credential.go` | 96 |
| `TestDelete` | Function | `agent/internal/credential/credential_test.go` | 118 |
| `TestLoadRefusesLoosePermissions` | Function | `agent/internal/credential/credential_test.go` | 55 |
| `TestLoadRejectsGarbage` | Function | `agent/internal/credential/credential_test.go` | 102 |
| `TestSaveIsAtomicAndKeepsOldOnFailure` | Function | `agent/internal/credential/credential_test.go` | 74 |
| `TestSaveLoadPermissions` | Function | `agent/internal/credential/credential_test.go` | 32 |
| `TestBrokenConfigIsAnError` | Function | `agent/internal/ctl/ctl_test.go` | 433 |
| `TestIdentityInit` | Function | `agent/internal/ctl/ctl_test.go` | 97 |
| `TestPairCodeIsNotReadFromTheEnvironment` | Function | `agent/internal/ctl/ctl_test.go` | 252 |
| `TestPairFailures` | Function | `agent/internal/ctl/ctl_test.go` | 196 |
| `TestPairRefusesInsecureURL` | Function | `agent/internal/ctl/ctl_test.go` | 240 |
| `TestPairWithPromptedCode` | Function | `agent/internal/ctl/ctl_test.go` | 135 |
| `TestPreflightCommand` | Function | `agent/internal/ctl/ctl_test.go` | 362 |
| `TestStateDirectoryCreatedByRootBelongsToTheAgentAccount` | Function | `agent/internal/ctl/ctl_test.go` | 448 |
| `TestStatus` | Function | `agent/internal/ctl/ctl_test.go` | 264 |
| `TestUnpair` | Function | `agent/internal/ctl/ctl_test.go` | 331 |
| `TestUsageAndVersion` | Function | `agent/internal/ctl/ctl_test.go` | 421 |
| `TestVastEnrollHelp` | Function | `agent/internal/ctl/ctl_test.go` | 397 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Main → WriteJSON` | cross_community | 5 |
| `Run → Redactor` | cross_community | 4 |
| `Run → Writer` | cross_community | 4 |
| `Main → RandomBytes` | intra_community | 4 |
| `Main → Server` | intra_community | 3 |
| `Main → Now` | intra_community | 3 |
| `Main → Enrollment` | intra_community | 3 |
| `HandleRotate → RandomBytes` | cross_community | 3 |

## How to Explore

1. `context({name: "Load"})` — see callers and callees
2. `query({search_query: "ctl"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
