---
name: gitnexus-area-preflight
description: "Skill for the Preflight area of firmware_happymining. 57 symbols across 7 files."
---

# Preflight

57 symbols | 7 files | Cohesion: 86%

## When to Use

- Working with code in `agent/`
- Understanding how CompareVersions, ParseOSRelease, Run work
- Modifying preflight-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/preflight/checks.go` | CompareVersions, ParseOSRelease, versionParts, checkArch, checkCPUFlags (+19) |
| `agent/internal/preflight/preflight_test.go` | TestCompareVersions, TestArchitecture, TestCoexistingDockerInstallsFail, TestDockerVariants, TestDriverInstalledButBroken (+18) |
| `agent/internal/preflight/preflight.go` | Run, gate, add, Render |
| `agent/internal/preflight/requirements.go` | EmbeddedRequirements, LoadRequirements, ParseRequirements |
| `agent/internal/protocol/protocol.go` | Truncate |
| `agent/internal/ctl/ctl.go` | hostOS |
| `agent/internal/execx/execx.go` | On |

## Entry Points

Start here when exploring this area:

- **`CompareVersions`** (Function) — `agent/internal/preflight/checks.go:316`
- **`ParseOSRelease`** (Function) — `agent/internal/preflight/checks.go:48`
- **`Run`** (Function) — `agent/internal/preflight/preflight.go:99`
- **`TestCompareVersions`** (Function) — `agent/internal/preflight/preflight_test.go:579`
- **`Truncate`** (Function) — `agent/internal/protocol/protocol.go:237`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `CompareVersions` | Function | `agent/internal/preflight/checks.go` | 316 |
| `ParseOSRelease` | Function | `agent/internal/preflight/checks.go` | 48 |
| `Run` | Function | `agent/internal/preflight/preflight.go` | 99 |
| `TestCompareVersions` | Function | `agent/internal/preflight/preflight_test.go` | 579 |
| `Truncate` | Function | `agent/internal/protocol/protocol.go` | 237 |
| `Render` | Function | `agent/internal/preflight/preflight.go` | 155 |
| `TestArchitecture` | Function | `agent/internal/preflight/preflight_test.go` | 470 |
| `TestCoexistingDockerInstallsFail` | Function | `agent/internal/preflight/preflight_test.go` | 255 |
| `TestDockerVariants` | Function | `agent/internal/preflight/preflight_test.go` | 264 |
| `TestDriverInstalledButBroken` | Function | `agent/internal/preflight/preflight_test.go` | 334 |
| `TestExistingVastInstallIsReportedAndPreserved` | Function | `agent/internal/preflight/preflight_test.go` | 284 |
| `TestGPUOnPCIBusWithoutDriver` | Function | `agent/internal/preflight/preflight_test.go` | 319 |
| `TestHardwareThresholds` | Function | `agent/internal/preflight/preflight_test.go` | 342 |
| `TestMissingGPUFails` | Function | `agent/internal/preflight/preflight_test.go` | 302 |
| `TestOfflineSkipsNetworkChecks` | Function | `agent/internal/preflight/preflight_test.go` | 458 |
| `TestReportStatesThatPassingIsNoGuarantee` | Function | `agent/internal/preflight/preflight_test.go` | 186 |
| `TestSecureBootVirtualizationTimeAndNetwork` | Function | `agent/internal/preflight/preflight_test.go` | 427 |
| `TestSnapDockerFails` | Function | `agent/internal/preflight/preflight_test.go` | 241 |
| `TestStorageChecks` | Function | `agent/internal/preflight/preflight_test.go` | 384 |
| `TestSupportedHostPasses` | Function | `agent/internal/preflight/preflight_test.go` | 155 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → CPUInfo` | cross_community | 4 |
| `Run → Path` | intra_community | 4 |
| `CollectDiagnostics → Truncate` | cross_community | 4 |
| `Run → Gate` | intra_community | 3 |
| `Run → Add` | intra_community | 3 |
| `Run → Check` | intra_community | 3 |
| `Run → Truncate` | intra_community | 3 |

## How to Explore

1. `context({name: "CompareVersions"})` — see callers and callees
2. `query({search_query: "preflight"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
