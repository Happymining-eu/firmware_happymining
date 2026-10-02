---
name: gitnexus-area-collector
description: "Skill for the Collector area of firmware_happymining. 51 symbols across 9 files."
---

# Collector

51 symbols | 9 files | Cohesion: 66%

## When to Use

- Working with code in `agent/`
- Understanding how UnitState, TestUnitStateMapping, FindAbs work
- Modifying collector-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/collector/collector_test.go` | TestUnitStateMapping, TestCollectorOnlyRunsAllowlistedCommands, TestNvidiaSMIFailureGivesEmptyList, TestRealCollectorOnFakeRoot, TestSamplePrivacyWhitelist (+12) |
| `agent/internal/collector/collector.go` | UnitState, GPUs, Services, Collect, isDecimalID (+7) |
| `agent/internal/collector/proc.go` | ParseCPUInfo, ParseMemInfo, cpuUtil, parseFirstFloat, parseProcStat (+4) |
| `agent/internal/execx/execx.go` | FindAbs, Run, Run, NewFake |
| `agent/internal/collector/nvsmi.go` | ParseNvidiaSMI, cleanString, parseInt, parseNumber |
| `agent/internal/execx/execx_test.go` | TestFindAbs, TestFake |
| `agent/internal/preflight/checks.go` | checkTimeSync |
| `agent/internal/config/config.go` | IsVastSecretFile |
| `agent/internal/config/config_test.go` | TestVastKeyFileIsRejectedAsMachineIDFile |

## Entry Points

Start here when exploring this area:

- **`UnitState`** (Function) — `agent/internal/collector/collector.go:235`
- **`TestUnitStateMapping`** (Function) — `agent/internal/collector/collector_test.go:333`
- **`FindAbs`** (Function) — `agent/internal/execx/execx.go:39`
- **`TestFindAbs`** (Function) — `agent/internal/execx/execx_test.go:82`
- **`TestCollectorOnlyRunsAllowlistedCommands`** (Function) — `agent/internal/collector/collector_test.go:449`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `UnitState` | Function | `agent/internal/collector/collector.go` | 235 |
| `TestUnitStateMapping` | Function | `agent/internal/collector/collector_test.go` | 333 |
| `FindAbs` | Function | `agent/internal/execx/execx.go` | 39 |
| `TestFindAbs` | Function | `agent/internal/execx/execx_test.go` | 82 |
| `TestCollectorOnlyRunsAllowlistedCommands` | Function | `agent/internal/collector/collector_test.go` | 449 |
| `TestNvidiaSMIFailureGivesEmptyList` | Function | `agent/internal/collector/collector_test.go` | 319 |
| `TestRealCollectorOnFakeRoot` | Function | `agent/internal/collector/collector_test.go` | 227 |
| `TestSamplePrivacyWhitelist` | Function | `agent/internal/collector/collector_test.go` | 393 |
| `TestVastHintIsNullWhenUnreadable` | Function | `agent/internal/collector/collector_test.go` | 305 |
| `TestVastKeyFileIsNeverRead` | Function | `agent/internal/collector/collector_test.go` | 466 |
| `IsVastSecretFile` | Function | `agent/internal/config/config.go` | 401 |
| `TestVastKeyFileIsRejectedAsMachineIDFile` | Function | `agent/internal/config/config_test.go` | 127 |
| `TestParseNvidiaSMIMissingValuesBecomeNull` | Function | `agent/internal/collector/collector_test.go` | 37 |
| `TestParseNvidiaSMIMultiGPU` | Function | `agent/internal/collector/collector_test.go` | 17 |
| `TestParseNvidiaSMIRobustness` | Function | `agent/internal/collector/collector_test.go` | 76 |
| `ParseNvidiaSMI` | Function | `agent/internal/collector/nvsmi.go` | 58 |
| `TestParseProcFiles` | Function | `agent/internal/collector/collector_test.go` | 106 |
| `ParseCPUInfo` | Function | `agent/internal/collector/proc.go` | 18 |
| `ParseMemInfo` | Function | `agent/internal/collector/proc.go` | 102 |
| `MountFor` | Function | `agent/internal/collector/proc.go` | 188 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `CollectDiagnostics → Path` | cross_community | 5 |
| `Run → CPUInfo` | cross_community | 4 |
| `CollectDiagnostics → Truncate` | cross_community | 4 |

## How to Explore

1. `context({name: "UnitState"})` — see callers and callees
2. `query({search_query: "collector"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
