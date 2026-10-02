---
name: gitnexus-area-packaging
description: "Skill for the Packaging area of firmware_happymining. 21 symbols across 1 files."
---

# Packaging

21 symbols | 1 files | Cohesion: 83%

## When to Use

- Working with code in `agent/`
- Understanding how TestPostinstFreshInstall, TestRemoveKeepsStateAndPurgeDeletesIt, TestAgentUnitHardening work
- Modifying packaging-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/packaging/packaging_test.go` | TestPostinstFreshInstall, TestRemoveKeepsStateAndPurgeDeletesIt, newScriptEnv, stub, calls (+16) |

## Entry Points

Start here when exploring this area:

- **`TestPostinstFreshInstall`** (Function) — `agent/packaging/packaging_test.go:391`
- **`TestRemoveKeepsStateAndPurgeDeletesIt`** (Function) — `agent/packaging/packaging_test.go:478`
- **`TestAgentUnitHardening`** (Function) — `agent/packaging/packaging_test.go:120`
- **`TestFirstbootUnit`** (Function) — `agent/packaging/packaging_test.go:180`
- **`TestHelperUnits`** (Function) — `agent/packaging/packaging_test.go:196`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `TestPostinstFreshInstall` | Function | `agent/packaging/packaging_test.go` | 391 |
| `TestRemoveKeepsStateAndPurgeDeletesIt` | Function | `agent/packaging/packaging_test.go` | 478 |
| `TestAgentUnitHardening` | Function | `agent/packaging/packaging_test.go` | 120 |
| `TestFirstbootUnit` | Function | `agent/packaging/packaging_test.go` | 180 |
| `TestHelperUnits` | Function | `agent/packaging/packaging_test.go` | 196 |
| `TestDebBinariesReportTheVersion` | Function | `agent/packaging/packaging_test.go` | 717 |
| `TestDebContentsHaveNoSecretsAndNoDockerSocket` | Function | `agent/packaging/packaging_test.go` | 602 |
| `TestDebLayoutOwnersAndModes` | Function | `agent/packaging/packaging_test.go` | 646 |
| `TestNoDockerSocketAnywhere` | Function | `agent/packaging/packaging_test.go` | 51 |
| `TestNoSudoersFileIsShipped` | Function | `agent/packaging/packaging_test.go` | 226 |
| `TestPackagingTreeHasNoSecrets` | Function | `agent/packaging/packaging_test.go` | 87 |
| `TestPostinstWithoutSystemd` | Function | `agent/packaging/packaging_test.go` | 424 |
| `TestScriptsRejectUnknownArguments` | Function | `agent/packaging/packaging_test.go` | 519 |
| `TestUpgradePreservesCredentialsAndSpool` | Function | `agent/packaging/packaging_test.go` | 438 |
| `newScriptEnv` | Function | `agent/packaging/packaging_test.go` | 341 |
| `stub` | Function | `agent/packaging/packaging_test.go` | 345 |
| `unit` | Function | `agent/packaging/packaging_test.go` | 97 |
| `debPath` | Function | `agent/packaging/packaging_test.go` | 583 |
| `textFiles` | Function | `agent/packaging/packaging_test.go` | 23 |
| `calls` | Method | `agent/packaging/packaging_test.go` | 386 |

## How to Explore

1. `context({name: "TestPostinstFreshInstall"})` — see callers and callees
2. `query({search_query: "packaging"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
