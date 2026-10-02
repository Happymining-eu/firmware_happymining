---
name: gitnexus-area-config
description: "Skill for the Config area of firmware_happymining. 20 symbols across 4 files."
---

# Config

20 symbols | 4 files | Cohesion: 75%

## When to Use

- Working with code in `agent/`
- Understanding how ParseAgent, TestDefaults, TestMinimumIntervalAccepted work
- Modifying config-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/config/config.go` | ParseAgent, absPath, parseInt, parseMounts, parseOps (+7) |
| `agent/internal/config/config_test.go` | TestDefaults, TestMinimumIntervalAccepted, TestParseAgentDefaultsAndValues, TestParseAgentStrictness, TestParseHelper (+1) |
| `agent/internal/helper/helper.go` | LoadConf |
| `agent/packaging/packaging_test.go` | TestConffileDefaultsAreSafe |

## Entry Points

Start here when exploring this area:

- **`ParseAgent`** (Function) — `agent/internal/config/config.go:193`
- **`TestDefaults`** (Function) — `agent/internal/config/config_test.go:42`
- **`TestMinimumIntervalAccepted`** (Function) — `agent/internal/config/config_test.go:87`
- **`TestParseAgentDefaultsAndValues`** (Function) — `agent/internal/config/config_test.go:10`
- **`TestParseAgentStrictness`** (Function) — `agent/internal/config/config_test.go:54`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `ParseAgent` | Function | `agent/internal/config/config.go` | 193 |
| `TestDefaults` | Function | `agent/internal/config/config_test.go` | 42 |
| `TestMinimumIntervalAccepted` | Function | `agent/internal/config/config_test.go` | 87 |
| `TestParseAgentDefaultsAndValues` | Function | `agent/internal/config/config_test.go` | 10 |
| `TestParseAgentStrictness` | Function | `agent/internal/config/config_test.go` | 54 |
| `ParseHelper` | Function | `agent/internal/config/config.go` | 372 |
| `ParseKV` | Function | `agent/internal/config/config.go` | 98 |
| `TestParseHelper` | Function | `agent/internal/config/config_test.go` | 111 |
| `LoadConf` | Function | `agent/internal/helper/helper.go` | 139 |
| `TestConffileDefaultsAreSafe` | Function | `agent/packaging/packaging_test.go` | 236 |
| `DefaultAgent` | Function | `agent/internal/config/config.go` | 80 |
| `LoadAgent` | Function | `agent/internal/config/config.go` | 168 |
| `LoadAgentOptional` | Function | `agent/internal/config/config.go` | 184 |
| `TestLoadAgentOptional` | Function | `agent/internal/config/config_test.go` | 94 |
| `absPath` | Function | `agent/internal/config/config.go` | 309 |
| `parseInt` | Function | `agent/internal/config/config.go` | 288 |
| `parseMounts` | Function | `agent/internal/config/config.go` | 346 |
| `parseOps` | Function | `agent/internal/config/config.go` | 319 |
| `parseBool` | Function | `agent/internal/config/config.go` | 299 |
| `unquote` | Function | `agent/internal/config/config.go` | 140 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `Run → Agent` | cross_community | 5 |
| `Run → Unquote` | cross_community | 5 |
| `Run → ParseInt` | cross_community | 4 |

## How to Explore

1. `context({name: "ParseAgent"})` — see callers and callees
2. `query({search_query: "config"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
