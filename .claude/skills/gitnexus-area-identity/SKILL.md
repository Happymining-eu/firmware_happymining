---
name: gitnexus-area-identity
description: "Skill for the Identity area of firmware_happymining. 11 symbols across 3 files."
---

# Identity

11 symbols | 3 files | Cohesion: 74%

## When to Use

- Working with code in `agent/`
- Understanding how Pair, Fingerprint, Init work
- Modifying identity-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/identity/identity.go` | Fingerprint, Init, fail, Load, Path |
| `agent/internal/identity/identity_test.go` | TestInitDoesNotOverwriteUnusableIdentity, TestInitIsIdempotent, TestLoadRefusesLoosePermissions, TestRegenerate, TestTwoMachinesGetDifferentIdentities |
| `agent/internal/enroll/enroll.go` | Pair |

## Entry Points

Start here when exploring this area:

- **`Pair`** (Function) — `agent/internal/enroll/enroll.go:51`
- **`Fingerprint`** (Function) — `agent/internal/identity/identity.go:122`
- **`Init`** (Function) — `agent/internal/identity/identity.go:36`
- **`Load`** (Function) — `agent/internal/identity/identity.go:99`
- **`Path`** (Function) — `agent/internal/identity/identity.go:28`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `Pair` | Function | `agent/internal/enroll/enroll.go` | 51 |
| `Fingerprint` | Function | `agent/internal/identity/identity.go` | 122 |
| `Init` | Function | `agent/internal/identity/identity.go` | 36 |
| `Load` | Function | `agent/internal/identity/identity.go` | 99 |
| `Path` | Function | `agent/internal/identity/identity.go` | 28 |
| `TestInitDoesNotOverwriteUnusableIdentity` | Function | `agent/internal/identity/identity_test.go` | 55 |
| `TestInitIsIdempotent` | Function | `agent/internal/identity/identity_test.go` | 8 |
| `TestLoadRefusesLoosePermissions` | Function | `agent/internal/identity/identity_test.go` | 69 |
| `TestRegenerate` | Function | `agent/internal/identity/identity_test.go` | 39 |
| `TestTwoMachinesGetDifferentIdentities` | Function | `agent/internal/identity/identity_test.go` | 82 |
| `fail` | Function | `agent/internal/identity/identity.go` | 65 |

## How to Explore

1. `context({name: "Pair"})` — see callers and callees
2. `query({search_query: "identity"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
