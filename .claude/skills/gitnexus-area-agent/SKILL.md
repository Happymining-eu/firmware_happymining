---
name: gitnexus-area-agent
description: "Skill for the Agent area of firmware_happymining. 91 symbols across 13 files."
---

# Agent

91 symbols | 13 files | Cohesion: 77%

## When to Use

- Working with code in `agent/`
- Understanding how New, TestClockSkewIsReportedOncePerHour, TestCredentialRotation work
- Modifying agent-related functionality

## Key Files

| File | Symbols |
|------|---------|
| `agent/internal/agent/agent_test.go` | TestClockSkewIsReportedOncePerHour, ack, count, TestCredentialRotation, TestErrorsWithoutEnvelopeNeverDropData (+39) |
| `agent/internal/agent/agent.go` | New, Close, Collected, Dropped, Snapshot (+15) |
| `agent/internal/spool/spool.go` | HighestSeq, Dropped, Quota, Len, Size (+2) |
| `agent/internal/testapi/testapi.go` | AuthorizationHeaders, HeartbeatRequests, QueueOperation, Revoke, SetHeartbeatFault |
| `agent/internal/agent/exec.go` | CollectDiagnostics, Reboot, RestartVastDaemon, helperCall |
| `agent/internal/agent/state.go` | ReadState, StatePath |
| `agent/internal/sim/synthetic.go` | ptr, Collect |
| `agent/internal/ops/journal.go` | Len, Prune |
| `agent/internal/credential/credential.go` | Delete |
| `agent/internal/collector/collector.go` | Collect |

## Entry Points

Start here when exploring this area:

- **`New`** (Function) — `agent/internal/agent/agent.go:121`
- **`TestClockSkewIsReportedOncePerHour`** (Function) — `agent/internal/agent/agent_test.go:1071`
- **`TestCredentialRotation`** (Function) — `agent/internal/agent/agent_test.go:1012`
- **`TestErrorsWithoutEnvelopeNeverDropData`** (Function) — `agent/internal/agent/agent_test.go:520`
- **`TestGracefulShutdownIsPrompt`** (Function) — `agent/internal/agent/agent_test.go:725`

## Key Symbols

| Symbol | Type | File | Line |
|--------|------|------|------|
| `New` | Function | `agent/internal/agent/agent.go` | 121 |
| `TestClockSkewIsReportedOncePerHour` | Function | `agent/internal/agent/agent_test.go` | 1071 |
| `TestCredentialRotation` | Function | `agent/internal/agent/agent_test.go` | 1012 |
| `TestErrorsWithoutEnvelopeNeverDropData` | Function | `agent/internal/agent/agent_test.go` | 520 |
| `TestGracefulShutdownIsPrompt` | Function | `agent/internal/agent/agent_test.go` | 725 |
| `TestHealthyRunDeliversEverySampleOnce` | Function | `agent/internal/agent/agent_test.go` | 211 |
| `TestHostileOperationsInResponseDoNotCrash` | Function | `agent/internal/agent/agent_test.go` | 362 |
| `TestInvalidRequestIsDroppedNotResent` | Function | `agent/internal/agent/agent_test.go` | 498 |
| `TestLogsAndSpoolNeverContainTheCredential` | Function | `agent/internal/agent/agent_test.go` | 753 |
| `TestLostAckIsRepeatedWithoutExecutingAgain` | Function | `agent/internal/agent/agent_test.go` | 970 |
| `TestLostAcknowledgementLeadsToASafeResend` | Function | `agent/internal/agent/agent_test.go` | 287 |
| `TestLostLocalStateRecoversFromHighestSeq` | Function | `agent/internal/agent/agent_test.go` | 660 |
| `TestMalformedAndOversizedResponsesDoNotCrashOrLoseData` | Function | `agent/internal/agent/agent_test.go` | 331 |
| `TestOfflineBufferingThenFlush` | Function | `agent/internal/agent/agent_test.go` | 238 |
| `TestOperationsEndToEnd` | Function | `agent/internal/agent/agent_test.go` | 867 |
| `TestOptInOperationReachesTheHelperExactlyOnce` | Function | `agent/internal/agent/agent_test.go` | 941 |
| `TestPairAndUnpairTakeEffectWithoutWaitingForTheInterval` | Function | `agent/internal/agent/agent_test.go` | 1097 |
| `TestPayloadTooLargeSplitsTheBatch` | Function | `agent/internal/agent/agent_test.go` | 543 |
| `TestRepairAfterRevocationResumesAndDropsOldSamples` | Function | `agent/internal/agent/agent_test.go` | 461 |
| `TestRetryAfterIsHonoured` | Function | `agent/internal/agent/agent_test.go` | 392 |

## Execution Flows

| Flow | Type | Steps |
|------|------|-------|
| `CollectDiagnostics → Path` | cross_community | 5 |
| `CollectDiagnostics → Truncate` | cross_community | 4 |
| `Run → Now` | cross_community | 3 |
| `Run → Append` | cross_community | 3 |
| `CollectDiagnostics → P` | intra_community | 3 |
| `CollectDiagnostics → Hook` | intra_community | 3 |
| `CollectDiagnostics → CPU` | intra_community | 3 |
| `CollectDiagnostics → Sample` | intra_community | 3 |

## How to Explore

1. `context({name: "New"})` — see callers and callees
2. `query({search_query: "agent"})` — find related execution flows
3. Read key files listed above for implementation details
4. `explain({target: "<file or symbol>"})` — persisted taint findings (source→sink data flows), when indexed with `--pdg`
