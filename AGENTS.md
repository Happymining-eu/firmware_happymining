# HappyMining OS — notes for coding agents

Read `README.md` first, then `IMPLEMENTATION_STATUS.md` (what is done, what is
not) and `docs/limitations.md`.

## Commands

- `make setup`, `make build-agent`, `make test`, `make lint`, `make demo`.
- API tests need PostgreSQL; `scripts/dev-postgres.sh` starts a throwaway one.
  Run one file with `api/.venv/bin/python -m pytest tests/api/<file> -q`.
- Run `ruff` from `api/` (its configuration is in `api/pyproject.toml`).
- Schema changes go in a new Alembic revision under `migrations/versions/`.

## Rules that are not negotiable here

- Money is `Decimal`. Journal entries are immutable; corrections are new
  entries. Every money mutation has an idempotency key.
- Never fall back from LIVE to DEMO, and never return fake success for a LIVE
  feature that is not supported: raise an explicit error.
- Never invent a Vast endpoint, field meaning or permission. If it is not in
  `docs/integration-evidence.md` as confirmed, it is unresolved.
- Unknown rental state blocks disruptive actions. Zero GPU utilisation proves
  nothing. Unlisting is not permission to end rentals.
- A device never chooses its owner or a provider machine. The Vast account key
  never leaves the backend. No arbitrary shell endpoint.
- A provider report is not cash; a provider invoice marked "Paid" is not cash;
  a timeout is not a failed payment.
- No secrets in the repository, in images or in logs. Signing keys are
  generated locally and stay out of version control.
- Do not describe anything as built, run or verified unless it was.
- A fix comes with a test that fails without it.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **firmware_happymining** (4943 symbols, 16051 relationships, 427 execution flows).

> Index stale? Run `node .gitnexus/run.cjs analyze --index-only` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? Bootstrap with `npx`, `bunx`, or `pnpm dlx` — e.g. `bunx gitnexus@latest analyze` (npm 11 npx crash; #1939).

## Always Do

- **MUST run impact before editing.** Use `impact({target: "symbolName", direction: "upstream"})` or `node .gitnexus/run.cjs impact "symbolName" --direction upstream --repo .`; report callers, processes, and risk. Never substitute grep for graph analysis.
- **MUST analyze graph changes before committing.** Use `detect_changes({scope: "all"})` (MCP) or `node .gitnexus/run.cjs detect-changes --scope all --repo .` (CLI fallback). `partial: true` or `truncated: true` is not a clean check — a zero means unseen, not unaffected; re-run it. For regression review: `detect_changes({scope: "compare", base_ref: "main"})` or `node .gitnexus/run.cjs detect-changes --scope compare --base-ref "main" --repo .`.
- MUST warn on HIGH/CRITICAL `risk` pre-edit; never use `riskSharedAxes` to waive a HIGH/CRITICAL `risk` warning. Compare File/symbol: MCP File omits axes; Graph-RAG expands File.
- **MUST treat `risk: UNKNOWN` as unresolved, not as low.** An empty caller set is not evidence the symbol is unused — it can also mean the callers are not resolvable by the index (plain-object property access, dynamic dispatch, cross-language calls). `impact` pairs `UNKNOWN` with a `riskNote` saying so. Confirm with a text search before treating the symbol as safe to change or delete; do not proceed on the strength of a zero.
- **MUST use `query({search_query: "concept"})` for concepts/flows, `context({name: "symbolName"})` for a named symbol, or `impact` for blast radius, on read-only callers, dependencies, imports, or execution flow.** Graph first; text search only for empty/`UNKNOWN`/literals.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method before MCP/CLI impact analysis.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis, and never read `UNKNOWN` as an all-clear — it means the walk could not answer, which is the one verdict that requires confirming by other means.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit before MCP/CLI graph change analysis.

## Resources

| Resource | Use for |
| --- | --- |
| `gitnexus://repo/firmware_happymining/context` | Codebase overview, check index freshness |
| `gitnexus://repo/firmware_happymining/clusters` | All functional areas |
| `gitnexus://repo/firmware_happymining/processes` | All execution flows |
| `gitnexus://repo/firmware_happymining/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
| --- | --- |
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus-cli/SKILL.md` |
| Work in the Api area (408 symbols) | `.claude/skills/gitnexus-area-api/SKILL.md` |
| Work in the Os area (191 symbols) | `.claude/skills/gitnexus-area-os/SKILL.md` |
| Work in the Routers area (182 symbols) | `.claude/skills/gitnexus-area-routers/SKILL.md` |
| Work in the Happymining area (156 symbols) | `.claude/skills/gitnexus-area-happymining/SKILL.md` |
| Work in the Services area (129 symbols) | `.claude/skills/gitnexus-area-services/SKILL.md` |
| Work in the Agent area (91 symbols) | `.claude/skills/gitnexus-area-agent/SKILL.md` |
| Work in the Ctl area (85 symbols) | `.claude/skills/gitnexus-area-ctl/SKILL.md` |
| Work in the Ops area (64 symbols) | `.claude/skills/gitnexus-area-ops/SKILL.md` |
| Work in the Preflight area (57 symbols) | `.claude/skills/gitnexus-area-preflight/SKILL.md` |
| Work in the Collector area (51 symbols) | `.claude/skills/gitnexus-area-collector/SKILL.md` |
| Work in the Providers area (39 symbols) | `.claude/skills/gitnexus-area-providers/SKILL.md` |
| Work in the Client area (30 symbols) | `.claude/skills/gitnexus-area-client/SKILL.md` |
| Work in the Spool area (28 symbols) | `.claude/skills/gitnexus-area-spool/SKILL.md` |
| Work in the Helper area (27 symbols) | `.claude/skills/gitnexus-area-helper/SKILL.md` |
| Work in the Autoinstall area (21 symbols) | `.claude/skills/gitnexus-area-autoinstall/SKILL.md` |
| Work in the Packaging area (21 symbols) | `.claude/skills/gitnexus-area-packaging/SKILL.md` |
| Work in the Config area (20 symbols) | `.claude/skills/gitnexus-area-config/SKILL.md` |
| Work in the Testapi area (17 symbols) | `.claude/skills/gitnexus-area-testapi/SKILL.md` |
| Work in the Fsx area (11 symbols) | `.claude/skills/gitnexus-area-fsx/SKILL.md` |
| Work in the Identity area (11 symbols) | `.claude/skills/gitnexus-area-identity/SKILL.md` |

<!-- gitnexus:end -->
