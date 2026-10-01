# AegisTrust AI

A hackathon demo of an AI security console for prompt inspection, sensitive-data masking, agent-action policy checks, and audit review.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/aegistrust-demo/` — AegisTrust web app and browser-side demo logic.
- `artifacts/api-server/` — shared API scaffold; the initial demo does not depend on it.
- `lib/api-spec/openapi.yaml` — shared API contract; unchanged for the frontend-only MVP.

## Architecture decisions

- The hackathon demo runs locally in the browser and does not send prompts to an LLM or external service.
- Prompt detection and tool authorization are illustrative deterministic rules, not a validated security product.
- Audit records should avoid raw prompt contents and detected PII; client-side hash chaining is demonstrative, not an immutable compliance ledger.

## Product

The console demonstrates three runtime controls: prompt/injection inspection with PII masking, role-based authorization of simulated agent tool calls, and a verifiable local audit-event chain.

## User preferences

_Populate as you build — explicit user instructions worth remembering across sessions._

## Gotchas

- Do not describe demo detections, latency, audit integrity, or policy decisions as production-validated guarantees.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
