# ValueLens Report

- Target: `.`
- Generated: `2026-01-14 17:24:00.162186 UTC`
- Findings: `1`

## Axis signal totals (rough)

- `privacy`: `+0.70`

## Findings

### VL-PRIV-001 — Logging request body

- Severity: `High`
- Confidence: `0.70`
- Waiver: ✅ active (owner `platform-team`, expires `2026-03-01`)
- Waiver reason: Telemetry required for incident response; redaction work in progress.
- Axes:
  - `privacy`: `+1.00`

Request body logging may expose PII

**Evidence**
- `demo/sample.rs`:2

