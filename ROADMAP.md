# ValueLens Roadmap

ValueLens is infrastructure for making the *implicit values encoded in software systems visible, inspectable, and discussable*.

This roadmap is organized around adoption milestones rather than feature density.

## Phase 0 — MVP Hardening
- Stable Rust CLI (`valuelens scan`)
- YAML rule packs
- Outputs: JSON, Markdown, SARIF
- GitHub Actions integration
- Policy gate (severity + confidence)

## Phase 1 — Adoption Safety
- Waivers with expiry (`valuelens_waivers.yml`)
- Deduplication + noise caps
- Grouped output

## Phase 2 — Value Axes
- Axis aggregation
- Stable axis schema

## Phase 3 — Declared Values & Contradictions
- `valuelens.yml` (declared values)
- Alignment / drift / contradiction detection

## Phase 4 — Drift Detection
- Baseline comparison
- PR-level drift summaries
- Drift-focused gating

## Phase 5 — Interpretive Layer (Spiral-informed, optional)
- Signal clusters
- Evidence-backed narratives
- Configurable weights

## Phase 6 — Native Rules
- Rust-native rules
- Terraform/K8s rules
- Telemetry minimization checks
